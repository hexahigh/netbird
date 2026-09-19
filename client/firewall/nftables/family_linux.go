//go:build !android

package nftables

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/firewall/firewalld"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/routemanager/ipfwdstate"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
)

const (
	tableNat      = "nat"
	tableMangle   = "mangle"
	tableRaw      = "raw"
	tableSecurity = "security"

	chainNameNatPrerouting = "PREROUTING"
	chainNameRoutingFw     = "netbird-rt-fwd"
	chainNameRoutingNat    = "netbird-rt-postrouting"
	chainNameRoutingRdr    = "netbird-rt-redirect"
	chainNameNATOutput     = "netbird-nat-output"
	chainNameForward       = "FORWARD"
	chainNameMangleForward = "netbird-mangle-forward"

	// Peer ACL chain names.
	chainNameInputRules        = "netbird-acl-input-rules"
	chainNameInputFilter       = "netbird-acl-input-filter"
	chainNameForwardFilter     = "netbird-acl-forward-filter"
	chainNameManglePrerouting  = "netbird-mangle-prerouting"
	chainNameManglePostrouting = "netbird-mangle-postrouting"

	flushError = "flush: %w"

	firewalldTableName = "firewalld"

	userDataAcceptForwardRuleIif = "frwacceptiif"
	userDataAcceptForwardRuleOif = "frwacceptoif"
	userDataAcceptInputRule      = "inputaccept"

	dnatSuffix firewall.RuleID = "_dnat"
	snatSuffix firewall.RuleID = "_snat"

	// ipv4TCPHeaderSize is the minimum IPv4 (20) + TCP (20) header size for MSS calculation.
	ipv4TCPHeaderSize = 40
	// ipv6TCPHeaderSize is the minimum IPv6 (40) + TCP (20) header size for MSS calculation.
	ipv6TCPHeaderSize = 60

	// maxPrefixesSet 1638 prefixes start to fail, taking some margin
	maxPrefixesSet       = 1500
	refreshRulesMapError = "refresh rules map: %w"
)

var (
	errFilterTableNotFound = fmt.Errorf("'filter' table not found")
)

type setInput struct {
	set      firewall.Set
	prefixes []netip.Prefix
}

// family holds the per-address-family nftables state. One instance
// handles route ACLs, peer ACLs, NAT, DNAT, and MSS clamping for a
// single family; the top-level Manager owns one for v4 and another
// for v6. The name predates the peer-ACL absorption; it's effectively
// the per-family backend now.
type family struct {
	conn        *nftables.Conn
	workTable   *nftables.Table
	filterTable *nftables.Table
	chains      map[string]*nftables.Chain

	// filters holds peer + route filter rules keyed by content hash.
	// AddFilterRule writes here; DeleteFilterRule looks up by id.
	filters map[firewall.RuleID]*Rule

	// rules holds NAT, DNAT, and external accept rules (auxiliary
	// plumbing that isn't a filter rule).
	rules map[firewall.RuleID]*nftables.Rule

	// Peer ACL chain handles.
	chainInputRules    *nftables.Chain
	chainPrerouting    *nftables.Chain
	routingFwChainName string

	ipsetCounter *refcounter.Counter[string, setInput, *nftables.Set]

	af               addrFamily
	wgIface          iFaceMapper
	ipFwdState       *ipfwdstate.IPForwardingState
	legacyManagement bool
	mtu              uint16

	// ifaceSet holds the overlay interface names (main plus multipath paths)
	// matched by the rules, so adding a path does not require re-rendering
	// rules. Guarded by ifaceMu together with extraIfaces.
	ifaceMu     sync.Mutex
	ifaceSet    *nftables.Set
	extraIfaces map[string]bool
}

func newFamily(workTable *nftables.Table, wgIface iFaceMapper, mtu uint16) *family {
	r := &family{
		conn:               &nftables.Conn{},
		workTable:          workTable,
		chains:             make(map[string]*nftables.Chain),
		filters:            make(map[firewall.RuleID]*Rule),
		rules:              make(map[firewall.RuleID]*nftables.Rule),
		routingFwChainName: chainNameRoutingFw,
		af:                 familyForAddr(workTable.Family == nftables.TableFamilyIPv4),
		wgIface:            wgIface,
		ipFwdState:         ipfwdstate.NewIPForwardingState(wgIface.Name()),
		mtu:                mtu,
	}

	r.ipsetCounter = refcounter.New(
		r.createIpSet,
		r.deleteIpSet,
	)

	var err error
	r.filterTable, err = r.loadFilterTable()
	if err != nil {
		log.Debugf("ip filter table not found: %v", err)
	}

	return r
}

// ifaceSetName is the interface set every rule matches overlay interfaces
// against. The set grows when multipath paths appear, so rules never need to
// be re-rendered.
const ifaceSetName = "netbird_ifaces"

// createIfaceSet creates the interface set, seeded with the main interface.
func (r *family) createIfaceSet() error {
	r.ifaceMu.Lock()
	defer r.ifaceMu.Unlock()

	r.ifaceSet = &nftables.Set{
		Name:    ifaceSetName,
		Table:   r.workTable,
		KeyType: nftables.TypeIFName,
	}
	r.extraIfaces = make(map[string]bool)
	if err := r.conn.AddSet(r.ifaceSet, []nftables.SetElement{{Key: ifname(r.wgIface.Name())}}); err != nil {
		return err
	}
	return r.conn.Flush()
}

// ifaceNames returns the main interface plus every active path interface.
func (r *family) ifaceNames() []string {
	r.ifaceMu.Lock()
	defer r.ifaceMu.Unlock()

	names := []string{r.wgIface.Name()}
	for name := range r.extraIfaces {
		names = append(names, name)
	}
	return names
}

// ifaceExprs matches a meta interface key against every overlay interface.
func (r *family) ifaceExprs(key expr.MetaKey) []expr.Any {
	return r.ifaceExprsInvert(key, false)
}

// ifaceExprsInvert matches a meta interface key, optionally negated.
func (r *family) ifaceExprsInvert(key expr.MetaKey, invert bool) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        r.ifaceSet.Name,
			SetID:          r.ifaceSet.ID,
			Invert:         invert,
		},
	}
}

// setMultipathInterfaces updates the path interfaces the rules match. The main
// interface is always part of the set. Unknown interfaces are added to the set
// and passed to firewalld first, so the rules cover the path from the moment
// it carries traffic.
func (r *family) setMultipathInterfaces(names []string) error {
	r.ifaceMu.Lock()
	defer r.ifaceMu.Unlock()

	if r.ifaceSet == nil {
		return errors.New("interface set is not initialized")
	}

	desired := make(map[string]bool, len(names))
	for _, name := range names {
		if name != "" && name != r.wgIface.Name() {
			desired[name] = true
		}
	}

	var add, remove []nftables.SetElement
	var trust, untrust []string
	for name := range desired {
		if !r.extraIfaces[name] {
			add = append(add, nftables.SetElement{Key: ifname(name)})
			trust = append(trust, name)
		}
	}
	for name := range r.extraIfaces {
		if !desired[name] {
			remove = append(remove, nftables.SetElement{Key: ifname(name)})
			untrust = append(untrust, name)
		}
	}
	if len(add) == 0 && len(remove) == 0 {
		return nil
	}

	for _, name := range trust {
		if err := firewalld.TrustInterface(name); err != nil {
			log.Warnf("failed to trust interface %s in firewalld: %v", name, err)
		}
	}
	if len(add) > 0 {
		if err := r.conn.SetAddElements(r.ifaceSet, add); err != nil {
			return fmt.Errorf("add path interfaces: %w", err)
		}
	}
	if len(remove) > 0 {
		if err := r.conn.SetDeleteElements(r.ifaceSet, remove); err != nil {
			return fmt.Errorf("remove path interfaces: %w", err)
		}
	}
	if err := r.conn.Flush(); err != nil {
		return fmt.Errorf("flush interface set: %w", err)
	}

	for _, name := range untrust {
		if err := firewalld.UntrustInterface(name); err != nil {
			log.Warnf("failed to untrust interface %s in firewalld: %v", name, err)
		}
	}

	r.extraIfaces = desired
	log.Infof("firewall covers path interfaces %v", names)
	return nil
}

func (r *family) init(workTable *nftables.Table) error {
	r.workTable = workTable

	if err := r.createIfaceSet(); err != nil {
		return fmt.Errorf("create interface set: %w", err)
	}

	if err := r.removeAcceptFilterRules(); err != nil {
		log.Errorf("failed to clean up rules from filter table: %s", err)
	}

	if err := r.createContainers(); err != nil {
		return fmt.Errorf("create containers: %w", err)
	}

	if err := r.setupDataPlaneMark(); err != nil {
		log.Errorf("failed to set up data plane mark: %v", err)
	}

	if err := r.createDefaultChains(); err != nil {
		return fmt.Errorf("create default acl chains: %w", err)
	}

	return nil
}

// Reset cleans existing nftables filter table rules from the system
func (r *family) Reset() error {
	// clear without deleting the ipsets, the nf table will be deleted by the caller
	r.ipsetCounter.Clear()

	var merr *multierror.Error

	if err := r.removeAcceptFilterRules(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove accept filter rules: %w", err))
	}

	if err := firewalld.UntrustInterface(r.wgIface.Name()); err != nil {
		merr = multierror.Append(merr, err)
	}

	if err := r.removeNatPreroutingRules(); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("remove filter prerouting rules: %w", err))
	}

	return nberrors.FormatErrorOrNil(merr)
}

func (r *family) loadFilterTable() (*nftables.Table, error) {
	tables, err := r.conn.ListTablesOfFamily(r.af.tableFamily)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}

	for _, table := range tables {
		if table.Name == "filter" {
			return table, nil
		}
	}

	return nil, errFilterTableNotFound
}

func hookName(hook *nftables.ChainHook) string {
	if hook == nil {
		return "unknown"
	}
	switch *hook {
	case *nftables.ChainHookForward:
		return chainNameForward
	case *nftables.ChainHookInput:
		return chainNameInput
	default:
		return fmt.Sprintf("hook(%d)", *hook)
	}
}

func familyName(family nftables.TableFamily) string {
	switch family {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	default:
		return fmt.Sprintf("family(%d)", family)
	}
}

func (r *family) iptablesProto() iptables.Protocol {
	if r.af.tableFamily == nftables.TableFamilyIPv6 {
		return iptables.ProtocolIPv6
	}
	return iptables.ProtocolIPv4
}

func (r *family) refreshRulesMap() error {
	var merr *multierror.Error
	newRules := make(map[firewall.RuleID]*nftables.Rule)
	for _, chain := range r.chains {
		rules, err := r.conn.GetRules(chain.Table, chain)
		if err != nil {
			merr = multierror.Append(merr, fmt.Errorf("list rules for chain %s: %w", chain.Name, err))
			// preserve existing entries for this chain since we can't verify their state
			for k, v := range r.rules {
				if v.Chain != nil && v.Chain.Name == chain.Name {
					newRules[k] = v
				}
			}
			continue
		}
		for _, rule := range rules {
			if len(rule.UserData) > 0 {
				newRules[firewall.RuleID(rule.UserData)] = rule
			}
		}
	}
	r.rules = newRules
	return nberrors.FormatErrorOrNil(merr)
}
