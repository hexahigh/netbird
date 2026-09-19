package multipath

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	probeInterval = 500 * time.Millisecond
	probeTimeout  = 1500 * time.Millisecond
	// probeFailThreshold is how many probes in a row may be lost before a
	// path is demoted, and probeUpThreshold how many replies are needed to
	// promote it again.
	probeFailThreshold = 3
	probeUpThreshold   = 3
	probeWindow        = 20

	probeRequest  = 1
	probeResponse = 2
	probeLen      = 21
)

var probeMagic = [4]byte{'N', 'B', 'M', 'P'}

// prober exchanges echo probes with the remote path's probe socket. The same
// socket receives the remote's probes and echoes them, so a path is
// considered up only when traffic passes in both directions.
type prober struct {
	log    *log.Entry
	conn   *net.UDPConn
	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	remote     netip.AddrPort
	hasRemote  bool
	seq        uint64
	pending    map[uint64]time.Time
	rtt        time.Duration
	window     []bool
	fails      int
	successes  int
	up         bool
	notify     func(bool)
	started    bool
	stopped    bool
	senderDone chan struct{}
}

func newProber(entry *log.Entry, conn *net.UDPConn, parent context.Context) *prober {
	ctx, cancel := context.WithCancel(parent)
	return &prober{
		log:        entry,
		conn:       conn,
		ctx:        ctx,
		cancel:     cancel,
		pending:    make(map[uint64]time.Time),
		senderDone: make(chan struct{}),
	}
}

// start points the prober at a remote probe endpoint and starts the echo and
// probe loops. It is a no-op when already started.
func (p *prober) start(remoteAddr netip.Addr, remotePort uint16, notify func(bool)) {
	p.mu.Lock()
	p.remote = netip.AddrPortFrom(remoteAddr, remotePort)
	p.hasRemote = true
	if p.started || p.stopped {
		p.mu.Unlock()
		return
	}
	p.started = true
	p.notify = notify
	p.mu.Unlock()

	go p.readLoop()
	go p.sendLoop()
}

func (p *prober) stop() {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	started := p.started
	p.started = false
	cancel := p.cancel
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if err := p.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		p.log.Debugf("close probe socket: %v", err)
	}
	if started {
		<-p.senderDone
	}
}

func (p *prober) stats() (time.Duration, float64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var lost int
	for _, ok := range p.window {
		if !ok {
			lost++
		}
	}
	var loss float64
	if len(p.window) > 0 {
		loss = float64(lost) / float64(len(p.window))
	}
	return p.rtt, loss
}

func (p *prober) readLoop() {
	buf := make([]byte, 64)
	for {
		n, from, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || p.ctx.Err() != nil {
				return
			}
			p.log.Tracef("probe read: %v", err)
			continue
		}
		if n < probeLen || string(buf[:4]) != string(probeMagic[:]) {
			continue
		}
		kind := buf[4]
		switch kind {
		case probeRequest:
			reply := make([]byte, n)
			copy(reply, buf[:n])
			reply[4] = probeResponse
			if _, err := p.conn.WriteToUDP(reply, from); err != nil && !errors.Is(err, net.ErrClosed) {
				p.log.Tracef("probe echo: %v", err)
			}
		case probeResponse:
			p.onResponse(binary.BigEndian.Uint64(buf[5:13]))
		}
	}
}

func (p *prober) sendLoop() {
	defer close(p.senderDone)

	ticker := time.NewTicker(probeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
		}
		p.send()
		p.expire()
	}
}

func (p *prober) send() {
	p.mu.Lock()
	remote := p.remote
	hasRemote := p.hasRemote
	p.seq++
	seq := p.seq
	p.pending[seq] = time.Now()
	p.mu.Unlock()

	if !hasRemote {
		return
	}

	packet := make([]byte, probeLen)
	copy(packet, probeMagic[:])
	packet[4] = probeRequest
	binary.BigEndian.PutUint64(packet[5:13], seq)
	binary.BigEndian.PutUint64(packet[13:21], uint64(time.Now().UnixNano()))
	if _, err := p.conn.WriteToUDP(packet, net.UDPAddrFromAddrPort(remote)); err != nil && !errors.Is(err, net.ErrClosed) {
		p.log.Tracef("send probe: %v", err)
	}
}

func (p *prober) expire() {
	now := time.Now()
	p.mu.Lock()
	var lost bool
	for seq, sent := range p.pending {
		if now.Sub(sent) > probeTimeout {
			delete(p.pending, seq)
			lost = true
		}
	}
	p.mu.Unlock()
	if lost {
		p.markResult(false)
	}
}

func (p *prober) onResponse(seq uint64) {
	p.mu.Lock()
	sent, ok := p.pending[seq]
	if ok {
		delete(p.pending, seq)
		p.rtt = time.Since(sent)
	}
	p.mu.Unlock()
	if ok {
		p.markResult(true)
	}
}

// markResult records a probe outcome and fires the up/down notification when
// the threshold is crossed. The notification is called without p.mu held so
// callers may take the manager lock.
func (p *prober) markResult(ok bool) {
	p.mu.Lock()
	p.window = append(p.window, ok)
	if len(p.window) > probeWindow {
		p.window = p.window[len(p.window)-probeWindow:]
	}
	var transition bool
	if ok {
		p.successes++
		p.fails = 0
		if !p.up && p.successes >= probeUpThreshold {
			p.up = true
			transition = true
		}
	} else {
		p.fails++
		p.successes = 0
		if p.up && p.fails >= probeFailThreshold {
			p.up = false
			transition = true
		}
	}
	up := p.up
	notify := p.notify
	p.mu.Unlock()

	if transition && notify != nil {
		notify(up)
	}
}
