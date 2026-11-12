package link

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

// ErrOffline: no tunnel to the tenant is open on this replica.
var ErrOffline = errors.New("tenant link is offline")

// Modes an agent runs in. A control-only agent (a tenant central reaches
// directly) carries control messages but never API streams.
const (
	ModeTunnel  = "tunnel"
	ModeControl = "control"
)

// DrainGrace is how long open streams may run after a replica starts draining.
const DrainGrace = 60 * time.Second

// Message is one control message, a JSON line on the control stream.
//
//	agent → gateway: hello (version, mode, lane, time), health (time)
//	gateway → agent: drain (open a replacement tunnel; this one takes no new streams)
//
// Every stream the agent opens starts with one Message saying what it is:
// "control", or "egress" with the target host:port.
type Message struct {
	Type    string `json:"type"`
	Version string `json:"version,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Time    int64  `json:"time,omitempty"` // sender's clock, unix nanoseconds
	Target  string `json:"target,omitempty"`
	Grace   int    `json:"grace_seconds,omitempty"`
	Lane    string `json:"lane,omitempty"`
}

// Lanes keep bulk traffic (log streams, state and bundle transfers, webhook
// deliveries) off the TCP connection that carries interactive requests, so a
// burst of logs cannot hold up an API call, a heartbeat or a control message
// behind it (head-of-line blocking happens per TCP connection, below yamux).
// An agent with two or more tunnels makes its first one interactive and the
// rest bulk; with one tunnel, or when a lane has no live tunnel, any serves.
const (
	LaneInteractive = "interactive"
	LaneBulk        = "bulk"
)

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 15 * time.Second
	c.ConnectionWriteTimeout = 15 * time.Second
	c.LogOutput = io.Discard
	return c
}

// Tunnel is one open tunnel from a tenant's agent to this replica.
type Tunnel struct {
	Tenant    string
	Serial    string
	Remote    string
	Connected time.Time
	lastSeen  atomic.Int64
	version   atomic.Value // string
	mode      atomic.Value // string
	lane      atomic.Value // string
	skew      atomic.Int64 // agent clock minus ours, nanoseconds
	draining  atomic.Bool
	sess      *yamux.Session
	ctrlMu    sync.Mutex
	ctrl      net.Conn
}

func (t *Tunnel) LastSeen() time.Time { return time.Unix(0, t.lastSeen.Load()) }
func (t *Tunnel) Version() string     { v, _ := t.version.Load().(string); return v }
func (t *Tunnel) Mode() string {
	if m, _ := t.mode.Load().(string); m != "" {
		return m
	}
	return ModeTunnel
}

// Lane is the traffic the agent assigned to this tunnel ("" for any).
func (t *Tunnel) Lane() string { l, _ := t.lane.Load().(string); return l }

// ClockSkew is the agent's clock minus the gateway's at its last report.
func (t *Tunnel) ClockSkew() time.Duration { return time.Duration(t.skew.Load()) }

func (t *Tunnel) send(m Message) error {
	t.ctrlMu.Lock()
	defer t.ctrlMu.Unlock()
	if t.ctrl == nil {
		return errors.New("no control stream")
	}
	b, _ := json.Marshal(m)
	t.ctrl.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := t.ctrl.Write(append(b, '\n'))
	return err
}

// Info is a tunnel as reported to admins.
type Info struct {
	Serial    string    `json:"serial"`
	Remote    string    `json:"remote"`
	Connected time.Time `json:"connected_at"`
	LastSeen  time.Time `json:"last_seen"`
	Version   string    `json:"version,omitempty"`
	Mode      string    `json:"mode"`
	Lane      string    `json:"lane,omitempty"`
	SkewMS    int64     `json:"clock_skew_ms"`
	Draining  bool      `json:"draining,omitempty"`
}

// EgressFunc opens an egress connection for a tenant (the relay to allowlisted
// hosts, such as its identity provider's token endpoint), or refuses it.
type EgressFunc func(ctx context.Context, tenant, target string) (net.Conn, error)

// Hub holds the tunnels open on this gateway replica.
type Hub struct {
	mu   sync.Mutex
	m    map[string][]*Tunnel
	next atomic.Uint64
	// OnChange is told when a tunnel opens, reports, or closes.
	OnChange func(t *Tunnel, up bool)
	// Egress serves egress streams; nil refuses them all.
	Egress EgressFunc
}

func NewHub() *Hub { return &Hub{m: map[string][]*Tunnel{}} }

// Serve runs a tunnel on conn (after the upgrade) until it closes. The
// gateway is the yamux client (it opens API streams); the agent opens the
// control stream and any egress streams.
func (h *Hub) Serve(ctx context.Context, conn net.Conn, tenant, serial, remote string) error {
	sess, err := yamux.Client(conn, yamuxConfig())
	if err != nil {
		conn.Close()
		return err
	}
	t := &Tunnel{Tenant: tenant, Serial: serial, Remote: remote, Connected: time.Now(), sess: sess}
	t.lastSeen.Store(time.Now().UnixNano())
	h.mu.Lock()
	h.m[tenant] = append(h.m[tenant], t)
	h.mu.Unlock()
	h.notify(t, true)
	defer func() {
		h.remove(t)
		sess.Close()
		h.notify(t, false)
	}()
	go h.accept(ctx, t)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-sess.CloseChan():
		return errors.New("tunnel closed")
	}
}

// accept serves the streams the agent opens: control and egress.
func (h *Hub) accept(ctx context.Context, t *Tunnel) {
	for {
		s, err := t.sess.Accept()
		if err != nil {
			return
		}
		go h.agentStream(ctx, t, s)
	}
}

func (h *Hub) agentStream(ctx context.Context, t *Tunnel, s net.Conn) {
	br := bufio.NewReader(s)
	s.SetReadDeadline(time.Now().Add(15 * time.Second))
	line, err := br.ReadBytes('\n')
	var m Message
	if err != nil || json.Unmarshal(line, &m) != nil {
		s.Close()
		return
	}
	s.SetReadDeadline(time.Time{})
	switch m.Type {
	case "control":
		t.ctrlMu.Lock()
		t.ctrl = s
		t.ctrlMu.Unlock()
		h.control(t, br)
	case "egress":
		if h.Egress == nil {
			io.WriteString(s, "refused\n")
			s.Close()
			return
		}
		c, err := h.Egress(ctx, t.Tenant, m.Target)
		if err != nil {
			io.WriteString(s, "refused: "+err.Error()+"\n")
			s.Close()
			return
		}
		io.WriteString(s, "ok\n")
		Pipe(&BufConn{Conn: s, R: br}, c)
	default:
		s.Close()
	}
}

func (h *Hub) control(t *Tunnel, br *bufio.Reader) {
	dec := json.NewDecoder(br)
	for {
		var m Message
		if err := dec.Decode(&m); err != nil {
			return
		}
		now := time.Now()
		t.lastSeen.Store(now.UnixNano())
		if m.Time != 0 {
			t.skew.Store(m.Time - now.UnixNano())
		}
		switch m.Type {
		case "hello":
			t.version.Store(m.Version)
			t.lane.Store(m.Lane)
			if m.Mode == ModeControl {
				t.mode.Store(ModeControl)
			} else {
				t.mode.Store(ModeTunnel)
			}
		}
		h.notify(t, true)
	}
}

func (h *Hub) notify(t *Tunnel, up bool) {
	if h.OnChange != nil {
		h.OnChange(t, up)
	}
}

func (h *Hub) remove(t *Tunnel) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ts := h.m[t.Tenant]
	for i, x := range ts {
		if x == t {
			h.m[t.Tenant] = append(ts[:i:i], ts[i+1:]...)
			break
		}
	}
	if len(h.m[t.Tenant]) == 0 {
		delete(h.m, t.Tenant)
	}
}

func (t *Tunnel) usable() bool {
	return !t.draining.Load() && !t.sess.IsClosed() && t.Mode() == ModeTunnel
}

// Online reports whether this replica holds a tunnel that carries API streams.
func (h *Hub) Online(tenant string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, t := range h.m[tenant] {
		if t.usable() {
			return true
		}
	}
	return false
}

// Connected reports whether any tunnel (control-only included) is open.
func (h *Hub) Connected(tenant string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, t := range h.m[tenant] {
		if !t.sess.IsClosed() {
			return true
		}
	}
	return false
}

// Tunnels lists the tunnels this replica holds to tenant.
func (h *Hub) Tunnels(tenant string) []Info {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []Info{}
	for _, t := range h.m[tenant] {
		out = append(out, Info{Serial: t.Serial, Remote: t.Remote, Connected: t.Connected, LastSeen: t.LastSeen(),
			Version: t.Version(), Mode: t.Mode(), Lane: t.Lane(), SkewMS: t.ClockSkew().Milliseconds(), Draining: t.draining.Load()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Connected.Before(out[j].Connected) })
	return out
}

// Drop closes every tunnel of tenant, or only those using serial.
func (h *Hub) Drop(tenant, serial string) int {
	h.mu.Lock()
	var hit []*Tunnel
	for _, t := range h.m[tenant] {
		if serial == "" || t.Serial == serial {
			hit = append(hit, t)
		}
	}
	h.mu.Unlock()
	for _, t := range hit {
		t.sess.Close()
	}
	return len(hit)
}

// Drain tells every agent to move to another replica, stops new streams
// here, and closes each tunnel once its open streams end or grace passes.
func (h *Hub) Drain(grace time.Duration) {
	h.mu.Lock()
	var all []*Tunnel
	for _, ts := range h.m {
		all = append(all, ts...)
	}
	h.mu.Unlock()
	var wg sync.WaitGroup
	for _, t := range all {
		t.draining.Store(true)
		t.send(Message{Type: "drain", Grace: int(grace.Seconds())})
		wg.Add(1)
		go func() {
			defer wg.Done()
			deadline := time.Now().Add(grace)
			// The control stream stays open to the end; it is not an API stream.
			for t.sess.NumStreams() > 1 && time.Now().Before(deadline) && !t.sess.IsClosed() {
				time.Sleep(200 * time.Millisecond)
			}
			t.sess.GoAway()
			t.sess.Close()
		}()
	}
	wg.Wait()
}

// Dial opens a stream to the tenant API through one of tenant's tunnels.
func (h *Hub) Dial(ctx context.Context, tenant string) (net.Conn, error) {
	return h.DialLane(ctx, tenant, "")
}

// DialLane opens a stream on a tunnel of the given lane, or any live tunnel
// when that lane has none ("" means any).
func (h *Hub) DialLane(ctx context.Context, tenant, lane string) (net.Conn, error) {
	h.mu.Lock()
	var live, inLane []*Tunnel
	for _, t := range h.m[tenant] {
		if t.usable() {
			live = append(live, t)
			if lane != "" && t.Lane() == lane {
				inLane = append(inLane, t)
			}
		}
	}
	h.mu.Unlock()
	if len(inLane) > 0 {
		live = inLane
	}
	if len(live) == 0 {
		return nil, ErrOffline
	}
	t := live[h.next.Add(1)%uint64(len(live))]
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { c, err := t.sess.Open(); ch <- res{c, err} }()
	select {
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.c != nil {
				r.c.Close()
			}
		}()
		return nil, ctx.Err()
	case r := <-ch:
		return r.c, r.err
	}
}
