// Package broker is the embedded MQTT broker that the clients connect to.
package broker

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/mochi-mqtt/server/v2/packets"

	"johnny_bot/internal/keyauth"
)

const (
	maxPacket      = 256 << 10
	connectTimeout = 10 * time.Second
	reloadEvery    = 2 * time.Second
)

// CommandFunc handles a command. It runs before the broker acknowledges the
// message: store the command and return. On an error the client gets a failure
// code and may send the command again.
type CommandFunc func(device string, payload []byte) error

// Broker serves the topics of one host:
//
//	jb/v1/{host}/cmd/{device}    the device writes its commands
//	jb/v1/{host}/reply/{device}  the device reads its replies
//	jb/v1/{host}/ev/...          all devices read
//	jb/v1/{host}/live/...        all devices read
type Broker struct {
	prefix string
	server *mqtt.Server
	keys   *keyauth.Keyring
	log    *slog.Logger
	addr   net.Addr
}

var validHost = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// New listens on addr. Call Run to serve.
func New(host, addr string, cert tls.Certificate, keys *keyauth.Keyring, onCommand CommandFunc, log *slog.Logger) (*Broker, error) {
	if !validHost.MatchString(host) {
		return nil, fmt.Errorf("host %q must be letters, digits, '_', '.' or '-'", host)
	}
	caps := mqtt.NewDefaultServerCapabilities()
	caps.MinimumProtocolVersion = 5
	caps.MaximumPacketSize = maxPacket
	caps.MaximumClients = 64
	caps.SharedSubAvailable = 0
	// Clients catch up with sync.pull, so the broker keeps sessions only for a short drop.
	caps.MaximumSessionExpiryInterval = 60
	caps.MaximumMessageExpiryInterval = 60

	b := &Broker{prefix: "jb/v1/" + host + "/", keys: keys, log: log}
	b.server = mqtt.New(&mqtt.Options{InlineClient: true, Capabilities: caps, Logger: log})
	if err := b.server.AddHook(&hook{b: b, onCommand: onCommand}, nil); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	b.addr = ln.Addr()
	conf := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if err := b.server.AddListener(listeners.NewNet("tls", tls.NewListener(deadlineListener{ln}, conf))); err != nil {
		ln.Close()
		return nil, err
	}
	return b, nil
}

func (b *Broker) Addr() net.Addr { return b.addr }

// Run serves until ctx ends. It drops a device soon after its key is removed.
func (b *Broker) Run(ctx context.Context) error {
	if err := b.server.Serve(); err != nil {
		return err
	}
	defer b.server.Close()
	tick := time.NewTicker(reloadEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			removed, err := b.keys.Reload()
			if err != nil {
				b.log.Error("authorized_keys unreadable, all devices are locked out", "err", err.Error())
			}
			for _, id := range removed {
				b.log.Info("device revoked", "device", id)
				if cl, ok := b.server.Clients.Get(id); ok {
					b.server.DisconnectClient(cl, packets.ErrNotAuthorized)
				}
			}
		}
	}
}

// Reply sends to one device.
func (b *Broker) Reply(device string, payload []byte) error {
	return b.server.Publish(b.prefix+"reply/"+device, payload, false, 1)
}

// Event sends to all devices, at least once while they are connected.
func (b *Broker) Event(topic string, payload []byte) error {
	return b.server.Publish(b.prefix+"ev/"+topic, payload, false, 1)
}

// Live sends to all devices, at most once.
func (b *Broker) Live(topic string, payload []byte) error {
	return b.server.Publish(b.prefix+"live/"+topic, payload, false, 0)
}

// HostFingerprint is the SHA-256 of the DER certificate, which devices pin.
func HostFingerprint(cert tls.Certificate) string {
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:])
}

type hook struct {
	mqtt.HookBase
	b         *Broker
	onCommand CommandFunc
}

func (h *hook) ID() string { return "johnnybot" }

func (h *hook) Provides(m byte) bool {
	return m == mqtt.OnConnectAuthenticate || m == mqtt.OnACLCheck || m == mqtt.OnPublish
}

func (h *hook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	err := func() error {
		if pk.Connect.WillFlag {
			return fmt.Errorf("wills are not allowed") // mochi publishes them without an ACL check
		}
		if string(pk.Connect.Username) != keyauth.Scheme {
			return fmt.Errorf("username must be %q", keyauth.Scheme)
		}
		return h.b.keys.Verify(cl.ID, string(pk.Connect.Password), time.Now())
	}()
	if err != nil {
		h.b.log.Warn("connection refused", "remote", cl.Net.Remote, "err", err.Error())
		return false
	}
	h.b.log.Info("device connected", "device", cl.ID, "remote", cl.Net.Remote)
	return true
}

// OnACLCheck sees the topic of a publish, the filter of a subscribe, and the
// topic of each delivery.
func (h *hook) OnACLCheck(cl *mqtt.Client, topic string, write bool) bool {
	if !h.b.keys.Has(cl.ID) {
		return false
	}
	rest, ok := strings.CutPrefix(topic, h.b.prefix)
	if !ok {
		return false
	}
	if write {
		return rest == "cmd/"+cl.ID
	}
	return rest == "reply/"+cl.ID || strings.HasPrefix(rest, "ev/") || strings.HasPrefix(rest, "live/")
}

func (h *hook) OnPublish(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	if cl.Net.Inline {
		return pk, nil
	}
	// The ACL leaves only the device's own command topic.
	if pk.FixedHeader.Retain || pk.FixedHeader.Qos != 1 {
		return pk, packets.ErrImplementationSpecificError
	}
	if err := h.onCommand(cl.ID, pk.Payload); err != nil {
		h.b.log.Error("command failed", "device", cl.ID, "err", err.Error())
		return pk, packets.ErrUnspecifiedError
	}
	return pk, packets.CodeSuccessIgnore // acknowledge, do not route
}

// deadlineListener bounds the time a peer may take for TLS and CONNECT. mochi
// replaces the deadline with the keepalive right before it authenticates.
type deadlineListener struct{ net.Listener }

func (l deadlineListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return c, c.SetDeadline(time.Now().Add(connectTimeout))
}
