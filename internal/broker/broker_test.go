package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/paho"
	"golang.org/x/crypto/ssh"

	"johnny_bot/internal/keyauth"
)

type env struct {
	b        *Broker
	fp       string
	keysPath string
	cmds     chan string
	fail     atomic.Bool
}

type device struct {
	key  ed25519.PrivateKey
	id   string
	line string
}

func newDevice(t *testing.T) device {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	sk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return device{key, keyauth.DeviceID(pub), string(ssh.MarshalAuthorizedKey(sk))}
}

func setup(t *testing.T, devs ...device) *env {
	t.Helper()
	dir := t.TempDir()
	cert, err := LoadOrCreateCert(filepath.Join(dir, "host.pem"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreateCert(filepath.Join(dir, "host.pem"))
	if err != nil || HostFingerprint(again) != HostFingerprint(cert) {
		t.Fatal("host key changed on reload", err)
	}
	e := &env{fp: HostFingerprint(cert), keysPath: filepath.Join(dir, "authorized_keys"), cmds: make(chan string, 8)}
	var lines string
	for _, d := range devs {
		lines += d.line
	}
	os.WriteFile(e.keysPath, []byte(lines), 0o600)
	log := slog.New(slog.DiscardHandler)
	keys, err := keyauth.Open(e.keysPath, e.fp, log)
	if err != nil {
		t.Fatal(err)
	}
	e.b, err = New("h", "127.0.0.1:0", cert, keys, func(dev string, p []byte) error {
		if e.fail.Load() {
			return errors.New("disk full")
		}
		e.cmds <- dev + " " + string(p)
		return nil
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.b.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return e
}

type conn struct {
	*paho.Client
	got    chan *paho.Publish
	closed chan struct{}
}

func (e *env) dial(t *testing.T, d device, edit func(*paho.Connect)) (*conn, error) {
	t.Helper()
	nc, err := tls.Dial("tcp", e.b.Addr().String(), &tls.Config{InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if HostFingerprint(tls.Certificate{Certificate: [][]byte{cs.PeerCertificates[0].Raw}}) != e.fp {
				return errors.New("wrong host")
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	c := &conn{got: make(chan *paho.Publish, 8), closed: make(chan struct{}, 2)}
	c.Client = paho.NewClient(paho.ClientConfig{Conn: nc,
		OnPublishReceived: []func(paho.PublishReceived) (bool, error){func(p paho.PublishReceived) (bool, error) {
			c.got <- p.Packet
			return true, nil
		}},
		OnServerDisconnect: func(*paho.Disconnect) { c.closed <- struct{}{} },
		OnClientError:      func(error) { c.closed <- struct{}{} }})
	cp := &paho.Connect{ClientID: d.id, KeepAlive: 30, CleanStart: true,
		UsernameFlag: true, Username: keyauth.Scheme,
		PasswordFlag: true, Password: []byte(keyauth.Sign(d.key, e.fp, time.Now()))}
	if edit != nil {
		edit(cp)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = c.Connect(ctx, cp)
	t.Cleanup(func() { nc.Close() })
	return c, err
}

func (c *conn) sub(topic string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := c.Subscribe(ctx, &paho.Subscribe{Subscriptions: []paho.SubscribeOptions{{Topic: topic, QoS: 1}}})
	return err
}

func (c *conn) pub(topic, payload string, retain bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := c.Publish(ctx, &paho.Publish{Topic: topic, QoS: 1, Retain: retain, Payload: []byte(payload)})
	return err
}

func TestAuth(t *testing.T) {
	phone, stranger := newDevice(t), newDevice(t)
	e := setup(t, phone)
	if _, err := e.dial(t, phone, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.dial(t, stranger, nil); err == nil {
		t.Error("stranger accepted")
	}
	if _, err := e.dial(t, device{stranger.key, phone.id, ""}, nil); err == nil {
		t.Error("stranger accepted under the id of phone")
	}
	if _, err := e.dial(t, phone, func(c *paho.Connect) { c.ClientID = "other" }); err == nil {
		t.Error("foreign client id accepted")
	}
	if _, err := e.dial(t, phone, func(c *paho.Connect) {
		c.WillMessage = &paho.WillMessage{Topic: "jb/v1/h/ev/threads", Payload: []byte("forged")}
	}); err == nil {
		t.Error("will accepted")
	}
	var proof []byte
	if _, err := e.dial(t, phone, func(c *paho.Connect) { proof = c.Password }); err != nil {
		t.Fatal(err)
	}
	if _, err := e.dial(t, phone, func(c *paho.Connect) { c.Password = proof }); err == nil {
		t.Error("replayed proof accepted")
	}
}

func TestACL(t *testing.T) {
	phone, mac := newDevice(t), newDevice(t)
	e := setup(t, phone, mac)
	c, err := e.dial(t, phone, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, topic := range []string{"#", "jb/v1/h/#", "jb/v1/h/+/" + mac.id, "jb/v1/h/cmd/#", "jb/v1/h/reply/" + mac.id, "jb/v1/h/reply/+", "jb/v1/x/ev/#", "$SYS/#", "$share/g/jb/v1/h/ev/#"} {
		if c.sub(topic) == nil {
			t.Errorf("subscribed to %s", topic)
		}
	}
	for _, topic := range []string{"jb/v1/h/cmd/" + mac.id, "jb/v1/h/reply/" + mac.id, "jb/v1/h/ev/threads", "x"} {
		if c.pub(topic, "x", false) == nil {
			t.Errorf("published to %s", topic)
		}
	}
	if c.pub("jb/v1/h/cmd/"+phone.id, "x", true) == nil {
		t.Error("retained command accepted")
	}
	if len(e.cmds) != 0 {
		t.Error("a refused publish reached the handler")
	}
}

func TestCommandAndDelivery(t *testing.T) {
	phone, mac := newDevice(t), newDevice(t)
	e := setup(t, phone, mac)
	cp, err := e.dial(t, phone, nil)
	if err != nil {
		t.Fatal(err)
	}
	cm, err := e.dial(t, mac, nil)
	if err != nil {
		t.Fatal(err)
	}
	for c, d := range map[*conn]device{cp: phone, cm: mac} {
		for _, topic := range []string{"jb/v1/h/reply/" + d.id, "jb/v1/h/ev/#"} {
			if err := c.sub(topic); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The handler has run by the time the client has its PUBACK.
	if err := cp.pub("jb/v1/h/cmd/"+phone.id, "hi", false); err != nil {
		t.Fatal(err)
	}
	if len(e.cmds) != 1 || <-e.cmds != phone.id+" hi" {
		t.Fatal("command not handled before the ack")
	}
	e.fail.Store(true)
	if cp.pub("jb/v1/h/cmd/"+phone.id, "hi", false) == nil {
		t.Error("failed command was acknowledged as a success")
	}
	e.b.Reply(phone.id, []byte("r"))
	e.b.Event("threads", []byte("e"))
	want := map[*conn][]string{cp: {"r", "e"}, cm: {"e"}}
	for c, msgs := range want {
		for _, m := range msgs {
			select {
			case p := <-c.got:
				if string(p.Payload) != m || p.QoS != 1 {
					t.Errorf("got %q at QoS %d, want %q at QoS 1", p.Payload, p.QoS, m)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("%q not delivered", m)
			}
		}
	}
	if len(cm.got) != 0 {
		t.Error("mac saw a reply to phone")
	}
}

func TestRevokedDeviceIsDropped(t *testing.T) {
	phone := newDevice(t)
	e := setup(t, phone)
	c, err := e.dial(t, phone, nil)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(e.keysPath, nil, 0o600)
	select {
	case <-c.closed:
	case <-time.After(reloadEvery + 3*time.Second):
		t.Fatal("still connected")
	}
	if _, err := e.dial(t, phone, nil); err == nil {
		t.Error("revoked device reconnected")
	}
}
