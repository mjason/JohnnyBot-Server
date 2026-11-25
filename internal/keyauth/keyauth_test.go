package keyauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func line(t *testing.T, pub any) string {
	t.Helper()
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(k))
}

func setup(t *testing.T) (*Keyring, ed25519.PrivateKey, string) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "authorized_keys")
	os.WriteFile(path, []byte("# phone\n"+line(t, pub)), 0o600)
	k, err := Open(path, "HOST", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return k, key, path
}

func TestVerify(t *testing.T) {
	k, key, _ := setup(t)
	id := DeviceID(key.Public().(ed25519.PublicKey))
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()

	good := Sign(key, "HOST", now)
	if err := k.Verify(id, good, now); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"replay":     good,
		"other host": Sign(key, "EVIL", now),
		"other key":  Sign(stranger, "HOST", now),
		"old":        Sign(key, "HOST", now.Add(-3*time.Minute)),
		"future":     Sign(key, "HOST", now.Add(3*time.Minute)),
		"empty":      "",
		"no sig":     strings.Join(strings.Split(good, ".")[:2], ".") + ".",
	}
	for name, proof := range bad {
		if k.Verify(id, proof, now) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if k.Verify(DeviceID(stranger.Public().(ed25519.PublicKey)), Sign(stranger, "HOST", now), now) == nil {
		t.Error("unknown device accepted")
	}
}

func TestReload(t *testing.T) {
	k, key, path := setup(t)
	id := DeviceID(key.Public().(ed25519.PublicKey))
	if r, err := k.Reload(); err != nil || len(r) != 0 {
		t.Fatal(r, err)
	}
	os.Remove(path)
	if r, err := k.Reload(); err != nil || len(r) != 1 || r[0] != id || k.Has(id) {
		t.Fatal(r, err)
	}
}

func TestUnsupportedLinesGrantNothing(t *testing.T) {
	k, _, path := setup(t)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(path, []byte(line(t, &rk.PublicKey)+`expiry-time="20200101" `+line(t, pub)+"garbage\n"), 0o600)
	k.Reload()
	if len(k.keys) != 0 {
		t.Fatal(len(k.keys))
	}
}

func TestDeviceConfigReload(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	id := DeviceID(pub)
	path := filepath.Join(t.TempDir(), "devices.json")
	data, _ := json.Marshal(map[string][]string{"authorized_keys": {strings.TrimSpace(line(t, pub)) + " iPhone"}})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	k, err := OpenConfig(path, "host", slog.New(slog.DiscardHandler))
	if err != nil || !k.Has(id) {
		t.Fatalf("key missing: %v", err)
	}
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	removed, err := k.Reload()
	if err == nil || len(removed) != 1 || k.Has(id) {
		t.Fatal("malformed config must revoke access")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Reload(); err != nil || !k.Has(id) {
		t.Fatal("valid config must restore access", err)
	}
}

func TestReadProofIsSeparateFromMQTTAndSingleUse(t *testing.T) {
	ring, key, _ := setup(t)
	id := DeviceID(key.Public().(ed25519.PublicKey))
	now := time.Now()
	mqtt := Sign(key, "HOST", now)
	if ring.VerifyRead(id, mqtt, now) == nil {
		t.Fatal("MQTT proof accepted on read stream")
	}
	parts := strings.Split(mqtt, ".")
	signed := strings.Join([]string{"johnnybot-read-v1", "HOST", id, parts[0], parts[1]}, "\n")
	parts[2] = b64.EncodeToString(ed25519.Sign(key, []byte(signed)))
	read := strings.Join(parts, ".")
	if ring.Verify(id, read, now) == nil {
		t.Fatal("read proof accepted by MQTT")
	}
	if err := ring.VerifyRead(id, read, now); err != nil {
		t.Fatal(err)
	}
	if ring.VerifyRead(id, read, now) == nil {
		t.Fatal("read proof replayed")
	}
}
