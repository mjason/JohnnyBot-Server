// Package keyauth authenticates devices with ssh-ed25519 keys.
//
// A device proves that it holds its key by signing
//
//	johnnybot-mqtt-auth-v1\n<host fingerprint>\n<device id>\n<unix seconds>\n<nonce>
//
// and sends "<unix seconds>.<nonce>.<signature>" as the MQTT password. The host
// fingerprint is the device's pinned one, so a proof given to an impostor is
// useless at the real host. Time and nonce stop a replay.
package keyauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Scheme is the MQTT username. It versions the proof.
const Scheme = "ed25519-v1"

const maxSkew = 2 * time.Minute

var b64 = base64.RawURLEncoding

// DeviceID names a key: 32 hex digits of the SHA-256 of the raw 32-byte public key.
func DeviceID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

func message(host, device, ts, nonce string) []byte {
	return []byte("johnnybot-mqtt-auth-v1\n" + host + "\n" + device + "\n" + ts + "\n" + nonce)
}

// Sign makes the MQTT password for a connection attempt.
func Sign(key ed25519.PrivateKey, host string, now time.Time) string {
	raw := make([]byte, 16)
	rand.Read(raw)
	nonce, ts := b64.EncodeToString(raw), strconv.FormatInt(now.Unix(), 10)
	sig := ed25519.Sign(key, message(host, DeviceID(key.Public().(ed25519.PublicKey)), ts, nonce))
	return ts + "." + nonce + "." + b64.EncodeToString(sig)
}

// Keyring holds the keys of an authorized_keys file.
type Keyring struct {
	path       string
	configFile bool
	host       string
	log        *slog.Logger

	mu   sync.RWMutex
	raw  []byte
	keys map[string]ed25519.PublicKey
	seen map[string]time.Time // used nonces, until they are too old to be accepted
}

// Open reads the file. A missing file means that no device may connect.
func Open(path, hostFingerprint string, log *slog.Logger) (*Keyring, error) {
	return open(path, hostFingerprint, log, false)
}

func OpenConfig(path, hostFingerprint string, log *slog.Logger) (*Keyring, error) {
	return open(path, hostFingerprint, log, true)
}

func open(path, hostFingerprint string, log *slog.Logger, config bool) (*Keyring, error) {
	k := &Keyring{configFile: config, path: path, host: hostFingerprint, log: log, seen: map[string]time.Time{}}
	_, err := k.Reload()
	return k, err
}

// Reload reads the file again and returns the devices that were removed.
// When the file cannot be read, every device is.
func (k *Keyring) Reload() (removed []string, err error) {
	raw, err := os.ReadFile(k.path)
	if !k.configFile && errors.Is(err, os.ErrNotExist) {
		raw, err = nil, nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if err == nil && k.raw != nil && bytes.Equal(raw, k.raw) {
		return nil, nil
	}
	keys := map[string]ed25519.PublicKey{}
	lines := strings.Split(string(raw), "\n")
	if k.configFile {
		var config struct {
			AuthorizedKeys []string `json:"authorized_keys"`
		}
		if err == nil {
			err = json.Unmarshal(raw, &config)
		}
		lines = config.AuthorizedKeys
		if err == nil && lines == nil {
			err = errors.New("config requires an authorized_keys array")
		}
		if err != nil {
			lines = nil
		}
	}
	for i, line := range lines {
		if k.configFile && strings.ContainsAny(line, "\r\n") {
			k.log.Warn("multiline device key ignored", "entry", i+1)
			continue
		}
		if line = strings.TrimSpace(line); line == "" || line[0] == '#' {
			continue
		}
		pub, perr := parse(line)
		if perr != nil {
			k.log.Warn("authorized_keys: line ignored", "line", i+1, "err", perr.Error())
			continue
		}
		keys[DeviceID(pub)] = pub
	}
	for id := range k.keys {
		if _, ok := keys[id]; !ok {
			removed = append(removed, id)
		}
	}
	if err != nil {
		raw = nil
	}
	k.raw, k.keys = raw, keys
	return removed, err
}

func parse(line string) (ed25519.PublicKey, error) {
	key, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, err
	}
	// Ignoring a restriction such as expiry-time would grant more than was meant.
	if len(opts) > 0 {
		return nil, errors.New("key options are not supported")
	}
	if ck, ok := key.(ssh.CryptoPublicKey); ok {
		if pub, ok := ck.CryptoPublicKey().(ed25519.PublicKey); ok && key.Type() == ssh.KeyAlgoED25519 {
			return pub, nil
		}
	}
	return nil, fmt.Errorf("%s is not supported, use ssh-ed25519", key.Type())
}

// Has reports whether the device is authorized now.
func (k *Keyring) Has(device string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	_, ok := k.keys[device]
	return ok
}

// Verify checks the proof of a device. A proof works once.
func (k *Keyring) Verify(device, proof string, now time.Time) error {
	return k.verify("johnnybot-mqtt-auth-v1", device, proof, now)
}

func (k *Keyring) VerifyRead(device, proof string, now time.Time) error {
	return k.verify("johnnybot-read-v1", device, proof, now)
}

func (k *Keyring) verify(protocol, device, proof string, now time.Time) error {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return errors.New("malformed proof")
	}
	ts, nonce := parts[0], parts[1]
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("malformed time")
	}
	if raw, err := b64.Strict().DecodeString(nonce); err != nil || len(raw) != 16 {
		return errors.New("malformed nonce")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return errors.New("malformed signature")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > maxSkew || d < -maxSkew {
		return fmt.Errorf("clock differs by more than %v", maxSkew)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	pub, ok := k.keys[device]
	if !ok {
		return errors.New("unknown device")
	}
	if !ed25519.Verify(pub, []byte(strings.Join([]string{protocol, k.host, device, ts, nonce}, "\n")), sig) {
		return errors.New("bad signature")
	}
	for n, until := range k.seen {
		if now.After(until) {
			delete(k.seen, n)
		}
	}
	if _, used := k.seen[device+nonce]; used {
		return errors.New("proof was already used")
	}
	k.seen[device+nonce] = now.Add(2*maxSkew + time.Second)
	return nil
}
