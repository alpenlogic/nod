package nod

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A software key stands in for the Secure Enclave: Verify sees only the
// signature, which has the same form.
func testKey(t *testing.T) (*ecdsa.PrivateKey, *PublicKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k, &PublicKey{Key: &k.PublicKey, Label: "test@host"}
}

func sign(t *testing.T, k *ecdsa.PrivateKey, raw []byte) *Approval {
	t.Helper()
	sum := sha256.Sum256(raw)
	sig, err := ecdsa.SignASN1(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return &Approval{Request: raw, Signature: sig}
}

func request(now time.Time) Request {
	return Request{V: Version, ID: NewID(), Service: "istando", Requester: "build-agent", Action: "release",
		Subject: "user.heather.finance:routing:1.0.0", Digest: Digest("3", "mac"), Reason: "ready for review",
		Expires: now.Add(2 * time.Minute)}
}

func TestVerify(t *testing.T) {
	now := time.Now()
	k, pub := testKey(t)
	req := request(now)
	raw, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	a := sign(t, k, raw)
	if err := Verify(pub, a, req, now); err != nil {
		t.Fatalf("verify: %v", err)
	}

	other, otherPub := testKey(t)
	_ = other
	tampered := strings.Replace(string(raw), "routing", "rooting", 1)
	for name, tc := range map[string]struct {
		key  *PublicKey
		a    *Approval
		want Request
		now  time.Time
		err  error
	}{
		"other key":        {otherPub, a, req, now, ErrBadSignature},
		"tampered bytes":   {pub, &Approval{Request: []byte(tampered), Signature: a.Signature}, req, now, ErrBadSignature},
		"different digest": {pub, a, func() Request { r := req; r.Digest = Digest("4", "mac"); return r }(), now, ErrMismatch},
		"different id":     {pub, a, func() Request { r := req; r.ID = NewID(); return r }(), now, ErrMismatch},
		"expired":          {pub, a, req, now.Add(3 * time.Minute), ErrExpired},
		"nil":              {pub, nil, req, now, ErrBadSignature},
	} {
		if err := Verify(tc.key, tc.a, tc.want, tc.now); !errors.Is(err, tc.err) {
			t.Errorf("%s: got %v, want %v", name, err, tc.err)
		}
	}

	// A validly signed request with an extra field is not the request.
	extra := strings.Replace(string(raw), `{"v":1`, `{"v":1,"admin":true`, 1)
	if err := Verify(pub, sign(t, k, []byte(extra)), req, now); !errors.Is(err, ErrMismatch) {
		t.Errorf("extra field: %v", err)
	}
}

func TestCheck(t *testing.T) {
	now := time.Now()
	for name, mod := range map[string]func(*Request){
		"empty subject":     func(r *Request) { r.Subject = " " },
		"newline in action": func(r *Request) { r.Action = "release\nand delete everything" },
		"bidi in subject":   func(r *Request) { r.Subject = "a‮b" },
		"long reason":       func(r *Request) { r.Reason = strings.Repeat("x", MaxReasonChars+1) },
		"too long-lived":    func(r *Request) { r.Expires = now.Add(MaxLifetime + time.Minute) },
		"expired":           func(r *Request) { r.Expires = now.Add(-time.Second) },
		"short id":          func(r *Request) { r.ID = "abc" },
		"no digest":         func(r *Request) { r.Digest = "" },
		"version":           func(r *Request) { r.V = 2 },
	} {
		r := request(now)
		mod(&r)
		if err := r.Check(now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := request(now).Check(now); err != nil {
		t.Fatal(err)
	}
	// The person's own action names no requester.
	own := request(now)
	own.Requester, own.Reason = "", ""
	if err := own.Check(now); err != nil {
		t.Fatalf("no requester: %v", err)
	}
	own.Requester = "a\nb"
	if err := own.Check(now); err == nil {
		t.Error("newline in requester: accepted")
	}
}

func TestPublicKeyText(t *testing.T) {
	_, pub := testKey(t)
	got, err := ParsePublicKey(pub.String())
	if err != nil || !got.Key.Equal(pub.Key) || got.Label != "test@host" || got.Fingerprint() != pub.Fingerprint() {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if !strings.HasPrefix(pub.Fingerprint(), "SHA256:") {
		t.Fatal(pub.Fingerprint())
	}
	for _, bad := range []string{"", "ssh-ed25519 AAAA", "nod-p256 !!!", "nod-p256 " + base64.StdEncoding.EncodeToString([]byte("x"))} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// fakeHelper writes a script that behaves like nod sign: it echoes the
// request back with a signature from key, or exits with code.
func fakeHelper(t *testing.T, k *ecdsa.PrivateKey, code int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "nod")
	script := "#!/bin/sh\nexit " + string(rune('0'+code)) + "\n"
	if code == 0 {
		// The script can't sign; the test signs the request it will
		// receive and has the script print that.
		script = "#!/bin/sh\ncat >/dev/null\ncat " + filepath.Join(dir, "approval.json") + "\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAsk(t *testing.T) {
	now := time.Now()
	k, pub := testKey(t)
	req := request(now)
	raw, _ := req.Marshal()
	path := fakeHelper(t, k, 0)
	b, _ := json.Marshal(sign(t, k, raw))
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "approval.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := Helper{Path: path}.Ask(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, a, req, time.Now()); err != nil {
		t.Fatal(err)
	}

	// A helper that signs something else is refused.
	other := request(now)
	if _, err := (Helper{Path: path}).Ask(context.Background(), other); err == nil || !strings.Contains(err.Error(), "other than the request") {
		t.Fatalf("other request: %v", err)
	}
	if _, err := (Helper{Path: fakeHelper(t, k, 2)}).Ask(context.Background(), req); !errors.Is(err, ErrDeclined) || errors.Is(err, ErrNoAnswer) {
		t.Fatalf("declined: %v", err)
	}
	if _, err := (Helper{Path: fakeHelper(t, k, 4)}).Ask(context.Background(), req); !errors.Is(err, ErrNoAnswer) || !errors.Is(err, ErrDeclined) {
		t.Fatalf("no answer: %v", err)
	}
	if _, err := (Helper{Path: fakeHelper(t, k, 3)}).Ask(context.Background(), req); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Helper{Path: path}).Ask(ctx, req); !errors.Is(err, ErrDeclined) {
		t.Fatalf("cancelled: %v", err)
	}
}

// Unlock passes the name and reason to nod unlock and maps its exit codes.
func TestUnlock(t *testing.T) {
	dir := t.TempDir()
	script := func(body string) string {
		p := filepath.Join(dir, fmt.Sprintf("nod%d", len(body)))
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := script(`[ "$1 $2 $3 $4" = "unlock vault-key --reason boot" ] || exit 1; printf 's3cret'`)
	got, err := Helper{Path: ok}.Unlock(context.Background(), "vault-key", "boot")
	if err != nil || string(got) != "s3cret" {
		t.Fatalf("got %q %v", got, err)
	}
	for code, want := range map[int]error{2: ErrDeclined, 4: ErrNoAnswer, 3: ErrUnavailable} {
		p := script(fmt.Sprintf("exit %d", code))
		if _, err := (Helper{Path: p}).Unlock(context.Background(), "vault-key", ""); !errors.Is(err, want) {
			t.Errorf("exit %d: %v, want %v", code, err, want)
		}
	}
	if _, err := (Helper{Path: ok}).Unlock(context.Background(), "vault-key", "bad\x1b[2Jreason"); err == nil {
		t.Error("control characters in the reason accepted")
	}
}
