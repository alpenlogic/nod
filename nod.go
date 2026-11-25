// Package nod asks a person to approve an action with Touch ID (or their
// login password) and lets a service verify that they did.
//
// The approval is a signature by a P-256 key held in the Secure Enclave
// of the person's Mac. The key is created with user presence required for
// every use, so nothing — no agent, no process running as the person —
// can sign without the system sheet and the person's finger or password.
// The private key never leaves the Secure Enclave; the file the helper
// keeps is a handle that only that Mac's Secure Enclave can use.
//
// A service enrolls the person's public key once, then for each action:
//
//	req := nod.Request{ID: nod.NewID(), Service: "istando", Requester: "discobot",
//		Action: "release", Subject: "finance:routing:1.0.0", Digest: nod.Digest(rev, mac),
//		Reason: agentWords, Expires: time.Now().Add(2 * time.Minute)}
//	a, err := nod.Helper{}.Ask(ctx, req)   // shows the sheet on this Mac
//	err = nod.Verify(pub, a, req, time.Now())
//
// The helper signs the exact request bytes it shows, and Verify checks
// those bytes against the request the service expected, so the dialog,
// the signature and the action can't drift apart. Each service keeps its
// own enrolled keys and verifies on its own: there is no approval server.
//
// IDs are single use: a service keeps a pending request per ID and drops
// it once verified, so a captured approval can't be replayed.
package nod

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Version is the request format this package writes and accepts.
const Version = 1

// Limits on what a request may carry. The helper enforces the same ones.
const (
	MaxFieldChars  = 200 // service, requester, action, subject
	MaxReasonChars = 300 // the requester's own words
	MaxLifetime    = 10 * time.Minute
)

// Request is what the person approves. Service, Action and Subject make up
// the dialog's main text; Requester (who asks, e.g. an agent) and Reason
// (their words) follow on a line of their own. Leave Requester empty when
// the person themself started the action: the sheet then names no one. Digest binds the approval to the exact
// payload (for istando: the revision and content MAC being released).
type Request struct {
	V         int       `json:"v"`
	ID        string    `json:"id"`
	Service   string    `json:"service"`
	Requester string    `json:"requester"`
	Action    string    `json:"action"`
	Subject   string    `json:"subject"`
	Digest    string    `json:"digest"`
	Reason    string    `json:"reason,omitempty"`
	Expires   time.Time `json:"expires"`
}

// Approval is a signed request: the exact bytes the helper showed and
// signed, the signature (ASN.1 DER ECDSA over SHA-256 of those bytes), and
// the signing key's fingerprint.
type Approval struct {
	Request   []byte `json:"request"`
	Signature []byte `json:"signature"`
	Key       string `json:"key"`
}

var (
	// ErrDeclined: the person declined, or didn't answer in time
	// (ErrNoAnswer, which matches ErrDeclined too).
	ErrDeclined = errors.New("nod: declined")
	// ErrNoAnswer: the request expired before the person answered.
	ErrNoAnswer = fmt.Errorf("%w: no answer before the request expired", ErrDeclined)
	// ErrUnavailable: the helper couldn't ask (no key enrolled, no GUI
	// session, no Secure Enclave).
	ErrUnavailable = errors.New("nod: approval unavailable")
	// ErrBadSignature: the signature doesn't verify under the key.
	ErrBadSignature = errors.New("nod: bad signature")
	// ErrMismatch: the signed request isn't the one expected.
	ErrMismatch = errors.New("nod: approval is for a different request")
	// ErrExpired: the request has expired.
	ErrExpired = errors.New("nod: approval expired")
)

// NewID returns a fresh random request ID.
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Digest hashes the parts of a payload, unambiguously (each part is
// length-prefixed), as hex SHA-256.
func Digest(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		fmt.Fprintf(h, "%d:%s\n", len(p), p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Check reports what is wrong with a request before it is shown.
func (r Request) Check(now time.Time) error {
	for name, v := range map[string]string{"service": r.Service, "action": r.Action, "subject": r.Subject} {
		if err := checkText(name, v, MaxFieldChars, true); err != nil {
			return err
		}
	}
	if err := checkText("requester", r.Requester, MaxFieldChars, false); err != nil {
		return err
	}
	if err := checkText("reason", r.Reason, MaxReasonChars, false); err != nil {
		return err
	}
	switch {
	case r.V != Version:
		return fmt.Errorf("nod: request version %d; want %d", r.V, Version)
	case len(r.ID) < 16:
		return errors.New("nod: request id too short")
	case r.Digest == "":
		return errors.New("nod: request has no digest")
	case !r.Expires.After(now):
		return ErrExpired
	case r.Expires.Sub(now) > MaxLifetime:
		return fmt.Errorf("nod: request expires in %s; at most %s", r.Expires.Sub(now).Round(time.Second), MaxLifetime)
	}
	return nil
}

func checkText(name, v string, max int, required bool) error {
	switch {
	case required && strings.TrimSpace(v) == "":
		return fmt.Errorf("nod: request %s is empty", name)
	case !utf8.ValidString(v):
		return fmt.Errorf("nod: request %s is not UTF-8", name)
	case utf8.RuneCountInString(v) > max:
		return fmt.Errorf("nod: request %s is over %d characters", name, max)
	case strings.ContainsFunc(v, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) }):
		return fmt.Errorf("nod: request %s has control characters", name)
	}
	return nil
}

// Marshal is the request as sent to the helper.
func (r Request) Marshal() ([]byte, error) {
	r.Expires = r.Expires.UTC().Truncate(time.Second)
	return json.Marshal(r)
}

// PublicKey is an enrolled approval key.
type PublicKey struct {
	Key   *ecdsa.PublicKey
	Label string // who and where, e.g. heather@denali; informational
}

// keyPrefix starts the text form of a public key: "nod-p256 <base64
// SubjectPublicKeyInfo DER> <label>", one line, like an SSH key.
const keyPrefix = "nod-p256"

// ParsePublicKey reads the line nod enroll prints.
func ParsePublicKey(s string) (*PublicKey, error) {
	f := strings.Fields(s)
	if len(f) < 2 || f[0] != keyPrefix {
		return nil, fmt.Errorf("nod: want %q followed by a key", keyPrefix)
	}
	der, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return nil, fmt.Errorf("nod: key: %w", err)
	}
	pk, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("nod: key: %w", err)
	}
	ek, ok := pk.(*ecdsa.PublicKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("nod: key is not P-256")
	}
	return &PublicKey{Key: ek, Label: strings.Join(f[2:], " ")}, nil
}

// String is the one-line form ParsePublicKey reads.
func (k *PublicKey) String() string {
	der, _ := x509.MarshalPKIXPublicKey(k.Key)
	s := keyPrefix + " " + base64.StdEncoding.EncodeToString(der)
	if k.Label != "" {
		s += " " + k.Label
	}
	return s
}

// Fingerprint names a key: SHA256: and the unpadded base64 of the SHA-256
// of its SubjectPublicKeyInfo, as ssh-keygen -l does.
func (k *PublicKey) Fingerprint() string {
	der, _ := x509.MarshalPKIXPublicKey(k.Key)
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// Verify checks an approval: the signature over the signed bytes under
// key, then that those bytes are exactly the request the service expects
// (every field, the expiry included), and that it hasn't expired.
func Verify(key *PublicKey, a *Approval, want Request, now time.Time) error {
	if a == nil {
		return ErrBadSignature
	}
	sum := sha256.Sum256(a.Request)
	if !ecdsa.VerifyASN1(key.Key, sum[:], a.Signature) {
		return ErrBadSignature
	}
	var got Request
	d := json.NewDecoder(bytes.NewReader(a.Request))
	d.DisallowUnknownFields()
	if err := d.Decode(&got); err != nil {
		return fmt.Errorf("%w: %v", ErrMismatch, err)
	}
	want.Expires = want.Expires.UTC().Truncate(time.Second)
	got.Expires = got.Expires.UTC()
	if got != want {
		return ErrMismatch
	}
	if !now.Before(got.Expires) {
		return ErrExpired
	}
	return nil
}

// Helper runs the nod helper to ask for approval on this Mac.
type Helper struct {
	Path  string // the nod binary; default "nod" on PATH
	Label string // which enrolled key; default "default"
}

// Exit codes of nod sign.
const (
	exitDeclined    = 2
	exitUnavailable = 3
	exitNoAnswer    = 4
)

// Ask shows the request and returns the person's signed approval. It
// returns ErrDeclined if they decline (ErrNoAnswer, which also matches
// ErrDeclined, if the request expires first), and
// ErrUnavailable if the helper can't ask. Cancelling ctx dismisses the
// sheet.
func (h Helper) Ask(ctx context.Context, req Request) (*Approval, error) {
	if err := req.Check(time.Now()); err != nil {
		return nil, err
	}
	raw, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	path, label := h.Path, h.Label
	if path == "" {
		path = "nod"
	}
	if label == "" {
		label = "default"
	}
	ctx, cancel := context.WithDeadline(ctx, req.Expires)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "sign", "--label", label)
	cmd.Stdin = bytes.NewReader(raw)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case ctx.Err() != nil, errors.As(err, &ee) && ee.ExitCode() == exitNoAnswer:
		return nil, ErrNoAnswer
	case errors.As(err, &ee) && ee.ExitCode() == exitDeclined:
		return nil, ErrDeclined
	case errors.As(err, &ee) && ee.ExitCode() == exitUnavailable:
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, strings.TrimSpace(errb.String()))
	case err != nil:
		return nil, fmt.Errorf("nod: helper: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	var a Approval
	if err := json.Unmarshal(out.Bytes(), &a); err != nil {
		return nil, fmt.Errorf("nod: helper output: %w", err)
	}
	if !bytes.Equal(a.Request, raw) {
		return nil, errors.New("nod: helper signed something other than the request")
	}
	return &a, nil
}
