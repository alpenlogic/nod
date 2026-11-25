// Command nod-try runs one approval end to end on this Mac: it builds a
// request, asks with the nod helper (the Touch ID or password sheet
// appears), and verifies the signature with the enrolled public key.
//
//	nod-try -helper helper/.build/release/nod -label test -pub "$(nod pubkey --label test)"
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"istando.dev/nod"
)

func main() {
	helper := flag.String("helper", "nod", "path to the nod helper")
	label := flag.String("label", "default", "enrolled key label")
	pub := flag.String("pub", "", "the key's public line, from nod pubkey")
	flag.Parse()
	key, err := nod.ParsePublicKey(*pub)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	req := nod.Request{V: nod.Version, ID: nod.NewID(), Service: "nod-try", Requester: "nod-try",
		Action: "test", Subject: "this approval", Digest: nod.Digest("nod-try"),
		Reason: "checking that approvals work", Expires: time.Now().Add(time.Minute)}
	a, err := nod.Helper{Path: *helper, Label: *label}.Ask(context.Background(), req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ask:", err)
		os.Exit(1)
	}
	if err := nod.Verify(key, a, req, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(1)
	}
	fmt.Println("approved and verified with", key.Fingerprint())
}
