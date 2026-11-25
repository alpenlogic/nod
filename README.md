# nod

Approve what an agent asks to do with Touch ID or your Mac login
password, and let a service check that you really did.

An agent asks a service (Istando, say) to release an entry. The service
asks `nod`, the system sheet appears on your Mac:

> "nod" is trying to approve: discobot asks to release
> user.heather.finance:routing:1.0.0 (istando).
> discobot says: "ready for Lori"

You touch the sensor (or type your password), and the service gets a
signature it verifies before acting. Cancel, or let it time out, and the
agent hears "declined".

## Why a signature, not a token

The approval is a signature by a P-256 key in your Mac's **Secure
Enclave**, created so that every use needs your presence
(`.privateKeyUsage` + `.userPresence`). Nothing running as you, agents
included, can sign without the sheet and your finger or password. No
secret sits in a file to be read or replayed: the key file nod keeps is a
handle that only this Mac's Secure Enclave can use, and only with you.

Each service stores your **public** key and verifies approvals itself.
There is no approval server, so no project depends on another being up.

## Parts

- `helper/`: the `nod` command (Swift).
  - `nod enroll [--label L]`: create a key, print its public key line.
  - `nod pubkey [--label L]`: print it again.
  - `nod sign [--label L] < request`: show the sheet, print the approval.
- `istando.dev/nod` (Go): `Request`, `Helper.Ask` (runs the helper),
  `Verify`, `ParsePublicKey`.
- `cmd/nod-try`: one approval end to end, to check a setup.

## How a service uses it

```go
req := nod.Request{V: nod.Version, ID: nod.NewID(), Service: "istando",
	Requester: "discobot", Action: "release", Subject: coord,
	Digest: nod.Digest(rev, mac), Reason: agentWords,
	Expires: time.Now().Add(2 * time.Minute)}
a, err := nod.Helper{Path: helperPath}.Ask(ctx, req) // the sheet appears
if err == nil {
	err = nod.Verify(enrolledKey, a, req, time.Now())
}
```

- **The dialog text is built by the helper** from `service`, `requester`,
  `action` and `subject`, which the service sets. `reason` is shown only
  as the requester's own words. Control and bidirectional-override
  characters are refused, so the text can't be disguised.
- **The helper signs the exact bytes it showed**, and `Verify` checks
  those bytes against the request the service expected, field by field.
  The dialog, the signature and the action can't drift apart.
- **`Digest` binds the payload**: for Istando, the revision and content
  MAC being released, so you approve exactly what you'd review.
- **IDs are single use**: keep each pending request by ID and drop it once
  verified, and a captured approval can't be replayed. Requests live at
  most 10 minutes.

## Build and try

```sh
cd helper && swift build -c release && cd ..
helper/.build/release/nod enroll --label test
go run ./cmd/nod-try -helper helper/.build/release/nod -label test \
  -pub "$(helper/.build/release/nod pubkey --label test)"
```

The helper must run in your logged-in GUI session (a LaunchAgent counts)
for the sheet to appear.

## Status

Early. Signing and notarizing the helper with a Developer ID, and
Istando's use of it, come next.

## License

Apache-2.0
