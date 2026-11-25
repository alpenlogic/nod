# nod

Approve what an agent asks to do with Touch ID or your Mac login
password, and let a service check that you really did.

An agent asks a service (Istando, say) to release an entry. The service
asks `nod`, and nod's window appears on the screen you're using:

> **istando needs your approval to promote
> user.heather.finance:routing to 1.0.0.RELEASE**
>
> Asked by discobot: "ready for Lori"
>
> (Touch ID) Touch ID to approve
>
> [Use Password…]                                   [Decline]

The words are the service's, not macOS's: nod draws its own window and
runs Touch ID inside it. "Use Password…" (or a Mac without Touch ID)
falls back to the system sheet.

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

- `helper/`: the `nod` command (Swift), packaged as `nod.app` by
  `helper/make-app.sh`.
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

## Security model: what a service must do

Anyone running as you can run `nod sign` with a request they wrote, and
the sheet will show their words; if you approve, they hold a valid
signature over *their* request. So a signature alone proves only that you
approved *some* text. What makes it an approval of an action is the
service's side:

- **Make the request yourself, and only accept approvals for it.** Build
  the `Request` (fresh random `ID`, short `Expires`, `Digest` of the exact
  payload), call `Ask`, and `Verify` the answer against that same request,
  in the same operation. Never offer an endpoint that accepts an
  `Approval` from outside: then a self-made signature has nowhere to go.
- **If you must accept approvals later** (a separate call, another
  process), keep each pending request by `ID`, verify against the stored
  request, and delete it on first use.
- **Set `Requester` to who you authenticated**, never to what a caller
  claims, so the sheet names the real asker.

Istando does the first: the request exists only inside the agent's
promote or delete call, and there is no route that takes an approval.

Residual risk: someone running as you can still put up a sheet with
misleading text. Its signature is useless to a service that follows the
rules above, but it costs you a decision. Decline sheets you didn't
expect.

## Build and try

```sh
app=$(helper/make-app.sh)             # ad hoc; make-app.sh IDENTITY for Developer ID
nod="$app/Contents/MacOS/nod"
"$nod" enroll --label test
go run ./cmd/nod-try -helper "$nod" -label test -pub "$("$nod" pubkey --label test)"
```

The helper must run in your logged-in GUI session (a LaunchAgent counts)
for the sheet to appear.

## Status

Early. Signing and notarizing the helper with a Developer ID, and
Istando's use of it, come next.

## License

Apache-2.0
