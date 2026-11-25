// nod: approve an action with Touch ID or your login password.
//
//   nod enroll [--label L] [--force]   create a Secure Enclave key; print its public key
//   nod pubkey [--label L]             print the public key again
//   nod sign   [--label L] < request   show the request, sign it, print the approval
//
// The key is a P-256 key in the Secure Enclave, created with
// .privateKeyUsage and .userPresence: every signature needs Touch ID or
// the login password, through the system sheet. What nod stores in
// ~/Library/Application Support/nod/<label>.key is a handle only this
// Mac's Secure Enclave can use; it is useless anywhere else, and useless
// here without the person.
//
// nod sign reads a request (JSON, the Go package's Request), builds the
// sheet's text itself from the service, requester, action and subject,
// shows the requester's reason only as their words, and signs the exact
// bytes it read. Exit codes: 0 signed, 2 declined or expired, 3 unable to
// ask, 1 any other error, 64 usage.

import CryptoKit
import Foundation
@preconcurrency import LocalAuthentication
import Security

enum Code: Int32 {
    case ok = 0, failure = 1, declined = 2, unavailable = 3, usage = 64
}

struct Failure: Error {
    let code: Code
    let message: String
}

let maxField = 200
let maxReason = 300
let maxLifetime: TimeInterval = 600
let maxRequestBytes = 8192

func fail(_ code: Code, _ message: String) -> Never {
    FileHandle.standardError.write(Data(("nod: " + message + "\n").utf8))
    exit(code.rawValue)
}

// MARK: Key files

func keyURL(_ label: String) throws -> URL {
    guard label.range(of: "^[a-z0-9][a-z0-9-]{0,31}$", options: .regularExpression) != nil else {
        throw Failure(code: .usage, message: "label must be lowercase letters, digits and dashes")
    }
    let dir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/nod", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    return dir.appendingPathComponent(label + ".key")
}

func loadKey(_ label: String, context: LAContext? = nil) throws -> SecureEnclave.P256.Signing.PrivateKey {
    let url = try keyURL(label)
    guard let blob = try? Data(contentsOf: url) else {
        throw Failure(code: .unavailable, message: "no key \"\(label)\"; run nod enroll")
    }
    do {
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
    } catch {
        throw Failure(code: .unavailable, message: "key \"\(label)\" can't be used on this Mac: \(error.localizedDescription)")
    }
}

func publicKeyLine(_ key: SecureEnclave.P256.Signing.PrivateKey) -> String {
    let who = NSUserName() + "@" + (Host.current().localizedName ?? ProcessInfo.processInfo.hostName)
        .replacingOccurrences(of: " ", with: "-")
    return "nod-p256 " + key.publicKey.derRepresentation.base64EncodedString() + " " + who
}

func fingerprint(_ key: SecureEnclave.P256.Signing.PrivateKey) -> String {
    let sum = SHA256.hash(data: key.publicKey.derRepresentation)
    return "SHA256:" + Data(sum).base64EncodedString().replacingOccurrences(of: "=", with: "")
}

// MARK: Commands

func enroll(label: String, force: Bool) throws {
    guard SecureEnclave.isAvailable else {
        throw Failure(code: .unavailable, message: "this Mac has no Secure Enclave")
    }
    let url = try keyURL(label)
    if FileManager.default.fileExists(atPath: url.path) && !force {
        throw Failure(code: .failure, message: "key \"\(label)\" exists; nod pubkey prints it, --force replaces it (services must enroll the new key)")
    }
    var err: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       [.privateKeyUsage, .userPresence], &err) else {
        throw Failure(code: .failure, message: "access control: \(err!.takeRetainedValue())")
    }
    let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
    let tmp = url.appendingPathExtension("tmp")
    FileManager.default.createFile(atPath: tmp.path, contents: key.dataRepresentation,
                                   attributes: [.posixPermissions: 0o600])
    _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp)
    print(publicKeyLine(key))
}

func pubkey(label: String) throws {
    print(publicKeyLine(try loadKey(label)))
}

/// A request field: present, a string, within limits, no control or
/// bidirectional-override characters (which could disguise the text).
func field(_ req: [String: Any], _ name: String, max: Int, required: Bool = true) throws -> String {
    guard let v = req[name] else {
        if required { throw Failure(code: .failure, message: "request has no \(name)") }
        return ""
    }
    guard let s = v as? String else { throw Failure(code: .failure, message: "request \(name) is not a string") }
    if required && s.trimmingCharacters(in: .whitespaces).isEmpty {
        throw Failure(code: .failure, message: "request \(name) is empty")
    }
    if s.count > max { throw Failure(code: .failure, message: "request \(name) is over \(max) characters") }
    for u in s.unicodeScalars where u.properties.generalCategory == .control || u.properties.isBidiControl {
        throw Failure(code: .failure, message: "request \(name) has control characters")
    }
    return s
}

func sign(label: String) throws {
    let raw = FileHandle.standardInput.readDataToEndOfFile()
    guard raw.count <= maxRequestBytes else { throw Failure(code: .failure, message: "request is too large") }
    guard let req = try JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
        throw Failure(code: .failure, message: "request is not a JSON object")
    }
    guard (req["v"] as? Int) == 1 else { throw Failure(code: .failure, message: "request version is not 1") }
    let service = try field(req, "service", max: maxField)
    let requester = try field(req, "requester", max: maxField)
    let action = try field(req, "action", max: maxField)
    let subject = try field(req, "subject", max: maxField)
    let reason = try field(req, "reason", max: maxReason, required: false)
    _ = try field(req, "id", max: 64)
    _ = try field(req, "digest", max: 128)
    let expiresText = try field(req, "expires", max: 64)
    guard let expires = ISO8601DateFormatter().date(from: expiresText) else {
        throw Failure(code: .failure, message: "request expires is not an RFC 3339 time")
    }
    let left = expires.timeIntervalSinceNow
    guard left > 0 else { throw Failure(code: .declined, message: "request has expired") }
    guard left <= maxLifetime + 5 else { throw Failure(code: .failure, message: "request lives too long") }

    // The sheet reads: "nod" is trying to <text>. (macOS adds the period.)
    // The service, action and subject come from the service; the reason is
    // the requester's own words, quoted after their name.
    var text = "get your approval for \(service):\n\n"
        + "\(action) \(subject)\n\n"
        + "Asked by \(requester)"
    if !reason.isEmpty {
        text += ": \u{201C}\(reason)\u{201D}"
    }
    let context = LAContext()
    context.localizedReason = text
    context.localizedCancelTitle = "Decline"
    // Dismiss the sheet when the request expires.
    DispatchQueue.global().asyncAfter(deadline: .now() + left) { context.invalidate() }

    let key = try loadKey(label, context: context)
    let signature: P256.Signing.ECDSASignature
    do {
        signature = try key.signature(for: raw)
    } catch {
        throw classify(error)
    }
    let approval: [String: String] = [
        "request": raw.base64EncodedString(),
        "signature": signature.derRepresentation.base64EncodedString(),
        "key": fingerprint(key),
    ]
    let out = try JSONSerialization.data(withJSONObject: approval, options: [.sortedKeys])
    FileHandle.standardOutput.write(out)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

/// classify maps an authentication error to an exit code: the person
/// declining (or the sheet expiring) is not a failure of nod.
func classify(_ error: Error) -> Failure {
    var e: NSError? = error as NSError
    while let cur = e {
        if cur.domain == LAErrorDomain, let code = LAError.Code(rawValue: cur.code) {
            switch code {
            case .userCancel, .appCancel, .systemCancel, .invalidContext, .userFallback, .notInteractive:
                return Failure(code: .declined, message: "declined")
            case .biometryNotAvailable, .passcodeNotSet, .biometryNotEnrolled, .biometryLockout:
                return Failure(code: .unavailable, message: cur.localizedDescription)
            default:
                break
            }
        }
        e = cur.userInfo[NSUnderlyingErrorKey] as? NSError
    }
    let ns = error as NSError
    if ns.domain == NSOSStatusErrorDomain && ns.code == Int(errSecUserCanceled) {
        return Failure(code: .declined, message: "declined")
    }
    return Failure(code: .failure, message: "signing failed: \(error.localizedDescription)")
}

// MARK: Main

let usage = """
usage: nod COMMAND [--label L]

Approve what an agent asks to do with Touch ID or your login password.

  enroll [--force]  Create your approval key in this Mac's Secure Enclave
                    and print its public key. Then register it with each
                    service that asks you, e.g. istando approver enroll.
                    --force replaces an existing key (re-register it).
  pubkey            Print the public key again.
  sign              Read a request (JSON) on stdin, show the approval
                    sheet, and print the signed approval. Services run
                    this; you don't need to.
  help              Show this.

--label picks one of several keys (default "default").
Keys live in ~/Library/Application Support/nod/.
"""

var args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else {
    FileHandle.standardError.write(Data(usage.utf8))
    exit(Code.usage.rawValue)
}
args.removeFirst()
if ["help", "-h", "--help"].contains(command) {
    print(usage, terminator: "")
    exit(Code.ok.rawValue)
}
var label = "default"
var force = false
while !args.isEmpty {
    let a = args.removeFirst()
    switch a {
    case "--label" where !args.isEmpty: label = args.removeFirst()
    case "--force": force = true
    default: fail(.usage, "unknown argument \(a)")
    }
}
do {
    switch command {
    case "enroll": try enroll(label: label, force: force)
    case "pubkey": try pubkey(label: label)
    case "sign": try sign(label: label)
    default: fail(.usage, "unknown command \(command); nod help lists them")
    }
} catch let f as Failure {
    fail(f.code, f.message)
} catch {
    fail(.failure, error.localizedDescription)
}
