// Locked secrets: a small secret (an unseal key, a passphrase) kept behind
// the same Touch ID gate as approvals.
//
//   nod lock NAME --service S --action A [--force] < secret
//   nod unlock NAME [--reason R] > secret
//
// lock encrypts the secret to a new Secure Enclave P-256 key of its own
// (ECIES: an ephemeral P-256 key agreement, HKDF-SHA256, AES-GCM) and
// writes ~/Library/Application Support/nod/locked/NAME. The window's words
// are fixed at lock time: "S needs your approval to A". Whoever runs
// unlock may add only a reason, shown quoted. The name, service and action
// are the cipher's associated data, so a file edited to say something else
// does not decrypt, even after an approval.
//
// unlock shows the window and, once the person approves, writes the
// secret to stdout and nowhere else. Exit codes as for sign: 0 unlocked,
// 2 declined, 4 no answer, 3 unable to ask, 1 any other error.
//
// Each locked secret has its own key, so approving one can never unlock
// another or sign an approval. The file only works with this Mac's Secure
// Enclave: keep the secret somewhere else as well.

import CryptoKit
import Foundation
@preconcurrency import LocalAuthentication
import Security

let maxSecretBytes = 4096
let unlockLifetime: TimeInterval = 120

struct LockedFile: Codable {
    var v: Int
    var name: String
    var service: String
    var action: String
    var key: String       // base64 Secure Enclave key handle (dataRepresentation)
    var ephemeral: String // base64 X9.63 ephemeral public key
    var sealed: String    // base64 AES-GCM combined (nonce, ciphertext, tag)
}

func lockedURL(_ name: String) throws -> URL {
    guard name.range(of: "^[a-z0-9][a-z0-9-]{0,63}$", options: .regularExpression) != nil else {
        throw Failure(code: .usage, message: "name must be lowercase letters, digits and dashes")
    }
    let dir = try keyURL("default").deletingLastPathComponent().appendingPathComponent("locked", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    return dir.appendingPathComponent(name)
}

/// The associated data binding the ciphertext to what the window says.
func lockedAAD(_ f: LockedFile) -> Data {
    Data("nod-locked v1\n\(f.name)\n\(f.service)\n\(f.action)".utf8)
}

func lockedKey(_ shared: SharedSecret, _ f: LockedFile, ephemeral: Data) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeral, sharedInfo: lockedAAD(f), outputByteCount: 32)
}

func userPresence() throws -> SecAccessControl {
    var err: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       [.privateKeyUsage, .userPresence], &err) else {
        throw Failure(code: .failure, message: "access control: \(err!.takeRetainedValue())")
    }
    return access
}

/// Checks text that the window will show, as for request fields.
func windowText(_ name: String, _ s: String, max: Int) throws -> String {
    try field([name: s], name, max: max)
}

func lock(name: String, service: String, action: String, force: Bool) throws {
    guard SecureEnclave.isAvailable else {
        throw Failure(code: .unavailable, message: "this Mac has no Secure Enclave")
    }
    let url = try lockedURL(name)
    if FileManager.default.fileExists(atPath: url.path) && !force {
        throw Failure(code: .failure, message: "\"\(name)\" is already locked; --force replaces it")
    }
    var f = LockedFile(v: 1, name: name,
                       service: try windowText("service", service, max: maxField),
                       action: try windowText("action", action, max: maxField),
                       key: "", ephemeral: "", sealed: "")
    var secret = FileHandle.standardInput.readData(ofLength: maxSecretBytes + 1)
    defer { secret.resetBytes(in: 0..<secret.count) }
    guard !secret.isEmpty else { throw Failure(code: .failure, message: "no secret on stdin") }
    guard secret.count <= maxSecretBytes else {
        throw Failure(code: .failure, message: "secret is over \(maxSecretBytes) bytes")
    }

    let se = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: try userPresence())
    let eph = P256.KeyAgreement.PrivateKey()
    let ephPub = eph.publicKey.x963Representation
    let shared = try eph.sharedSecretFromKeyAgreement(with: se.publicKey)
    let box = try AES.GCM.seal(secret, using: lockedKey(shared, f, ephemeral: ephPub), authenticating: lockedAAD(f))
    f.key = se.dataRepresentation.base64EncodedString()
    f.ephemeral = ephPub.base64EncodedString()
    f.sealed = box.combined!.base64EncodedString()

    let tmp = url.appendingPathExtension("tmp")
    let data = try JSONEncoder().encode(f)
    guard FileManager.default.createFile(atPath: tmp.path, contents: data, attributes: [.posixPermissions: 0o600]) else {
        throw Failure(code: .failure, message: "can't write \(tmp.path)")
    }
    if FileManager.default.fileExists(atPath: url.path) {
        _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp)
    } else {
        try FileManager.default.moveItem(at: tmp, to: url)
    }
    print("locked \(name): unlocking it asks \"\(f.service) needs your approval to \(f.action)\"")
}

@MainActor
func unlock(name: String, reason: String) throws {
    let url = try lockedURL(name)
    guard let data = try? Data(contentsOf: url) else {
        throw Failure(code: .unavailable, message: "nothing locked as \"\(name)\"")
    }
    guard let f = try? JSONDecoder().decode(LockedFile.self, from: data), f.v == 1, f.name == name,
          let keyData = Data(base64Encoded: f.key), let ephPub = Data(base64Encoded: f.ephemeral),
          let sealed = Data(base64Encoded: f.sealed) else {
        throw Failure(code: .failure, message: "\(url.path) is not a locked secret")
    }
    // The file's words are checked like a request's before they are shown.
    let service = try windowText("service", f.service, max: maxField)
    let action = try windowText("action", f.action, max: maxField)
    let why = reason.isEmpty ? "" : try windowText("reason", reason, max: maxReason)
    // Fail before showing anything if the key can't be used here.
    do {
        _ = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData)
    } catch {
        throw Failure(code: .unavailable, message: "\"\(name)\" can't be unlocked on this Mac: \(error.localizedDescription)")
    }

    var detail = "Unlocks the secret \u{201C}\(name)\u{201D}."
    if !why.isEmpty { detail += " Reason given: \u{201C}\(why)\u{201D}" }
    let prompt = Prompt(headline: "\(service) needs your approval to \(action)",
                        detail: detail,
                        sheetReason: "confirm that \(service) may \(action)",
                        deadline: Date().addingTimeInterval(unlockLifetime))
    let context: LAContext
    switch ApprovalWindow(prompt: prompt, access: try userPresence(), operation: .useKeyKeyExchange).run() {
    case .approved(let c): context = c
    case .declined: throw Failure(code: .declined, message: "declined")
    case .noAnswer: throw Failure(code: .noAnswer, message: "no answer")
    case .failed(let failure): throw failure
    }
    context.interactionNotAllowed = true
    var secret: Data
    do {
        let se = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData, authenticationContext: context)
        let shared = try se.sharedSecretFromKeyAgreement(with: try P256.KeyAgreement.PublicKey(x963Representation: ephPub))
        secret = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: lockedKey(shared, f, ephemeral: ephPub),
                                  authenticating: lockedAAD(f))
    } catch {
        throw Failure(code: .failure, message: "\"\(name)\" did not decrypt (changed since it was locked?)")
    }
    defer { secret.resetBytes(in: 0..<secret.count) }
    FileHandle.standardOutput.write(secret)
}
