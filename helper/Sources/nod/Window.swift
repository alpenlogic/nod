// The approval window: nod's own panel, so the words are the service's
// ("istando needs your approval to ..."), not macOS's "nod is trying to".
// Touch ID runs inside it (LAAuthenticationView); "Use Password…" falls
// back to the system sheet. It opens centered on the screen with the
// pointer, above other windows.

import AppKit
@preconcurrency import LocalAuthentication
import LocalAuthenticationEmbeddedUI

/// What the person did.
enum Outcome {
    case approved(LAContext) // this context has satisfied the key's access control
    case declined
    case noAnswer // the request expired first
    case failed(Failure)
}

/// What the window shows.
struct Prompt {
    let headline: String   // "istando needs your approval to promote ..."
    let detail: String     // "Asked by build-agent: “ready for review”", or ""
    let sheetReason: String // the system sheet's text, for the password fallback
    let deadline: Date
}

@MainActor
final class ApprovalWindow: NSObject, NSWindowDelegate {
    private let prompt: Prompt
    private let access: SecAccessControl
    private var panel: NSPanel!
    private let touchContext = LAContext()
    private var passwordContext: LAContext?
    private(set) var outcome: Outcome?

    init(prompt: Prompt, access: SecAccessControl) {
        self.prompt = prompt
        self.access = access
    }

    /// Shows the window and runs until the person answers or the request
    /// expires.
    func run() -> Outcome {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        build()
        app.activate()
        panel.makeKeyAndOrderFront(nil)
        panel.orderFrontRegardless()

        Timer.scheduledTimer(withTimeInterval: max(0, prompt.deadline.timeIntervalSinceNow), repeats: false) { _ in
            MainActor.assumeIsolated { self.finish(.noAnswer) }
        }
        evaluate(touchContext, viaWindow: true)
        app.run()
        return outcome ?? .declined
    }

    // MARK: Layout

    private func build() {
        let width: CGFloat = 400
        panel = NSPanel(contentRect: NSRect(x: 0, y: 0, width: width, height: 10),
                        styleMask: [.titled, .closable, .fullSizeContentView],
                        backing: .buffered, defer: false)
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isMovableByWindowBackground = true
        panel.level = .modalPanel
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.hidesOnDeactivate = false
        panel.delegate = self
        panel.standardWindowButton(.miniaturizeButton)?.isHidden = true
        panel.standardWindowButton(.zoomButton)?.isHidden = true

        let headline = label(prompt.headline, font: .boldSystemFont(ofSize: 14), color: .labelColor)
        var rows: [NSView] = [headline]
        if !prompt.detail.isEmpty {
            rows.append(label(prompt.detail, font: .systemFont(ofSize: 13), color: .secondaryLabelColor))
        }

        let touch = LAAuthenticationView(context: touchContext, controlSize: .regular)
        let hint = label("Touch ID to approve", font: .systemFont(ofSize: 12), color: .secondaryLabelColor)
        let touchRow = NSStackView(views: [touch, hint])
        touchRow.orientation = .horizontal
        touchRow.spacing = 10
        rows.append(touchRow)

        let password = NSButton(title: "Use Password…", target: self, action: #selector(usePassword))
        let decline = NSButton(title: "Decline", target: self, action: #selector(declineClicked))
        decline.keyEquivalent = "\u{1b}" // Esc
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let buttons = NSStackView(views: [password, spacer, decline])
        buttons.orientation = .horizontal
        rows.append(buttons)

        let stack = NSStackView(views: rows)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        stack.edgeInsets = NSEdgeInsets(top: 28, left: 22, bottom: 18, right: 22)
        stack.translatesAutoresizingMaskIntoConstraints = false
        buttons.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -44).isActive = true

        let content = NSView()
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            stack.topAnchor.constraint(equalTo: content.topAnchor),
            stack.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            content.widthAnchor.constraint(equalToConstant: width),
        ])
        panel.contentView = content
        panel.layoutIfNeeded()
        panel.setContentSize(content.fittingSize)
        place()
    }

    private func label(_ text: String, font: NSFont, color: NSColor) -> NSTextField {
        let l = NSTextField(wrappingLabelWithString: text)
        l.font = font
        l.textColor = color
        l.isSelectable = false
        l.preferredMaxLayoutWidth = 356
        return l
    }

    /// Centers the panel on the screen with the pointer, a little above the
    /// middle, where an alert would go.
    private func place() {
        let mouse = NSEvent.mouseLocation
        let screen = NSScreen.screens.first { NSMouseInRect(mouse, $0.frame, false) } ?? NSScreen.main
        guard let area = screen?.visibleFrame else { panel.center(); return }
        let size = panel.frame.size
        panel.setFrameOrigin(NSPoint(x: area.midX - size.width / 2,
                                     y: area.midY - size.height / 2 + area.height / 6))
    }

    // MARK: Authentication

    private func evaluate(_ context: LAContext, viaWindow: Bool) {
        let access = self.access
        let reason = prompt.sheetReason
        Task { @MainActor in
            do {
                try await context.evaluateAccessControl(access, operation: .useKeySign, localizedReason: reason)
                self.finish(.approved(context))
            } catch {
                guard self.outcome == nil else { return }
                if viaWindow, self.passwordContext == nil, Self.needsPassword(error) {
                    // No Touch ID here (lid closed, locked out): the system
                    // sheet takes the password instead.
                    self.usePassword()
                    return
                }
                if !viaWindow || self.passwordContext == nil {
                    self.finish(.failed(classify(error)))
                }
            }
        }
    }

    private static func needsPassword(_ error: Error) -> Bool {
        let ns = error as NSError
        guard ns.domain == LAErrorDomain, let code = LAError.Code(rawValue: ns.code) else { return false }
        return [.biometryNotAvailable, .biometryNotEnrolled, .biometryLockout, .userFallback].contains(code)
    }

    @objc private func usePassword() {
        guard outcome == nil, passwordContext == nil else { return }
        let context = LAContext()
        context.localizedCancelTitle = "Decline"
        passwordContext = context
        touchContext.invalidate()
        panel.orderOut(nil)
        evaluate(context, viaWindow: false)
    }

    @objc private func declineClicked() { finish(.declined) }

    func windowWillClose(_ notification: Notification) { finish(.declined) }

    private func finish(_ result: Outcome) {
        guard outcome == nil else { return }
        outcome = result
        if case .approved = result {} else {
            touchContext.invalidate()
            passwordContext?.invalidate()
        }
        panel.delegate = nil
        panel.orderOut(nil)
        let app = NSApplication.shared
        app.stop(nil)
        // stop takes effect after the next event.
        if let e = NSEvent.otherEvent(with: .applicationDefined, location: .zero, modifierFlags: [],
                                      timestamp: 0, windowNumber: 0, context: nil, subtype: 0, data1: 0, data2: 0) {
            app.postEvent(e, atStart: false)
        }
    }
}
