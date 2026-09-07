// The picker. Summoned by a keystroke, dismissed before it inserts anything.
//
// NO SECRET EVER ENTERS QML. omarchy-shell is long-lived and unsandboxed, so
// anything placed in a QML property stays in its heap for the whole session.
// This file handles entry paths and nothing else — `ctl fill` and `ctl insert`
// tell the agent to type, and no value ever comes back across that boundary.
//
// Chrome follows the shipped overlays rather than inventing anything: the
// filter is plain Text driven by Keys.onPressed (a TextInput would be a second
// focus consumer, which is why the first version needed forceActiveFocus
// nudges), and header, rows, empty state and footer come from
// plugins/clipboard/Clipboard.qml and plugins/agents/Panel.qml.

import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import QtQuick
import qs.Commons
import qs.Ui

Item {
  id: root

  property var shell: null
  property var manifest: null

  readonly property string ctlPath: String(Qt.resolvedUrl("bin/keepass-picker-ctl")).replace("file://", "")

  property bool opened: false
  property string filterText: ""
  property int selectedIndex: 0

  // "unknown" | "no-database" | "missing-database" | "locked" | "unlocked" | "engine-missing"
  property string state: "unknown"
  property string notice: ""
  property bool busy: false

  // Summoning a locked picker used to show "Locked. Press Enter to unlock." —
  // a keystroke that carried no information, because there is nothing else you
  // could want from a locked vault. The prompt now comes up on its own.
  //
  // Once per open, though: cancelling pinentry returns here with the vault
  // still locked, and re-prompting on that would be an unclosable loop.
  property bool unlockOffered: false

  property int totalMatches: 0
  property int shownMatches: 0

  // The window a paste will land in, captured when the overlay opens. A
  // layer-shell surface does not become Hyprland's active window, so this
  // stays truthful while the picker has keyboard focus — verified.
  //
  // The ADDRESS ONLY. Nothing about the window steers what a key does. An
  // earlier version varied Enter by window class — fill in a browser, password
  // in a terminal — which made the primary key unpredictable and dragged the
  // class name into the UI to explain itself. A key that means one thing is
  // worth more than a key that guesses well.
  property string targetAddress: ""

  // The window a paste will land in, in words you recognise. DISPLAY ONLY: the
  // pane states it so a wrong window is caught before Enter rather than after.
  // It steers nothing. The title, not the class -- "foot" told you nothing the
  // first time it appeared in this UI.
  property string targetTitle: ""
  property string targetApp: ""

  // How long the vault has been open, captured when the picker opens. The
  // header says it so you know the vault is live before typing a character.
  property double unlockedFor: 0

  readonly property bool ready: root.state === "unlocked"

  property color foreground: Color.menu.text
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property color faint: Qt.darker(foreground, 2.4)

  // One step of contrast off the desktop. The theme sets menu.background to the
  // SAME value as the desktop background (#121212 on evergreen), so taking the
  // token straight left the card with no body -- it read as a hole rather than
  // a surface. Tinted toward the ink, so it lifts on a dark theme and settles
  // on a light one without either being special-cased.
  property color background: Qt.tint(Color.menu.background,
                                     Qt.rgba(Color.menu.text.r, Color.menu.text.g,
                                             Color.menu.text.b, 0.045))
  property color scrim: Color.menu.scrim

  // The ring is the theme ACCENT, the way the Tailscale panel rings itself.
  //
  // Passing Color.accent to Border.surfaceSpec did nothing: its third argument
  // is only a FALLBACK, used when the theme leaves the token unset. Evergreen
  // sets menu.border to hyprland.active-border-foreground, so the ring came out
  // grey. The width still comes from the theme; only the colour is forced.
  readonly property var themeBorder:
    Border.surfaceSpec("menu", "border", Color.accent, Math.max(1, Style.space(2)))
  property var borderSpec: ({ color: Color.accent,
                              widths: root.themeBorder.widths,
                              gradient: null })

  // The theme's own selection surface -- an 8% wash of the foreground on
  // evergreen. What must NOT be used is Color.menu.selectedText, which the
  // theme sets to the accent: that is what painted the selected row's title
  // orange and doubled a signal the accent bar already carries.
  readonly property color selectedBackground: Color.menu.selectedBackground
  // Kept for the empty state's glyph, which is the one place an accent-tinted
  // mark is the subject rather than the chrome.
  readonly property color selectedText: Color.menu.selectedText
  readonly property int cornerRadius: Style.cornerRadius
  property string fontFamily: Style.font.menuFamily
  property int contentMargin: Style.spacing.panelPadding
  property int contentSpacing: Style.spacing.md
  property int headerHeight: Style.font.heading + Style.spacing.xxl * 2
  // Two full-width lines per row: title, then username beneath it at the same
  // x. Both get the whole row, which is what long titles and long usernames
  // actually need; the alignment holds without a fixed username column.
  // Measured, not calculated.
  //
  // The previous version set lineHeight: 1.35 on both lines. A monospace face
  // already spaces its lines at roughly 1.3x, so that multiplied an existing
  // leading rather than replacing it: each single-line Text grew a box half
  // again as tall as its glyphs, the extra space landed between the two lines,
  // and the row came out with a 10px gap and a band shorter than its own
  // content. The line boxes now touch at their natural size, and the row is
  // exactly as tall as what it holds.
  property int rowHeight: titleMetrics.implicitHeight + userMetrics.implicitHeight
                          + Style.spacing.xs * 2
  // Narrow enough that the pane sits directly beside the list. At 1080 the
  // list stretched to meet a fixed pane and the space in between was dead.
  property int cardWidth: Math.min(Style.space(820), panel.width - Style.gapsOut * 2)
  readonly property int paneWidth: Style.space(250)
  // Two vertical rules for the whole card, and everything sits on one of them.
  //
  // markerInset -> the search magnifier and every row's bullet
  // textInset   -> the query, every title and every username
  //
  // The header used to set its own margins, so the magnifier and the bullets
  // were ten pixels apart in one direction and the placeholder and the titles
  // ten in the other. Both columns are now the same numbers in both places.
  readonly property int barWidth: Style.space(2)
  // The bar's own gutter. Flush on the band's left edge, then this, then the
  // marker: with only 4px between them the bar read as part of the glyph.
  readonly property int markerInset: root.barWidth + Style.spacing.xl
  readonly property int glyphColumn: Style.space(14)
  readonly property int glyphGap: Style.spacing.xl
  readonly property int textInset: root.markerInset + root.glyphColumn + root.glyphGap

  // Height follows the content. A fixed card left seven results floating in a
  // sea of empty space, which is the most visible flaw in the picker as
  // shipped. Clamped so a 60-row list still fits the screen and a one-row list
  // still looks like a card rather than a strip.
  // Measured off the two blocks that actually exist, so it cannot drift from
  // what the results area computes for itself -- which it no longer does. It
  // takes exactly what is between them.
  readonly property int chromeHeight: topBlock.height + bottomBlock.height
    + root.contentSpacing * 2
    + card.contentTopInset + card.contentBottomInset
  // The pane has a floor of its own: a one-row result must not shrink the card
  // until the details it is showing no longer fit beside it.
  // Ten. Seven made the card a 2:1 strip; ten brings it near 5:3, which sits
  // better on the screen, and the extra rows are still one glance rather than
  // a scan. Past that, another keystroke beats a longer list.
  readonly property int visibleRows: 10
  readonly property int listHeight: Math.max(
    root.rowHeight * 2,
    Math.min(resultModel.count, root.visibleRows) * root.rowHeight)
  property int cardHeight: Math.min(
    Style.space(640),
    panel.height - Style.gapsOut * 2,
    Math.max(Style.space(150), root.chromeHeight + root.listHeight))

  function open(payloadJson) {
    // FIRST, before the layer surface exists. A layer-shell surface does not
    // become Hyprland's active window, so asking afterwards has been correct
    // in practice -- but "correct in practice" is not a thing to rely on for
    // the one value that decides where a password lands.
    targetProc.running = false
    targetProc.running = true
    root.opened = true
    root.filterText = ""
    root.selectedIndex = 0
    root.notice = ""
    root.unlockOffered = false
    root.totalMatches = 0
    root.shownMatches = 0
    resultModel.clear()
    root.refresh()
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function close() { root.opened = false }

  function dismiss() {
    root.opened = false
    resultModel.clear()
    root.filterText = ""
    if (root.shell && typeof root.shell.hide === "function")
      root.shell.hide((root.manifest && root.manifest.id) || "mkelk.keepass-picker")
  }

  function toggle() {
    // While pinentry is up this surface is deliberately hidden. Summoning it
    // again would put it back in front of the prompt and steal the keyboard a
    // second time.
    if (root.busy) return
    if (root.opened) root.dismiss()
    else root.open("{}")
  }

  function refresh() {
    statusProc.running = false
    statusProc.running = true
  }

  function applyStatus(raw) {
    var reply = {}
    try { reply = JSON.parse(raw) } catch (e) { reply = {} }
    if (reply.state) root.state = String(reply.state)
    else if (reply.error) { root.state = "unknown"; root.notice = String(reply.error) }
    root.unlockedFor = Number(reply.unlocked_for || 0)
    // An unlocked vault with nothing typed should show your most-used, not a
    // blank pane — that is what makes the common case need no typing at all.
    if (root.state === "unlocked") root.runSearch()
    else if (root.state === "locked" && root.opened && !root.busy && !root.unlockOffered) {
      root.unlockOffered = true
      root.unlock()
    }
  }

  function applyTarget(raw) {
    var reply = {}
    try { reply = JSON.parse(raw) } catch (e) { reply = {} }
    var w = reply.window || {}
    root.targetAddress = w.address ? String(w.address) : ""
    root.targetTitle = String(w.title || "")
    root.targetApp = String(w.app || "")
  }

  function setFilter(next) {
    root.filterText = next
    root.selectedIndex = 0
    if (root.ready) searchDebounce.restart()
  }

  function runSearch() {
    if (!root.ready) { resultModel.clear(); return }
    searchProc.running = false
    searchProc.command = [root.ctlPath, "search", root.filterText]
    searchProc.running = true
  }

  function applyResults(raw) {
    var reply = {}
    try { reply = JSON.parse(raw) } catch (e) { reply = {} }

    if (reply.state && reply.state !== "unlocked") {
      root.state = String(reply.state)
      resultModel.clear()
      return
    }

    resultModel.clear()
    var entries = reply.entries || []
    for (var i = 0; i < entries.length; i++) {
      var row = entries[i]
      resultModel.append({
        entryPath: String(row.path),
        title: String(row.title),
        group: String(row.group),
        // Username and URL are shown because a title alone often cannot tell
        // two entries apart — a vault can hold three entries titled with the
        // same person's name that differ only by the phone number in their
        // username. Neither is a secret. NOTES ARE NEVER FETCHED OR SHOWN: they routinely hold PINs,
        // PUKs and recovery codes.
        username: String(row.username || ""),
        url: String(row.url || ""),
        // Which field the search actually hit, so a lookalike URL cannot pass
        // for the real entry.
        why: String(row.why || "title"),
        // Epoch seconds, or 0 for an entry you have not used yet.
        lastUsed: Number(row.last_used || 0)
      })
    }
    root.totalMatches = reply.total || resultModel.count
    root.shownMatches = resultModel.count
    root.selectedIndex = resultModel.count > 0 ? 0 : -1
    root.notice = ""
  }

  // Vault titles carry leading spaces and dashes -- "  - Backup codes", " router".
  // Rendered verbatim they ragged the left edge of the list, which was the
  // single most visible flaw. Display only: the entry path is untouched.
  function cleanTitle(text) {
    var trimmed = String(text).replace(/^[\s\-\u2013\u2014·•]+/, "")
    return trimmed || String(text)
  }

  function escapeHtml(text) {
    return String(text).replace(/&/g, "&amp;")
                       .replace(/</g, "&lt;")
                       .replace(/>/g, "&gt;")
  }

  // Only the characters you actually typed go accent. Nothing else explained
  // why a short title with your term in the middle outranks a long one that
  // starts with it.
  //
  // Escaped on the way in: a title is vault content, and StyledText would
  // otherwise treat an angle bracket in it as markup.
  function highlight(text, term) {
    var plain = String(text)
    if (!term) return root.escapeHtml(plain)
    var at = plain.toLowerCase().indexOf(String(term).toLowerCase())
    if (at < 0) return root.escapeHtml(plain)
    return root.escapeHtml(plain.slice(0, at))
         + "<font color=\"" + root.keyColor + "\">"
         + root.escapeHtml(plain.slice(at, at + term.length))
         + "</font>"
         + root.escapeHtml(plain.slice(at + term.length))
  }

  // What the pane prints, in three groups: what it is, where it is going, and
  // what it will type. The rules between them are what stop the pane reading
  // as one undifferentiated stack.
  readonly property var paneIdentity: {
    var r = root.currentRow
    return r ? [{ label: "TITLE", shown: root.cleanTitle(r.title) }] : []
  }

  readonly property var paneTarget: {
    if (!root.currentRow) return []
    // One line. Hyprland gives a window's class and title and nothing else --
    // there is no URL to show, so the page title is the nearest thing to a
    // host, and the app is the part that matters. Elided rather than wrapped
    // so a long page title cannot break mid-word or grow the pane.
    return [{ label: "WILL TYPE INTO", shown: root.targetLabel, oneLine: true }]
  }

  // Always the same three, in the same order, whether or not the entry has
  // them. A field that vanishes moves every label below it, and then the eye
  // has to find each one again on every keystroke. An em dash says "this entry
  // has none" in the same place the value would have been.
  readonly property var paneCredential: {
    var r = root.currentRow
    if (!r) return []
    return [{ label: "USERNAME", shown: String(r.username) || "—" },
            { label: "URL",      shown: String(r.url) || "—" },
            { label: "LAST USED", shown: root.relativeTime(r.lastUsed) }]
  }

  // "unlocked 4m", the way the shipped plugins state a live connection.
  function shortAge(seconds) {
    var mins = Math.floor(Number(seconds) / 60)
    if (mins < 1) return "unlocked just now"
    if (mins < 60) return "unlocked " + mins + "m"
    return "unlocked " + Math.floor(mins / 60) + "h"
  }

  // "chromium", "org.gnome.Nautilus" -> "Chromium", "Nautilus". The class is
  // never the whole label and never explains a key -- it only names the app
  // the pane is about to type into.
  //
  // A Chromium-family web app is the one case where the class DOES carry a
  // host: "chrome-mail.google.com__mail_u_0_-Profile_1". Taking the last
  // dotted segment of that gave "Com__mail_u_0_-Profile_1". The host is both
  // readable and exactly what the field wants to say, so it wins.
  function prettyApp(name) {
    var raw = String(name)
    var webApp = raw.match(/^[a-z]+-([a-z0-9][a-z0-9.-]*)__/i)
    if (webApp) return webApp[1]
    var bare = raw.split(".").pop()
    return bare ? bare.charAt(0).toUpperCase() + bare.slice(1) : ""
  }

  // The app, and only the app.
  //
  // The design asks for "Chromium — adwords.google.com". That cannot be built:
  // `hyprctl activewindow` returns a window's class and title and NOTHING
  // else -- there is no URL anywhere in it, and a browser's title is its page
  // name ("Omarchy password manager plugin"), not its host. Reading a real
  // host would take a browser extension or AT-SPI, and this plugin takes
  // neither.
  //
  // So the field says the one thing it can say truthfully and completely: the
  // app that will receive the keystrokes. That is also the distinction the
  // field exists for -- browser or terminal -- and it never truncates, which
  // the page title did.
  readonly property string targetLabel: {
    var app = root.prettyApp(root.targetApp)
    if (app) return app
    return root.targetTitle || "no window focused"
  }

  // The row the pane describes. A binding rather than a stored copy, so it
  // follows the cursor without anything having to remember to update it.
  readonly property var currentRow:
    (root.selectedIndex >= 0 && root.selectedIndex < resultModel.count)
      ? resultModel.get(root.selectedIndex) : null

  // "3 days ago". Coarse on purpose: the pane is settling which of three
  // identically named entries is the live one, and an exact timestamp is more
  // digits than that question needs.
  function relativeTime(epochSeconds) {
    if (!epochSeconds) return "never"
    var secs = Math.max(0, Date.now() / 1000 - epochSeconds)
    if (secs < 90) return "just now"
    var mins = Math.round(secs / 60)
    if (mins < 60) return mins + (mins === 1 ? " minute ago" : " minutes ago")
    var hours = Math.round(mins / 60)
    if (hours < 24) return hours + (hours === 1 ? " hour ago" : " hours ago")
    var days = Math.round(hours / 24)
    if (days < 31) return days + (days === 1 ? " day ago" : " days ago")
    var months = Math.round(days / 30)
    if (months < 18) return months + (months === 1 ? " month ago" : " months ago")
    return Math.round(days / 365) + " years ago"
  }

  // Only http and https. The URL comes out of the vault, and xdg-open will
  // cheerfully hand a file:// or a custom scheme to whatever claims it.
  function openUrl() {
    var row = root.currentRow
    if (!row || !row.url) return
    var url = String(row.url)
    if (!/^https?:\/\//i.test(url)) {
      if (/^[a-z][a-z0-9+.-]*:/i.test(url)) return   // some other scheme: no
      url = "https://" + url
    }
    root.dismiss()
    Quickshell.execDetached(["xdg-open", url])
  }

  // Hosts are what you recognise; the scheme and path are noise at this size.
  function shortUrl(url) {
    var text = String(url).replace(/^[a-z]+:\/\//i, "").replace(/^www\./i, "")
    var slash = text.indexOf("/")
    if (slash > 0) text = text.substring(0, slash)
    return text
  }

  function select(delta) {
    if (resultModel.count === 0) return
    root.selectedIndex = (root.selectedIndex + delta + resultModel.count) % resultModel.count
    resultList.positionViewAtIndex(root.selectedIndex, ListView.Contain)
  }

  // Dismiss FIRST, then type. That order is what returns keyboard focus to the
  // window the credential is meant for. The captured address travels with the
  // request so the agent can refuse if focus moved in between.
  function deliver(mode, field) {
    if (root.selectedIndex < 0 || root.selectedIndex >= resultModel.count) return
    var entryPath = resultModel.get(root.selectedIndex).entryPath
    var target = root.targetAddress
    root.dismiss()
    if (mode === "fill")
      Quickshell.execDetached([root.ctlPath, "fill", entryPath, target])
    else
      Quickshell.execDetached([root.ctlPath, "insert", entryPath, field || "Password", target])
  }

  // Step aside for pinentry.
  //
  // This surface is layer-shell on the Overlay layer with EXCLUSIVE keyboard
  // focus, so a normal toplevel — which pinentry is — renders behind it and
  // receives no keystrokes. Left as it was, the unlock prompt was visible but
  // untypeable.
  //
  // omarchy.polkit and omarchy.lock avoid this by drawing their own password
  // field in QML. That is not open to us: the master password would then live
  // in the long-lived, unsandboxed shell heap, which is the one thing this
  // plugin is built to avoid. So the overlay hides itself instead, and comes
  // back when the agent is done.
  //
  // `opened = false` rather than dismiss(): it drops the layer surface and the
  // focus grab, but leaves the component loaded so unlockProc's callback still
  // has somewhere to land.
  function unlock() {
    root.busy = true
    root.opened = false
    unlockProc.running = false
    unlockProc.running = true
  }

  function reopenAfterUnlock() {
    root.busy = false
    root.opened = true
    Qt.callLater(function() { keyCatcher.forceActiveFocus() })
  }

  function configure() {
    root.dismiss()
    Quickshell.execDetached([root.ctlPath, "configure"])
  }

  // Enter means "do the obvious next thing". Before the vault is open that is
  // choosing a database or unlocking; after it, it is the password — always,
  // in every window.
  function activate() {
    if (root.state === "no-database" || root.state === "missing-database") root.configure()
    else if (root.state === "locked") root.unlock()
    else if (root.ready) root.deliver("insert", "Password")
  }

  // Footer text is StyledText so the key names can carry the accent colour.
  // Without that the footer was caption-sized dim text sitting under a row of
  // caption-sized dim text, and read as one more entry rather than as chrome.
  readonly property string keyColor: Color.accent

  function key(name) {
    return "<font color=\"" + root.keyColor + "\">" + name + "</font>"
  }

  // One line, the same in every window, every time.
  //
  // Enter delivers; the modifier picks the field. That is the whole rule, and
  // it is why there is nothing here about which window you are in: a footer
  // that changes is a footer you have to read, and a key that changes is one
  // you have to think about before pressing.
  readonly property var footerHints: {
    if (!root.ready || resultModel.count === 0) return []
    return [{ name: "Enter",      what: "password" },
            { name: "Shift+Enter", what: "username" },
            { name: "Ctrl+Enter",  what: "both" },
            { name: "Ctrl+L",      what: "lock" }]
  }

  // Never drawn. They exist so rowHeight is the height of a real title over a
  // real username in the real font, which is what lets the list be sized to a
  // whole number of rows.
  Text {
    id: titleMetrics
    visible: false
    text: "Ag"
    font.family: root.fontFamily
    font.pixelSize: Style.font.body
  }

  Text {
    id: userMetrics
    visible: false
    text: "Ag"
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
  }

  ListModel { id: resultModel }

  Timer {
    id: searchDebounce
    interval: 70
    onTriggered: root.runSearch()
  }

  Process {
    id: statusProc
    command: [root.ctlPath, "status"]
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: root.applyStatus(text) }
  }

  Process {
    id: targetProc
    command: [root.ctlPath, "target"]
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: root.applyTarget(text) }
  }

  Process {
    id: searchProc
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: root.applyResults(text) }
  }

  Process {
    id: lockProc
    command: [root.ctlPath, "lock"]
  }

  Process {
    id: unlockProc
    command: [root.ctlPath, "unlock"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var reply = {}
        try { reply = JSON.parse(text) } catch (e) { reply = {} }
        if (reply.ok) {
          root.state = "unlocked"
          root.notice = ""
          root.reopenAfterUnlock()
          root.runSearch()
        } else {
          // Cancelling pinentry lands here too, which is why this reopens
          // rather than staying invisible: a keystroke that appears to do
          // nothing is worse than an error you can read.
          root.notice = reply.error ? String(reply.error) : "Could not unlock"
          root.reopenAfterUnlock()
          root.refresh()
        }
      }
    }
  }

  PanelWindow {
    id: panel
    visible: root.opened
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    WlrLayershell.namespace: "keepass-picker"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.Exclusive
    exclusionMode: ExclusionMode.Ignore

    Rectangle { anchors.fill: parent; color: root.scrim }
    MouseArea { anchors.fill: parent; onClicked: root.dismiss() }

    BorderSurface {
      id: card
      width: root.cardWidth
      height: root.cardHeight
      radius: root.cornerRadius
      anchors.centerIn: parent
      color: root.background
      borderSpec: root.borderSpec
      padding: root.contentMargin

      MouseArea { anchors.fill: parent; onClicked: {} }

      Item {
        id: keyCatcher
        anchors.fill: parent
        focus: true

        Keys.priority: Keys.BeforeItem
        Keys.onPressed: function(event) {
          if (event.key === Qt.Key_Escape) {
            if (root.filterText) root.setFilter("")
            else root.dismiss()
            event.accepted = true
          } else if (event.key === Qt.Key_Down) {
            root.select(1); event.accepted = true
          } else if (event.key === Qt.Key_Up) {
            root.select(-1); event.accepted = true
          } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
            // Enter delivers; the modifier picks the field. One rule, and the
            // same rule in every window.
            if (event.modifiers & Qt.ControlModifier) root.deliver("fill")
            else if (event.modifiers & Qt.ShiftModifier) root.deliver("insert", "UserName")
            else root.activate()
            event.accepted = true
          } else if (event.key === Qt.Key_Tab || event.key === Qt.Key_Backtab) {
            // What a picker normally does with Tab. It used to paste the
            // username, which is an arbitrary meaning for a key that means
            // "next" everywhere else.
            root.select((event.modifiers & Qt.ShiftModifier) ? -1 : 1)
            event.accepted = true
          } else if (event.key === Qt.Key_U && (event.modifiers & Qt.ControlModifier)) {
            root.openUrl()
            event.accepted = true
          } else if (event.key === Qt.Key_L && (event.modifiers & Qt.ControlModifier)) {
            lockProc.running = true
            root.dismiss()
            event.accepted = true
          } else if (event.key === Qt.Key_Backspace) {
            if (root.filterText) root.setFilter(root.filterText.slice(0, -1))
            event.accepted = true
          } else if (event.text && event.text.length === 1
                     && event.text.charCodeAt(0) >= 32 && event.text.charCodeAt(0) !== 127) {
            root.setFilter(root.filterText + event.text)
            event.accepted = true
          }
        }

        // Three blocks, not one Column.
        //
        // A Column made the results area compute its own height by subtracting
        // everything above and below it, and that sum disagreed with the one
        // cardHeight used -- by about a row and a half, which is where the
        // empty band between the last row and the footer rule came from. The
        // header sits at the top, the footer at the bottom, and the list takes
        // exactly what is between them.
        Item {
          id: content
          anchors.fill: parent
          anchors.topMargin: card.contentTopInset
          anchors.rightMargin: card.contentRightInset
          anchors.bottomMargin: card.contentBottomInset
          anchors.leftMargin: card.contentLeftInset

        Column {
          id: topBlock
          anchors.top: parent.top
          anchors.left: parent.left
          anchors.right: parent.right
          spacing: root.contentSpacing

          // Header: the filter, or its placeholder. Plain Text, per the
          // shipped overlays — the key catcher above owns the keyboard.
          Rectangle {
            width: parent.width
            height: root.headerHeight
            color: "transparent"

            Text {
              id: searchGlyph
              anchors.left: parent.left
              anchors.leftMargin: root.markerInset
              anchors.verticalCenter: parent.verticalCenter
              width: root.glyphColumn
              horizontalAlignment: Text.AlignHCenter
              text: "󰍉"
              color: root.foreground
              opacity: 0.45
              font.family: root.fontFamily
              font.pixelSize: Style.font.heading
            }

            Text {
              textFormat: Text.PlainText
              anchors.left: searchGlyph.right
              anchors.leftMargin: root.glyphGap
              anchors.right: countLabel.left
              anchors.rightMargin: Style.spacing.md
              anchors.verticalCenter: parent.verticalCenter
              text: root.filterText || (root.ready ? "Search the vault…" : "KeePass")
              color: root.foreground
              opacity: root.filterText ? 1 : 0.58
              font.family: root.fontFamily
              font.pixelSize: Style.font.heading
              // One line, always. A long placeholder in a narrow card would
              // otherwise take a second one and push the list down.
              maximumLineCount: 1
              elide: Text.ElideRight
            }

            // How many matched, where you are looking rather than buried in
            // the footer.
            Text {
              id: countLabel
              textFormat: Text.PlainText
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter
              visible: root.ready && resultModel.count > 0
              text: {
                var counted = root.shownMatches + " / " + root.totalMatches
                return root.ready ? counted + "  ·  " + root.shortAge(root.unlockedFor)
                                  : counted
              }
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }
          }

          // A rule under the search row, spanning both columns. Without it the
          // list started hard against the header with nothing to separate the
          // thing you type from the thing you are choosing.
          Item {
            id: headerRule
            width: parent.width
            height: Style.spacing.sm
            visible: root.ready

            PanelSeparator {
              width: parent.width
              anchors.verticalCenter: parent.verticalCenter
              strength: 0.18
            }
          }

          // One line for whatever the picker is waiting on.
          Text {
            id: statusLine
            width: parent.width
            visible: !root.ready || root.notice.length > 0
            wrapMode: Text.WordWrap
            textFormat: Text.PlainText
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
            text: {
              if (root.busy) return "Waiting for the master password…"
              if (root.notice) return root.notice
              if (root.state === "engine-missing") return "KeePassXC is not installed."
              if (root.state === "no-database") return "No database selected. Press Enter to choose one."
              if (root.state === "missing-database") return "The selected database is gone. Press Enter to choose another."
              if (root.state === "locked") return "Locked. Press Enter to unlock."   // after a cancel
              if (root.state === "unknown") return "Checking the vault…"
              return ""
            }
          }
        }

          Item {
            id: resultsArea
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: topBlock.bottom
            anchors.topMargin: root.contentSpacing
            anchors.bottom: bottomBlock.top
            anchors.bottomMargin: root.contentSpacing
            visible: root.ready

            // The pane is only meaningful with a row to describe. With nothing
            // matched the list takes the full width and the empty state centres
            // on it, rather than sitting beside a blank column of labels.
            readonly property bool paneVisible: resultModel.count > 0

            ListView {
              id: resultList
              anchors.left: parent.left
              anchors.top: parent.top
              anchors.right: resultsArea.paneVisible ? paneRule.left : parent.right
              anchors.rightMargin: resultsArea.paneVisible ? Style.spacing.lg : 0
              // A whole number of rows. Anchored to the bottom it showed six
              // rows and the top half of a seventh, and a row cut through its
              // own glyphs is worse than no row.
              height: Math.max(root.rowHeight,
                               Math.floor(parent.height / root.rowHeight) * root.rowHeight)
              model: resultModel
              clip: true
              // Rows touch: the selection band IS the row, so a gap between
              // them would be a gap the band could not cover.
              spacing: 0
              boundsBehavior: Flickable.StopAtBounds
              currentIndex: root.selectedIndex

              delegate: Rectangle {
                id: rowItem
                width: resultList.width
                height: root.rowHeight
                // Square. Omarchy declares no radius for a list selection --
                // Style.cornerRadius is the CARD's -- and a rounded row inside
                // a rounded card reads as a second card.
                radius: 0
                color: index === root.selectedIndex ? root.selectedBackground : "transparent"

                // The cursor row changes its GROUND, not its ink. Recolouring
                // the text as well made the selected row the loudest thing on
                // screen and left the accent nothing quieter to mark.
                readonly property bool current: index === root.selectedIndex
                readonly property color primary: root.foreground
                readonly property color secondary: root.dim

                // A 2px accent on the cursor row. The filled background alone
                // reads as a block of colour; an edge tells you where you are
                // even at a glance.
                // Full height, flush left. Inset with a gap above and below it
                // read as a decoration on the row; running the whole height it
                // reads as the row's edge, which is what it is.
                Rectangle {
                  anchors.left: parent.left
                  anchors.top: parent.top
                  anchors.bottom: parent.bottom
                  width: root.barWidth
                  color: Color.accent
                  visible: rowItem.current
                }

                // A list marker, not a pictogram.
                //
                // This was a key glyph. At 12px type a key outline is noisier
                // than the text it labels, every row carried the same one so it
                // said nothing, and an icon at the head of a row reads as
                // something you could click. A bullet reads as what it is.
                Item {
                  id: rowMarker
                  anchors.left: parent.left
                  // Inside the band, past the bar's gutter. The band is the
                  // row's background and everything the row draws sits within
                  // it -- bar, marker and both lines as one unit.
                  anchors.leftMargin: root.markerInset
                  // On the two-line block, not on the row. The same thing now
                  // that the row is as tall as its content, but the block is
                  // what the marker belongs to.
                  anchors.verticalCenter: rowText.verticalCenter
                  width: root.glyphColumn
                  height: root.glyphColumn

                  Rectangle {
                    anchors.centerIn: parent
                    width: Style.space(5)
                    height: width
                    rotation: 45
                    color: rowItem.current ? Color.accent : root.faint
                  }
                }

                // Which field the search hit, when it was not the title. A
                // glyph rather than a sentence: the pane spells it out for the
                // one row you are actually looking at.
                Text {
                  id: whyGlyph
                  anchors.right: parent.right
                  anchors.rightMargin: Style.spacing.sm
                  anchors.verticalCenter: parent.verticalCenter
                  visible: model.why !== "title" && model.why !== "path"
                  text: model.why === "url" ? "󰖟"
                      : model.why === "username" ? "󰀄"
                      : "󰠮"
                  color: root.faint
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }

                Item {
                  id: rowText
                  anchors.left: rowMarker.right
                  anchors.leftMargin: root.glyphGap
                  anchors.right: whyGlyph.visible ? whyGlyph.left : parent.right
                  anchors.rightMargin: Style.spacing.xl
                  anchors.verticalCenter: parent.verticalCenter
                  height: titleText.implicitHeight + userText.implicitHeight

                  // Title on one line, username on the next, both starting at
                  // the same x. Each line gets the whole row, which is what
                  // long titles and long usernames actually need -- a fixed
                  // username column costs the title exactly the width the long
                  // ones are short of. The roles are positional: line one is
                  // always the title, line two always the username, so neither
                  // needs a header to say which is which.
                  Text {
                    id: titleText
                    // StyledText so the characters you typed can carry the
                    // accent. The title is escaped before it gets here.
                    textFormat: Text.StyledText
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    text: root.highlight(root.cleanTitle(model.title), root.filterText)
                    color: rowItem.primary
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    elide: Text.ElideRight
                  }

                  Text {
                    id: userText
                    textFormat: Text.PlainText
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: titleText.bottom
                    // Front-truncated when it is a real username: two accounts
                    // on the same host share a prefix and differ at the domain.
                    // Missing ones say so in words -- a lone em dash reads as a
                    // rendering fault rather than as an empty field.
                    text: model.username || "no username stored"
                    // body over caption, which is the pairing every shipped
                    // two-line Omarchy row uses. It looked like too small a
                    // step the first time only because lineHeight had inflated
                    // both boxes; at their natural size the colour carries it.
                    color: model.username ? rowItem.secondary : root.faint
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                    elide: model.username ? Text.ElideLeft : Text.ElideRight
                  }
                }

                MouseArea {
                  anchors.fill: parent
                  onClicked: {
                    root.selectedIndex = index
                    root.activate()
                  }
                }
              }
            }

            Rectangle {
              id: paneRule
              visible: resultsArea.paneVisible
              width: Math.max(1, Style.spacing.hairline)
              anchors.right: detailPane.left
              anchors.rightMargin: Style.spacing.lg
              anchors.top: parent.top
              anchors.bottom: parent.bottom
              // Down to the footer rule rather than to the last row: the gap
              // below it is the footer's breathing room, not a margin the
              // divider should respect.
              anchors.bottomMargin: -(root.contentSpacing + Style.spacing.xxl / 2)
              color: root.foreground
              opacity: 0.12
            }

            // The confirmation pane.
            //
            // Typing a password into the wrong field is the expensive mistake
            // this plugin can make, and a vault with four entries called "GGL
            // creds" invites it. This states what is about to be typed and
            // where, which is enough to commit without revealing anything: it
            // shows only the title, username and URL the agent already returns.
            // NO SECRET IS FETCHED OR DISPLAYED HERE, and there is no
            // reveal -- that would need the password to cross into QML, which
            // is the one thing this plugin exists to avoid.
            //
            // It is information, not behaviour. Enter still means password in
            // every window; the pane only lets you see which window that is.
            Item {
              id: detailPane
              visible: resultsArea.paneVisible
              width: root.paneWidth
              anchors.right: parent.right
              anchors.top: parent.top
              anchors.bottom: parent.bottom
              clip: true

              Column {
                id: paneColumn
                width: parent.width
                spacing: 0

                // Labels are small, spaced-out and faint; values are body-sized
                // and wrap rather than truncate. The pane is the one place the
                // whole string is guaranteed readable, so nothing here elides.
                Component {
                  id: paneField

                  Column {
                    width: paneColumn.width
                    // The system's label-to-value gap. Each field reads as one
                    // unit and the rules do the separating.
                    spacing: Style.spacing.labelGap
                    bottomPadding: Style.spacing.md

                    Text {
                      textFormat: Text.PlainText
                      text: modelData.label
                      color: root.faint
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      font.letterSpacing: Style.font.caption * 0.16
                    }

                    Text {
                      textFormat: Text.PlainText
                      width: parent.width
                      text: modelData.shown
                      // A value is a value. Dimming "never" or "—" made a
                      // stated fact look like a disabled control.
                      color: root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.body
                      // Word boundaries, falling back to anywhere only for a
                      // single word too long for the column -- a URL. Breaking
                      // "manager" across two lines was WrapAnywhere doing
                      // exactly what it was told.
                      wrapMode: modelData.oneLine ? Text.NoWrap : Text.Wrap
                      maximumLineCount: modelData.oneLine ? 1 : 3
                      elide: Text.ElideRight
                    }
                  }
                }

                Component {
                  id: paneRuleRow

                  Item {
                    width: paneColumn.width
                    height: Style.spacing.xl

                    PanelSeparator {
                      width: parent.width
                      anchors.verticalCenter: parent.verticalCenter
                      strength: 0.14
                    }
                  }
                }

                Repeater { model: root.paneIdentity; delegate: paneField }
                Loader { sourceComponent: paneRuleRow }
                Repeater { model: root.paneTarget; delegate: paneField }
                Loader { sourceComponent: paneRuleRow }
                Repeater { model: root.paneCredential; delegate: paneField }

                // The one action that belongs to the pane rather than to the
                // whole picker, so it lives here instead of lengthening a
                // footer that is meant to stay the same in every window.
                Loader { sourceComponent: paneRuleRow }

                // Always here, dimmed when there is nothing to open. Removing
                // it changed the pane's height as the selection moved, which
                // made the whole right-hand column twitch on every keystroke.
                Row {
                  id: paneAction
                  spacing: 0
                  readonly property bool armed:
                    root.currentRow !== null && String(root.currentRow.url) !== ""

                  Text {
                    textFormat: Text.PlainText
                    width: Style.space(52)
                    text: "Ctrl+U"
                    color: paneAction.armed ? Color.accent : root.faint
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }

                  Text {
                    textFormat: Text.PlainText
                    text: "open URL"
                    color: paneAction.armed ? root.dim : root.faint
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.caption
                  }
                }
              }
            }

            // Empty state, per plugins/clipboard/Clipboard.qml.
            Column {
              anchors.centerIn: parent
              width: parent.width
              spacing: Style.space(8)
              visible: resultModel.count === 0

              Text {
                text: "󰌿"
                color: root.selectedText
                opacity: 0.8
                font.family: root.fontFamily
                font.pixelSize: Style.font.displayLarge
                horizontalAlignment: Text.AlignHCenter
                width: parent.width
              }

              Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.filterText
                  ? "No entry matches “" + root.filterText + "”"
                  : "Start typing to search the vault"
                color: root.foreground
                opacity: 0.7
                font.family: root.fontFamily
                font.pixelSize: Style.font.title
                horizontalAlignment: Text.AlignHCenter
              }
            }
          }

        Column {
          id: bottomBlock
          anchors.bottom: parent.bottom
          anchors.left: parent.left
          anchors.right: parent.right
          spacing: 0

          // A rule and real space between the results and the chrome. Without
          // them the footer butted straight against the last row in the same
          // size and colour, and read as one more entry.
          Item {
            id: footerRule
            width: parent.width
            // The rule is 1px; the height is the breathing room around it.
            // Column spacing alone (6px) left it cramped against both.
            height: footer.visible ? Style.spacing.xxl : 0
            visible: footer.visible

            PanelSeparator {
              width: parent.width
              anchors.verticalCenter: parent.verticalCenter
              strength: 0.18
            }
          }

          // What Enter will do, and where it will land. Stated before you
          // commit, because a fill into a terminal is a different act.
          //
          // A Row rather than one styled string: the gap between hints is the
          // thing that makes four labels read as one strip, and it has to be a
          // spacing token rather than however wide six non-breaking spaces
          // happen to render.
          Row {
            id: footer
            width: parent.width
            visible: root.footerHints.length > 0
            topPadding: Style.spacing.lg
            bottomPadding: Style.spacing.xs
            spacing: Style.spacing.huge

            Repeater {
              model: root.footerHints

              Row {
                spacing: Style.spacing.sm

                Text {
                  textFormat: Text.PlainText
                  text: modelData.name
                  color: Color.accent
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                }

                Text {
                  textFormat: Text.PlainText
                  text: modelData.what
                  color: root.dim
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.bodySmall
                }
              }
            }
          }
        }
        }
      }
    }
  }
}
