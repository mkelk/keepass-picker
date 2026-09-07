// BarWidget.qml — the ambient half of mkelk.keepass-picker.
//
// A lock glyph and nothing else. What it shows comes entirely from
// ~/.local/state/omarchy/keepass-picker.status.json, which the agent
// publishes on every state change.
//
// THAT FILE IS THE WHOLE POINT. The first version of this widget ran
// `keepass-picker-ctl status` on a five-second timer, and when a spawn-lock
// deadlock made those calls hang they piled up inside omarchy-shell until it
// stopped answering IPC — process alive, bar gone. So this widget runs one
// FileView and never a process of its own: a bar with the plugin enabled
// costs nothing, and the failure mode is gone structurally rather than
// bounded by a watchdog.
//
// The same convention, and the same reasoning, as
// ~/.config/omarchy/plugins/mkelk.dock-recall/BarWidget.qml.
//
// Reference: /usr/share/omarchy/shell/plugins/panels/clock/BarWidget.qml for
// the bar-widget contract.

import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

BarWidget {
  id: root
  moduleName: "mkelk.keepass-picker"

  readonly property string statusPath: (Quickshell.env("XDG_STATE_HOME") || (Quickshell.env("HOME") + "/.local/state"))
    + "/omarchy/keepass-picker.status.json"

  // A status file that is missing, empty or corrupt lands on "unknown", which
  // is the honest answer for an agent that has not spoken yet.
  property string vaultState: "unknown"
  property string databaseName: ""
  property int relocksIn: -1
  property double statusUpdated: 0

  // Nothing restarts the agent now that this widget spawns no process, so a
  // status file can outlive the agent that wrote it. Only a live agent can
  // hold an unlocked vault, so a stale file means "not unlocked" whatever it
  // says. Showing a padlock that is wrong is worse than showing one that is
  // merely cautious.
  // `now` is what makes this re-evaluate; assigning statusUpdated its own
  // value would emit no change signal and the padlock would never go stale.
  property double now: Date.now() / 1000
  readonly property bool stale: root.statusUpdated > 0
    && (root.now - root.statusUpdated) > 60

  readonly property bool unlocked: vaultState === "unlocked" && !root.stale
  readonly property bool configured: vaultState !== "no-database"
    && vaultState !== "missing-database"
    && vaultState !== "engine-missing"

  // 󰌿 open, 󰌾 shut. Both verified present in the bar font rather than assumed —
  // an absent glyph renders as a blank box and nothing warns you.
  readonly property string glyph: root.unlocked ? "󰌿" : "󰌾"

  readonly property string tooltip: {
    if (root.vaultState === "unlocked") {
      var base = "KeePass — unlocked"
      if (root.databaseName) base += " (" + root.databaseName + ")"
      if (root.relocksIn > 0) base += "\nRelocks in " + root.humanize(root.relocksIn)
      return base + "\nClick to search"
    }
    if (root.stale) return "KeePass — the agent is not running\nClick to start it"
    if (root.vaultState === "locked")
      return "KeePass — locked" + (root.databaseName ? " (" + root.databaseName + ")" : "")
        + "\nClick to unlock and search"
    if (root.vaultState === "no-database") return "KeePass — no database selected"
    if (root.vaultState === "missing-database") return "KeePass — the selected database is gone"
    if (root.vaultState === "engine-missing") return "KeePass — keepassxc-cli is not installed"
    return "KeePass — waiting for the agent"
  }

  function humanize(seconds) {
    if (seconds >= 3600) return Math.round(seconds / 3600) + "h"
    if (seconds >= 60) return Math.round(seconds / 60) + "m"
    return seconds + "s"
  }

  function applyStatus(raw) {
    var data = {}
    try { data = JSON.parse(raw || "{}") } catch (e) { data = {} }
    root.vaultState = data.state ? String(data.state) : "unknown"
    root.databaseName = data.database ? String(data.database) : ""
    root.relocksIn = (typeof data.relocks_in === "number") ? data.relocks_in : -1
    root.statusUpdated = (typeof data.updated === "number") ? data.updated : 0
  }

  // Re-evaluates `stale` without touching the filesystem: no FileView reload,
  // no process, just the clock.
  Timer {
    interval: 30000
    running: true
    repeat: true
    onTriggered: root.now = Date.now() / 1000
  }

  // The route is the SHELL's, not a panel of our own, so the bar click and
  // SUPER+SHIFT+K land on the same single overlay instance.
  readonly property var hostShell: root.bar && root.bar.shell ? root.bar.shell : null

  function togglePicker() {
    if (root.hostShell && typeof root.hostShell.toggle === "function")
      root.hostShell.toggle(root.moduleName, "{}")
  }

  FileView {
    path: root.statusPath
    watchChanges: true
    // A missing status file is the normal state before the agent's first run,
    // not a fault worth a stack trace.
    printErrors: false
    onLoaded: root.applyStatus(text())
    onLoadFailed: root.applyStatus("")
    onFileChanged: reload()
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.glyph
    // Unlocked is the state worth noticing, so it carries the weight; a locked
    // vault is the resting state and recedes.
    active: root.unlocked
    dimmed: !root.configured
    tooltipText: root.tooltip
    onPressed: function (b) { root.togglePicker() }
  }
}
