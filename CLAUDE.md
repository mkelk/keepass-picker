# Working in this repository

Read [CONTRIBUTING.md](CONTRIBUTING.md) first. It has the layout, the five
security rules every change must keep, the gates, and the traps.

- This repository is the shipped plugin. Design history and working notes live
  in the private sibling `mkelk/keepass-picker-dev` (`~/git/keepass-picker-dev`).
  Nothing from there belongs here, and nothing here may name a real vault,
  entry, home path or machine.
- Run `./tests/run-all.sh` and `omarchy plugin validate .` before every commit.
- Never screenshot, read or point a test at the real vault. `preview.png` is a
  demo vault; keep it that way.
- Bump `version` in `manifest.json` before a push that is meant as a release.
