# Blue-enum — Planned Improvements & Features

A focused modernisation of `blueenum.py`, the OSCP enumeration helper. The plan
keeps the interactive, single-file, procedural style while fixing runtime-breaking
bugs and adding practical enumeration capability.

## Improvements (existing behaviour / robustness / quality)

1. **Fix Python-3 `unicode()` / `raw_input()` crashes** — `addips` and
   `removeitem` call `unicode(...)`/`raw_input(...)` which do not exist in
   Python 3, so *any* IP entry raises `NameError`. Use plain `input()`.
   _Rationale: the core "Add IPs" path is completely broken on every modern Python._

2. **Fix the output-directory check + creation** — `os.path.exists(os.path.dirname("./blueenum_outputs"))`
   always evaluates `os.path.exists(".")` (True), so the directory is never made;
   replace the `Popen(["mkdir", ...])` shell-out with `os.makedirs(exist_ok=True)`.
   _Rationale: reliable, cross-platform directory creation that actually runs._

3. **Fix the Utilities submenu** — it compares `input()` (a `str`) against ints
   (`if uitem == 1`), so no option ever fires and `while uitem != 4` never exits.
   Normalise all menu handling to string comparisons and clean loop exits.
   _Rationale: the entire utility menu is currently a no-op infinite loop._

4. **Safe filename matching for deletion** — `removedata`/`removeitem` use the raw
   IP as an unescaped, unanchored regex, so removing `10.0.0.1` also deletes
   `10.0.0.10`, `10.0.0.100`, etc. Use `re.escape` + a numeric-boundary anchor.
   _Rationale: prevents destroying scan data for unrelated hosts._

5. **Decode subprocess output and surface messages** — `Popen` returns `bytes`;
   results/messages were discarded or mixed str/bytes. Centralise in a `run()`
   helper that decodes, and print a runtime-message summary on exit.
   _Rationale: users actually see nmap/nikto errors instead of silent failure._

6. **Replace bare `except:` blocks** — `parse2enums` and `niktoscan` swallow every
   error with `except:`. Catch specific exceptions with informative messages.
   _Rationale: real errors (missing tools, bad XML) become visible and debuggable._

7. **Detect required tools before invoking** — check `shutil.which("nmap"/"nikto")`
   and warn gracefully instead of raising when a tool is absent.
   _Rationale: clear UX on machines without nikto/nmap installed._

8. **Guard against empty IP lists + dedupe on add** — scanning `[None]` fed `None`
   to nmap; adds allowed duplicates. Filter the sentinel and dedupe.
   _Rationale: avoids nmap being called on a `None` target and repeated scans._

9. **Add a `.gitignore`** for `blueenum_outputs/`, backups, and Python caches.
   _Rationale: scan artifacts and `__pycache__` should never be committed._

10. **Importable module + accurate README** — wrap the menu loop in a
    `main()` / `if __name__ == "__main__"` guard (importing the file no longer
    launches the menu) and rewrite the README with real usage/requirements. A
    small unit-test suite for the pure helpers is added alongside.
    _Rationale: enables testing/reuse and gives users honest documentation._

## New Features

1. **Non-interactive CLI (argparse)** — `blueenum.py -t 10.0.0.0/24 --scan --report`
   for scripting; the menu remains the default when no arguments are given.
   _Rationale: lets the tool run in pipelines and one-liners, not just interactively._

2. **Multi-port HTTP/HTTPS detection** — drive nikto from nmap's parsed service
   names/tunnels (80/443/8080/8443/…, `-ssl` for TLS) instead of hardcoding port 80.
   _Rationale: finds web servers on the many non-80 ports OSCP targets use._

3. **Zip backup utility** — implement the "Backup all stored files" option (was a
   `print(3)` stub) using `zipfile` with a timestamped archive.
   _Rationale: one-command, portable snapshot of all enumeration output._

4. **Program/scan configuration menu** — implement "Program select" (was `print(4)`):
   set custom nmap flags and toggle the nikto follow-up.
   _Rationale: lets users tune scan speed/stealth without editing code._

5. **Consolidated open-ports report** — parse every stored XML into a per-host
   open-ports summary, available as a menu action and `--report`.
   _Rationale: fast at-a-glance enumeration overview across all targets._
