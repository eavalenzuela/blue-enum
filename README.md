# blue-enum

A small enumeration helper I built to speed up the OSCP labs. It drives **nmap**
against a set of targets, parses the XML results, and follows up with **nikto**
against any discovered web servers — while managing the output files for you.

> **Authorised use only.** Only run this against hosts and networks you have
> explicit permission to test.

## Requirements

- Python 3.6+ (standard library only — no `pip install` needed)
- [`nmap`](https://nmap.org/) on your `PATH`
- [`nikto`](https://github.com/sullo/nikto) on your `PATH` (optional; the
  web-server follow-up is skipped with a warning if it is missing)

## Usage

### Interactive menu (default)

```bash
python3 blueenum.py
```

```
Blue-enum scanner.
Please make a selection.
   1: Add IPs                     # accepts a single IP or a CIDR block
   2: Run Scans                   # nmap each host, then nikto on web ports
   3: Clear IPs
   4: Program select              # set nmap flags / toggle nikto
   5: List IPs
   6: Rebuild IP list from files  # repopulate from existing scan output
   7: Utilities                   # remove data, zip backup, open-port report
   8: Exit
```

### Non-interactive (scriptable)

```bash
# Scan a /24 and follow up on web servers
python3 blueenum.py -t 10.0.0.0/24 --scan

# Scan several targets with custom nmap flags, no nikto
python3 blueenum.py -t 10.0.0.5 10.0.0.10 --nmap-flags "-sV -T4" --no-nikto --scan

# Print a consolidated open-port report from existing scan data
python3 blueenum.py -t 10.0.0.0/24 --report
```

| Option | Description |
| ------ | ----------- |
| `-t, --targets` | One or more IPs / CIDR blocks to load |
| `-o, --output-dir` | Directory for scan output (default `./blueenum_outputs`) |
| `--scan` | Run scans for the targets, then exit |
| `--report` | Print an open-port report for the targets, then exit |
| `--no-nikto` | Disable the nikto web-server follow-up |
| `--nmap-flags` | Override nmap flags (default `-A`) |

## Output

Scan artifacts are written to `./blueenum_outputs/`:

- `‹ip›.xml` — nmap XML output per host
- `nikto_‹ip›_‹port›.xml` — nikto output per web service

Web-server detection is driven by nmap's own service/tunnel information plus a
set of common HTTP/HTTPS ports (80/443/8080/8443/…), so it is not limited to
port 80. TLS services are scanned with `nikto -ssl`.

## Tests

```bash
python3 -m pytest -q       # or: python3 -m unittest -v tests/test_blueenum.py
```

The suite covers the pure helper logic (target expansion, safe file matching,
report generation) and does **not** invoke nmap/nikto.

---

Original author: Eric Valenzuela — eevn.io

- email: eric@eevn.io
- twitter: @angeloCire

Feedback and pull requests welcome.
