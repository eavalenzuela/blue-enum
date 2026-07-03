#!/usr/bin/env python3
"""blueenum.py -- a small enumeration helper for the OSCP / authorised pentests.

Runs nmap against a set of targets, parses the XML results, and follows up with
nikto against any discovered web servers. Provides an interactive menu as well
as a non-interactive command-line mode for scripting.

Original: Eric Valenzuela, eevn.io -- June 14, 2017.
Modernised for Python 3 with a CLI, multi-port web detection, backups and
reporting.

Only run this against systems you are explicitly authorised to test.
"""

import argparse
import datetime
import ipaddress
import os
import re
import shutil
import sys
import xml.etree.ElementTree as ET
import zipfile
from subprocess import PIPE, Popen

# ----- Configuration ---------------------------------------------------------

OUTPUT_DIR = "./blueenum_outputs"

# Ports we treat as "web" for the nikto follow-up (in addition to nmap's own
# service detection). TLS ports additionally get nikto's -ssl flag.
HTTP_PORTS = {"80", "8000", "8080", "8888"}
HTTPS_PORTS = {"443", "8443"}

# Runtime-configurable scan settings (adjusted via the "Program select" menu or
# the command line).
CONFIG = {
    "nmap_flags": ["-A"],
    "run_nikto": True,
}

# Collected non-fatal runtime messages, printed on exit.
messages = []


# ----- Small helpers ---------------------------------------------------------

def log(message):
    """Record a non-fatal runtime message for the end-of-run summary."""
    if message:
        messages.append(message)


def print_messages():
    """Print any collected runtime messages."""
    if messages:
        print("\nRuntime messages:")
        for message in messages:
            print("  " + str(message))


def has_tool(name):
    """Return True if an external tool is available on PATH."""
    return shutil.which(name) is not None


def _decode(data):
    """Decode subprocess bytes output to str (no-op for str/None)."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return str(data)


def run(cmd):
    """Run a command, returning (stdout, stderr) as decoded strings."""
    try:
        proc = Popen(cmd, stdout=PIPE, stderr=PIPE)
        out, err = proc.communicate()
        proc.wait()
        return _decode(out), _decode(err)
    except FileNotFoundError:
        return "", "command not found: %s" % cmd[0]


def ensure_output_dir(output_dir=None):
    """Create the output directory if it does not already exist."""
    output_dir = output_dir or OUTPUT_DIR
    if not os.path.isdir(output_dir):
        print("No output directory found. Creating %s." % output_dir)
        os.makedirs(output_dir, exist_ok=True)
    return output_dir


def expand_targets(text):
    """Expand an IP or CIDR block into a list of host address strings.

    Returns an empty list if the input is not a valid IP/CIDR.
    """
    text = (text or "").strip()
    if not text:
        return []
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return []
    hosts = [str(ip) for ip in net.hosts()]
    return hosts or [str(net.network_address)]


def merge_addresses(addresses, new_ips):
    """Merge new IPs into the address list, dropping the None sentinel and dupes."""
    existing = [a for a in addresses if a]
    for ip in new_ips:
        if ip not in existing:
            existing.append(ip)
    return existing or [None]


def match_ip_files(ip, files):
    """Return the stored files associated with a single IP.

    Matching is anchored on a numeric boundary so that removing "10.0.0.1" does
    not also match "10.0.0.10" or "10.0.0.100".
    """
    pattern = re.compile(r"^(nikto_)?" + re.escape(ip) + r"(?![0-9])")
    return [f for f in files if pattern.match(f)]


# ----- Menu prompts ----------------------------------------------------------

MAIN_MENU = (
    "\n\nBlue-enum scanner.\nPlease make a selection.\n"
    "   1: Add IPs\n"
    "   2: Run Scans\n"
    "   3: Clear IPs\n"
    "   4: Program select\n"
    "   5: List IPs\n"
    "   6: Rebuild IP list from files\n"
    "   7: Utilities\n"
    "   8: Exit"
)


# ----- Add / clear / list IPs ------------------------------------------------

def addips(addresses):
    """Interactively add an IP or CIDR block to the address list."""
    print("\nPlease enter the IP or IP block (CIDR notation) you wish to add.")
    new_ips = expand_targets(input("new_ips> "))
    if not new_ips:
        print("Invalid entry. Did you use a valid IP or CIDR block?")
        return addresses
    print("Added %d address(es)." % len(new_ips))
    return merge_addresses(addresses, new_ips)


def clearips(addresses):
    """Clear all stored IPs."""
    return [None]


def printaddrs(addresses):
    """Print the currently stored IPs."""
    print("\nIPs stored:")
    stored = [a for a in addresses if a]
    if not stored:
        print("1: None")
        return
    for index, ip in enumerate(stored, start=1):
        print("%d: %s" % (index, ip))


def rebuildips(addresses):
    """Repopulate the IP list from nmap XML files already on disk."""
    ip_re = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    found = [a for a in addresses if a]
    if os.path.isdir(OUTPUT_DIR):
        for name in sorted(os.listdir(OUTPUT_DIR)):
            match = ip_re.match(name)
            if match and match.group(1) not in found:
                found.append(match.group(1))
    return found or [None]


# ----- Scanning --------------------------------------------------------------

def scanner(addresses, output_dir=None):
    """Run nmap against every stored address, then follow up on web servers."""
    output_dir = output_dir or OUTPUT_DIR
    targets = [a for a in addresses if a]
    if not targets:
        print("No IPs to scan. Add some first (menu option 1).")
        return
    if not has_tool("nmap"):
        log("nmap not found on PATH; cannot run scans.")
        print("Error: nmap is not installed or not on PATH.")
        return

    ensure_output_dir(output_dir)
    for ip in targets:
        xml_path = os.path.join(output_dir, ip + ".xml")
        if os.path.isfile(xml_path):
            print("Skipping %s (already scanned)." % ip)
            continue
        cmd = ["nmap"] + CONFIG["nmap_flags"] + ["-oX", xml_path, str(ip)]
        print("Running: " + " ".join(cmd))
        _out, err = run(cmd)
        if err.strip():
            log("nmap errors for %s: %s" % (ip, err.strip()))
        print("Finished nmap for %s." % ip)

    parse2enums(targets, output_dir)


def parse2enums(addresses, output_dir=None):
    """Parse each host's nmap XML and trigger web-server follow-up."""
    output_dir = output_dir or OUTPUT_DIR
    for ip in [a for a in addresses if a]:
        xml_path = os.path.join(output_dir, ip + ".xml")
        try:
            root = ET.parse(xml_path).getroot()
        except FileNotFoundError:
            print("No scan file for %s (skipping enumeration)." % ip)
            continue
        except ET.ParseError as exc:
            print("Malformed XML for %s: %s. Remove and re-scan." % (ip, exc))
            continue
        follow_up_web(root, ip, output_dir)


def follow_up_web(root, ip, output_dir=None):
    """Run nikto against open web ports found in a parsed nmap tree."""
    output_dir = output_dir or OUTPUT_DIR
    for port in root.iter("port"):
        state = port.find("state")
        if state is not None and state.get("state") != "open":
            continue
        portid = port.get("portid") or ""
        service = port.find("service")
        name = (service.get("name") or "") if service is not None else ""
        tunnel = (service.get("tunnel") or "") if service is not None else ""

        looks_web = "http" in name or portid in HTTP_PORTS or portid in HTTPS_PORTS
        is_ssl = tunnel == "ssl" or "https" in name or portid in HTTPS_PORTS
        if looks_web:
            scheme = "https" if is_ssl else "http"
            print("%s:%s looks like a %s server -- running nikto." % (ip, portid, scheme))
            niktoscan(ip, portid or "80", use_ssl=is_ssl, output_dir=output_dir)


def niktoscan(address, port="80", use_ssl=False, output_dir=None):
    """Run nikto against a single host:port."""
    output_dir = output_dir or OUTPUT_DIR
    if not CONFIG["run_nikto"]:
        return
    if not has_tool("nikto"):
        log("nikto not found on PATH; skipping web scan of %s:%s." % (address, port))
        print("Warning: nikto not installed; skipping %s:%s." % (address, port))
        return

    ensure_output_dir(output_dir)
    out_file = os.path.join(output_dir, "nikto_%s_%s.xml" % (address, port))
    cmd = ["nikto", "-h", str(address), "-p", str(port), "-output", out_file]
    if use_ssl:
        cmd.append("-ssl")
    _out, err = run(cmd)
    if err.strip():
        log("nikto errors for %s:%s: %s" % (address, port, err.strip()))


# ----- Reporting -------------------------------------------------------------

def build_report(addresses, output_dir=None):
    """Build a consolidated per-host open-ports report from stored XML files."""
    output_dir = output_dir or OUTPUT_DIR
    lines = ["Blue-enum open-port report", "=" * 30]
    targets = [a for a in addresses if a]
    if not targets:
        lines.append("(no IPs loaded)")
        return "\n".join(lines)

    for ip in targets:
        xml_path = os.path.join(output_dir, ip + ".xml")
        if not os.path.isfile(xml_path):
            lines.append("%s: (no scan data)" % ip)
            continue
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError:
            lines.append("%s: (malformed scan data)" % ip)
            continue

        open_ports = []
        for port in root.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            name = (service.get("name") or "?") if service is not None else "?"
            open_ports.append(
                "%s/%s %s" % (port.get("portid"), port.get("protocol"), name)
            )

        if open_ports:
            lines.append("%s:" % ip)
            lines.extend("  " + entry for entry in open_ports)
        else:
            lines.append("%s: no open ports found" % ip)
    return "\n".join(lines)


# ----- Utilities: remove / backup --------------------------------------------

def removedata(addresses):
    """Remove every stored scan file and clear the IP list."""
    removed = 0
    if os.path.isdir(OUTPUT_DIR):
        for name in os.listdir(OUTPUT_DIR):
            path = os.path.join(OUTPUT_DIR, name)
            if not os.path.isfile(path):
                continue
            try:
                os.remove(path)
                removed += 1
            except OSError as exc:
                log("Could not remove %s: %s" % (name, exc))
    print("Removed %d stored file(s)." % removed)
    return [None]


def removeitem(addresses):
    """Remove the files (and list entries) for one or more IPs."""
    print("\nEnter the IP or CIDR block to remove. Associated files are deleted too.")
    targets = expand_targets(input("rem_ips> "))
    if not targets:
        print("Invalid entry.")
        return addresses

    files = os.listdir(OUTPUT_DIR) if os.path.isdir(OUTPUT_DIR) else []
    for ip in targets:
        for name in match_ip_files(ip, files):
            try:
                os.remove(os.path.join(OUTPUT_DIR, name))
                print("Removed " + name)
            except OSError as exc:
                log("Could not remove %s: %s" % (name, exc))

    kept = [a for a in addresses if a and a not in targets]
    return kept or [None]


def backup_zip(output_dir=None):
    """Back up all stored files into a timestamped zip archive."""
    output_dir = output_dir or OUTPUT_DIR
    if not os.path.isdir(output_dir):
        print("No output directory to back up yet.")
        return None
    files = sorted(
        f for f in os.listdir(output_dir)
        if os.path.isfile(os.path.join(output_dir, f))
    )
    if not files:
        print("No files to back up.")
        return None

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_path = "blueenum_backup_%s.zip" % stamp
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in files:
            archive.write(os.path.join(output_dir, name), arcname=name)
    print("Backed up %d file(s) to %s" % (len(files), zip_path))
    return zip_path


# ----- Interactive menus -----------------------------------------------------

def progmenu():
    """Configure scan behaviour (nmap flags, nikto follow-up)."""
    while True:
        print("\nProgram / scan configuration")
        print("  Current nmap flags: %s" % " ".join(CONFIG["nmap_flags"]))
        print("  nikto follow-up:    %s" % ("on" if CONFIG["run_nikto"] else "off"))
        print("   1: Set nmap flags")
        print("   2: Toggle nikto follow-up")
        print("   3: Return to main menu")
        choice = input("cfg_$> ").strip()
        if choice == "1":
            flags = input("nmap flags> ").strip()
            if flags:
                CONFIG["nmap_flags"] = flags.split()
                print("nmap flags set to: %s" % " ".join(CONFIG["nmap_flags"]))
        elif choice == "2":
            CONFIG["run_nikto"] = not CONFIG["run_nikto"]
            print("nikto follow-up is now %s." % ("on" if CONFIG["run_nikto"] else "off"))
        elif choice == "3":
            return
        else:
            print("Invalid selection.")


def utilmenu(addresses):
    """Utility submenu: remove data, back up, or report."""
    while True:
        print(
            "\nUtility Menu\nPlease make a selection.\n"
            "   1: Remove all stored files\n"
            "   2: Remove single IP + files\n"
            "   3: Backup all stored files to zip\n"
            "   4: Open-port report\n"
            "   5: Return to main menu"
        )
        choice = input("bp_$> ").strip()
        if choice == "1":
            addresses = removedata(addresses)
        elif choice == "2":
            addresses = removeitem(addresses)
        elif choice == "3":
            backup_zip()
        elif choice == "4":
            print("\n" + build_report(addresses))
        elif choice == "5":
            print("\nReturning to main menu.")
            return addresses
        else:
            print("You have entered an invalid selection.")


def interactive(addresses):
    """Run the interactive menu loop."""
    while True:
        print(MAIN_MENU)
        choice = input("bp_$> ").strip()
        if choice == "1":
            addresses = addips(addresses)
        elif choice == "2":
            scanner(addresses)
        elif choice == "3":
            addresses = clearips(addresses)
        elif choice == "4":
            progmenu()
        elif choice == "5":
            printaddrs(addresses)
        elif choice == "6":
            addresses = rebuildips(addresses)
        elif choice == "7":
            addresses = utilmenu(addresses)
        elif choice == "8":
            print("Exiting.")
            break
        else:
            print("Invalid selection. Please re-enter.")
    print_messages()


# ----- Command-line entry point ----------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Blue-enum: nmap + nikto enumeration helper for authorised testing."
    )
    parser.add_argument(
        "-t", "--targets", nargs="+", metavar="IP/CIDR",
        help="one or more IPs or CIDR blocks to load",
    )
    parser.add_argument(
        "-o", "--output-dir", default=OUTPUT_DIR,
        help="directory for scan output (default: %(default)s)",
    )
    parser.add_argument(
        "--scan", action="store_true",
        help="run scans for the given targets, then exit",
    )
    parser.add_argument(
        "--report", action="store_true",
        help="print an open-port report for the given targets, then exit",
    )
    parser.add_argument(
        "--no-nikto", action="store_true",
        help="disable the nikto web-server follow-up",
    )
    parser.add_argument(
        "--nmap-flags", metavar="FLAGS",
        help="override nmap flags, e.g. \"-sV -T4\" (default: -A)",
    )
    return parser


def main(argv=None):
    global OUTPUT_DIR
    args = build_parser().parse_args(argv)

    OUTPUT_DIR = args.output_dir
    if args.no_nikto:
        CONFIG["run_nikto"] = False
    if args.nmap_flags:
        CONFIG["nmap_flags"] = args.nmap_flags.split()

    addresses = [None]
    if args.targets:
        for target in args.targets:
            expanded = expand_targets(target)
            if expanded:
                addresses = merge_addresses(addresses, expanded)
            else:
                print("Ignoring invalid target: %s" % target)

    # Non-interactive actions.
    if args.scan or args.report:
        if args.scan:
            scanner(addresses)
        if args.report:
            print(build_report(addresses))
        print_messages()
        return

    interactive(addresses)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        sys.exit(0)
