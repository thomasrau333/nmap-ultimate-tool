#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SPDX-License-Identifier: GPL-3.0-or-later

Copyright (C) 2025-2026 Thomas Rau

This program is free software: you can redistribute it
and/or modify it under the terms of the GNU General
Public License as published by the Free Software
Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will
be useful, but WITHOUT ANY WARRANTY; without even the
implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE.

See the LICENSE file for the full license text.



Nmap Ultimate Tool — v7.0 (fix + UDP Top-200 default)
2025-10-20 by Thomas Rau

⚠️ WICHTIG — Rechtliche & ethische Nutzung
Dieses Tool darf ausschließlich **in privaten Prüf‑/Laborumgebungen** oder **in Netzwerken, für die Sie eine schriftliche Erlaubnis** 
(z. B. ausdrückliche Einwilligung des Eigentümers/Betreibers) besitzen, verwendet werden. 
Jeglicher nicht autorisierte Einsatz in fremden Netzen ist untersagt und kann rechtliche Folgen haben.


Dieses Tool bietet eine erweiterte, interaktive Oberfläche für Nmap. 
Es umfasst schnelle Portscans, Versionsscans, OS-Erkennung, Ping Sweeps, All-Hosts Discovery, Stealth Scans, aggressive Scans, SSH-Versionserkennung und einen neuen UDP-Scan auf Standard-Top-Ports. 
Alle Menüfunktionen laufen interaktiv, mit Fortschrittsbalken und optionaler Reverse-DNS Auflösung.

---

## Umgebung

OS: Debian GNU/Linux 13 (trixie) x86_64
Kernel: Linux 6.12.48+deb13-amd64
Shell version bash 5.2.37
Nmap version 7.95 ( https://nmap.org )
Python3 version 3.13.5
colorama version 0.4.6

Ziele:
 - Alle Menüoptionen 1..9 funktionieren vollständig
 - Option 6 (All-Hosts) zeigt nur wirklich erreichbare Hosts (Status: Up)
 - Fortschrittsbalken für Option 2 & 3 (und für lange Scans, inkl. UDP, falls nmap % meldet)
 - Reverse DNS parallel + cached
 - UDP-Scan als neue Option 'u' mit Default Top-200 (keine Full-Port-Abfrage)
 - Keine Versionsnummeränderung (v7.0)
"""

import os
import sys
import re
import shlex
import shutil
import subprocess
import socket
import ipaddress
import platform
import traceback
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

# colorama for colored output
try:
    from colorama import init as colorama_init, Fore, Style
except Exception:
    print("Benötigtes Paket 'colorama' nicht gefunden. Bitte installieren: pip3 install colorama")
    sys.exit(1)
colorama_init(autoreset=True)

# -----------------------
# Config & defaults
# -----------------------
VERSION = "v7.0-final"
NMAP_BIN = shutil.which("nmap") or "nmap"
SCAN_DIR = "nmap_scans"

PROFILES = {
    "schnell": "-T4 --top-ports 200",
    "tief": "-p 1-65535 -sV -sC -O -T3",
    "aggressiv": "-A -T4",
    "paranoid": "-T0 --top-ports 100 -sS"
}

MENU = [
    ("1", "Schneller Portscan (Profil: schnell)"),
    ("2", "Versionsscan (-sV)"),
    ("3", "OS-Erkennung (-O)"),
    ("4", "Ping Sweep (ICMP Tabelle, einmalig)"),
    ("5", "Benutzerdefiniert (Targets, Ports, Profil)"),
    ("6", "All-Hosts (Host Discovery, nur erreichbare Hosts)"),
    ("7", "Stealth Scan (SYN, top-ports)"),
    ("8", "Aggressive Scan (A)"),
    ("9", "SSH-Versionen prüfen (nutzt -sV Filter)"),
    ("u", "UDP Scan (Top-200 default, optional eigene Ports, optional -sV)"),
    ("0", "Beenden")
]

PERCENT_RE = re.compile(r'(\d{1,3}(?:\.\d+)?)\s*%')

# -----------------------
# Helpers
# -----------------------
def check_nmap():
    if not shutil.which(NMAP_BIN):
        print(Fore.RED + "nmap wurde nicht gefunden. Bitte installieren (z. B. sudo apt install nmap)." + Style.RESET_ALL)
        sys.exit(1)

def ensure_scan_folder():
    os.makedirs(SCAN_DIR, exist_ok=True)

def safe_filename(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]', '_', s)

def now_str():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def color_port_line(line: str) -> str:
    if re.search(r"\bopen\b", line, re.IGNORECASE):
        return Fore.GREEN + line + Style.RESET_ALL
    if re.search(r"\bclosed\b", line, re.IGNORECASE):
        return Fore.RED + line + Style.RESET_ALL
    return Fore.YELLOW + line + Style.RESET_ALL

def make_paths(target_label: str, label: str):
    ensure_scan_folder()
    safe = safe_filename(target_label)
    ts = now_str()
    txt = os.path.join(SCAN_DIR, f"scan_{safe}_{label}_{ts}.txt")
    xml = os.path.join(SCAN_DIR, f"scan_{safe}_{label}_{ts}.xml")
    return txt, xml

# -----------------------
# Nmap run helpers
# -----------------------
def run_nmap_stream(targets, opts, txt_path=None, live_progress=True):
    parts = [NMAP_BIN] + shlex.split(opts) + targets.split()
    print(Fore.YELLOW + f"\nAusgeführter Befehl: {Style.BRIGHT}{' '.join(parts)}{Style.RESET_ALL}\n")
    try:
        proc = subprocess.Popen(parts, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    except Exception as e:
        print(Fore.RED + f"Fehler beim Starten von nmap: {e}" + Style.RESET_ALL)
        return ""

    out_lines = []
    last_pct = -1
    f = None
    try:
        if txt_path:
            try:
                f = open(txt_path, "w", encoding="utf-8")
            except Exception:
                f = None
        for raw in proc.stdout:
            out_lines.append(raw)
            if f:
                try:
                    f.write(raw)
                except Exception:
                    pass
            if live_progress:
                m = PERCENT_RE.search(raw)
                if m:
                    try:
                        pct = int(round(float(m.group(1))))
                        if pct != last_pct:
                            last_pct = pct
                            bar_len = 40
                            filled = int(bar_len * pct / 100)
                            bar = "█" * filled + "-" * (bar_len - filled)
                            sys.stdout.write(f"\rFortschritt: |{bar}| {pct:3d}%")
                            sys.stdout.flush()
                    except Exception:
                        pass
        if last_pct >= 0:
            print()
    except KeyboardInterrupt:
        try:
            proc.terminate()
        except Exception:
            pass
        print(Fore.CYAN + "\nScan abgebrochen." + Style.RESET_ALL)
    finally:
        try:
            proc.wait()
        except Exception:
            pass
        if f:
            try:
                f.close()
            except Exception:
                pass
    return "".join(out_lines)

def run_nmap_quick(targets, opts, txt_path=None, xml_path=None):
    parts = [NMAP_BIN] + shlex.split(opts) + targets.split()
    if xml_path:
        parts += ["-oX", xml_path]
    print(Fore.YELLOW + f"\nAusgeführter Befehl: {Style.BRIGHT}{' '.join(parts)}{Style.RESET_ALL}\n")
    try:
        res = subprocess.run(parts, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output = res.stdout
        if txt_path:
            try:
                with open(txt_path, "w", encoding="utf-8") as f:
                    f.write(output)
            except Exception:
                pass
        return output
    except KeyboardInterrupt:
        print(Fore.CYAN + "\nScan abgebrochen." + Style.RESET_ALL)
        return ""

def run_nmap_grepable(targets, opts, txt_path=None):
    parts = [NMAP_BIN] + shlex.split(opts)
    if not any(p.startswith("-oG") for p in parts):
        parts += ["-oG", "-"]
    parts += targets.split()
    print(Fore.YELLOW + f"\nAusgeführter Befehl: {Style.BRIGHT}{' '.join(parts)}{Style.RESET_ALL}\n")
    try:
        res = subprocess.run(parts, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output = res.stdout
        if txt_path:
            try:
                with open(txt_path, "w", encoding="utf-8") as f:
                    f.write(output)
            except Exception:
                pass
        return output
    except KeyboardInterrupt:
        print(Fore.CYAN + "\nScan abgebrochen." + Style.RESET_ALL)
        return ""

# -----------------------
# Parse utilities
# -----------------------
def extract_ips_from_nmap_output(output: str):
    found = re.findall(r"Nmap scan report for ([\w\.\:\-]+)", output)
    seen = []
    for ip in found:
        if ip not in seen:
            seen.append(ip)
    return seen

def extract_ssh_lines(output: str):
    return [ln.strip() for ln in output.splitlines() if re.search(r"\bssh\b", ln, re.IGNORECASE) or "OpenSSH" in ln]

# -----------------------
# Grepable parsing: live hosts only
# -----------------------
def extract_live_ips_from_grepable(output: str):
    ips = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.search(r"Host:\s*([\d\.]+)\s*(?:\(([^\)]*)\))?\s*Status:\s*(\w+)", line, re.IGNORECASE)
        if m:
            ip = m.group(1)
            status = m.group(3).lower()
            if status.startswith("up"):
                ips.append(ip)
            continue
        if "status:" in line.lower() and "up" in line.lower():
            ip_m = re.search(r"([\d]+\.[\d]+\.[\d]+\.[\d]+)", line)
            if ip_m:
                ips.append(ip_m.group(1))
    return list(dict.fromkeys(ips))

# -----------------------
# Cached + parallel reverse DNS
# -----------------------
@lru_cache(maxsize=2048)
def _resolve_cached(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip

def resolve_hostnames_parallel(ips, max_workers=16):
    results = {}
    if not ips:
        return results
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ips))) as ex:
        future_to_ip = {ex.submit(_resolve_cached, ip): ip for ip in ips}
        for fut in as_completed(future_to_ip):
            ip = future_to_ip[fut]
            try:
                results[ip] = fut.result()
            except Exception:
                results[ip] = ip
    return results

# -----------------------
# Interactive helpers
# -----------------------
def print_header():
    os.system("cls" if os.name == "nt" else "clear")
    print(Fore.CYAN + f"Nmap Ultimate Tool {VERSION} — by Thomas Rau 2025-10-20" + Style.RESET_ALL)
    print("Scan-Logs: " + os.path.abspath(SCAN_DIR))
    print("-" * 60)

def ask_targets(prompt="Ziele eingeben (IP oder CIDR, Komma getrennt): "):
    s = input(prompt).strip()
    if not s:
        return []
    return [t.strip() for t in re.split(r"[,\s]+", s) if t.strip()]

def choose_timing_interactive():
    print("\nT0..T5 (Timing Templates):")
    print(" 0) T0 Paranoid  1) T1 Sneaky  2) T2 Polite  3) T3 Normal  4) T4 Aggressive  5) T5 Insane")
    s = input("Wähle 0..5 oder Enter für T3: ").strip()
    if s in ["0","1","2","3","4","5"]:
        return f"-T{s}"
    return "-T3"

def ping_sweep_table(ip_range: str):
    hosts_up = []
    try:
        net = ipaddress.ip_network(ip_range, strict=False)
    except Exception:
        print(Fore.RED + "Ungültiger Bereich." + Style.RESET_ALL)
        return hosts_up

    param_count = "-n" if platform.system().lower() == "windows" else "-c"
    param_wait = "-W" if platform.system().lower() != "windows" else "-w"

    print(Fore.CYAN + f"Starte Ping Sweep für {ip_range}..." + Style.RESET_ALL)
    print(f"{'IP':15} | {'Hostname':30} | RTT")
    print("-" * 60)
    for ip in net.hosts():
        ip_s = str(ip)
        try:
            res = subprocess.run(["ping", param_count, "1", param_wait, "1", ip_s],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
            out = res.stdout
            if res.returncode == 0 and ("bytes from" in out or "ttl=" in out):
                m = re.search(r"time[=<]?([\d\.]+)\s*ms", out)
                rtt = f"{m.group(1)} ms" if m else "-"
                hn = _resolve_cached(ip_s)
                print(Fore.GREEN + f"{ip_s:15} | {hn:30} | {rtt}" + Style.RESET_ALL)
                hosts_up.append({"ip": ip_s, "hostname": hn, "rtt": rtt})
            else:
                print(Fore.RED + f"{ip_s:15} | {'-':30} | -" + Style.RESET_ALL)
        except subprocess.TimeoutExpired:
            print(Fore.RED + f"{ip_s:15} | {'-':30} | timeout" + Style.RESET_ALL)
    return hosts_up

# -----------------------
# Menu handler (all options implemented)
# -----------------------
def print_menu():
    print_header()
    for k, v in MENU:
        print(f"{k}) {v}")
    print()

def handle_menu_choice():
    ensure_scan_folder()
    while True:
        print_menu()
        choice = input("Deine Wahl > ").strip()

        if choice == "0":
            print(Fore.CYAN + "Programm beendet. Bis zum nächsten Scan!" + Style.RESET_ALL)
            return

        # 1 - Quick (profile 'schnell')
        if choice == "1":
            targets = ask_targets()
            if not targets:
                print(Fore.RED + "Keine Ziele angegeben." + Style.RESET_ALL)
                input("Enter zum Fortfahren...")
                continue
            for t in targets:
                txt, xml = make_paths(t, "quick")
                opts = PROFILES["schnell"]
                if "/" in t:
                    out = run_nmap_grepable(t, "-sn -T4", txt)
                    ips = extract_live_ips_from_grepable(out)
                    hn_map = resolve_hostnames_parallel(ips)
                    print(Fore.CYAN + f"Gefundene Live-Hosts: {len(ips)}" + Style.RESET_ALL)
                    for ip in ips:
                        print(f" - {ip:15} Hostname: {hn_map.get(ip, ip)}")
                else:
                    out = run_nmap_stream(t, opts, txt, live_progress=False)
                    for ln in out.splitlines():
                        print(color_port_line(ln))
                print(Fore.CYAN + f"Ergebnis gespeichert: {txt}" + Style.RESET_ALL)
            input("Enter zum Fortfahren...")
            continue

        # 2 - Versionsscan (-sV) with progress bar
        if choice == "2":
            targets = ask_targets()
            if not targets:
                print(Fore.RED + "Keine Ziele angegeben." + Style.RESET_ALL)
                input("Enter zum Fortfahren...")
                continue
            for t in targets:
                txt, xml = make_paths(t, "version")
                opts = "-sV -T4"
                out = run_nmap_stream(t, opts, txt, live_progress=True)
                for ln in out.splitlines():
                    print(color_port_line(ln))
                print(Fore.CYAN + f"Ergebnis gespeichert: {txt}" + Style.RESET_ALL)
            input("Enter zum Fortfahren...")
            continue

        # 3 - OS detection (-O) with timing
        if choice == "3":
            targets = ask_targets()
            if not targets:
                print(Fore.RED + "Keine Ziele angegeben." + Style.RESET_ALL)
                input("Enter zum Fortfahren...")
                continue
            timing = choose_timing_interactive()
            for t in targets:
                txt, xml = make_paths(t, "os")
                opts = f"-O {timing}"
                out = run_nmap_stream(t, opts, txt, live_progress=True)
                for ln in out.splitlines():
                    print(color_port_line(ln))
                print(Fore.CYAN + f"Ergebnis gespeichert: {txt}" + Style.RESET_ALL)
            input("Enter zum Fortfahren...")
            continue

        # 4 - Ping sweep (ICMP) table
        if choice == "4":
            ipr = input("Adressbereich (z. B. 192.168.1.0/24): ").strip()
            if not ipr:
                continue
            hosts = ping_sweep_table(ipr)
            if hosts:
                txt, _ = make_paths(ipr, "pingsweep")
                try:
                    with open(txt, "w", encoding="utf-8") as f:
                        f.write("IP\tHostname\tRTT\n")
                        for h in hosts:
                            f.write(f"{h['ip']}\t{h['hostname']}\t{h['rtt']}\n")
                    print(Fore.CYAN + f"Ping Sweep saved: {txt}" + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"Fehler beim Speichern: {e}" + Style.RESET_ALL)
            input("Enter zum Fortfahren...")
            continue

        # 5 - Custom
        if choice == "5":
            targets = ask_targets()
            if not targets:
                print(Fore.RED + "Keine Ziele angegeben." + Style.RESET_ALL)
                input("Enter zum Fortfahren...")
                continue
            ports = input("Ports angeben (z. B. 80,443 oder 1-65535) oder Enter für Top-200: ").strip()
            prof = input("Profil wählen (schnell/tief/aggressiv/paranoid) oder Enter für 'schnell': ").strip()
            if prof not in PROFILES:
                prof = "schnell"
            timing = ""
            use_timing = input("Timing wählen (T0..T5) ? (j/N): ").strip().lower()
            if use_timing == "j":
                timing = choose_timing_interactive()
            for t in targets:
                label = f"custom_{prof}"
                txt, xml = make_paths(t, label)
                base = PROFILES[prof]
                if ports:
                    opts = f"-p {ports} {base} {timing}".strip()
                else:
                    opts = f"{base} {timing}".strip()
                out = run_nmap_stream(t, opts, txt, live_progress=True)
                for ln in out.splitlines():
                    print(color_port_line(ln))
                print(Fore.CYAN + f"Ergebnis gespeichert: {txt}" + Style.RESET_ALL)
            input("Enter zum Fortfahren...")
            continue

        # 6 - All-hosts (Host discovery) - use grepable to get Status: Up
        if choice == "6":
            net = input("Netzwerk (z. B. 192.168.1.0/24): ").strip()
            if not net:
                continue
            txt, xml = make_paths(net, "allhosts")
            out = run_nmap_grepable(net, "-sn -T4", txt)
            ips = extract_live_ips_from_grepable(out)
            hn_map = resolve_hostnames_parallel(ips)
            print(Fore.CYAN + f"Gefundene Live-Hosts: {len(ips)}" + Style.RESET_ALL)
            for ip in ips:
                print(f" - {ip:15} Hostname: {hn_map.get(ip, ip)}")
            print(Fore.CYAN + f"Logs: {txt}" + Style.RESET_ALL)
            input("Enter zum Fortfahren...")
            continue

        # 7 - Stealth
        if choice == "7":
            targets = ask_targets()
            if not targets:
                input("Enter zum Fortfahren...")
                continue
            timing = choose_timing_interactive()
            for t in targets:
                txt, xml = make_paths(t, "stealth")
                opts = f"-sS --top-ports 200 {timing}"
                out = run_nmap_stream(t, opts, txt, live_progress=True)
                for ln in out.splitlines():
                    print(color_port_line(ln))
                print(Fore.CYAN + f"Ergebnis: {txt}" + Style.RESET_ALL)
            input("Enter zum Fortfahren...")
            continue

        # 8 - Aggressive
        if choice == "8":
            targets = ask_targets()
            if not targets:
                input("Enter zum Fortfahren...")
                continue
            timing = choose_timing_interactive()
            for t in targets:
                txt, xml = make_paths(t, "aggressive")
                opts = f"-A {timing}"
                out = run_nmap_stream(t, opts, txt, live_progress=True)
                for ln in out.splitlines():
                    print(color_port_line(ln))
                print(Fore.CYAN + f"Ergebnis: {txt}" + Style.RESET_ALL)
            input("Enter zum Fortfahren...")
            continue

        # 9 - SSH versions (filter)
        if choice == "9":
            targets = ask_targets()
            if not targets:
                input("Enter zum Fortfahren...")
                continue
            for t in targets:
                txt, xml = make_paths(t, "ssh_versions")
                opts = "-sV -p 22 -T4"
                out = run_nmap_stream(t, opts, txt, live_progress=True)
                ssh = extract_ssh_lines(out)
                if ssh:
                    print(Fore.GREEN + "Gefundene SSH-Infos:" + Style.RESET_ALL)
                    for ln in ssh:
                        print("  " + ln)
                else:
                    print(Fore.YELLOW + "Keine SSH-Infos gefunden." + Style.RESET_ALL)
                print(Fore.CYAN + f"Ergebnis: {txt}" + Style.RESET_ALL)
            input("Enter zum Fortfahren...")
            continue

        # u - UDP Scan (Top-200 default; optional custom ports; optional -sV)
        if choice.lower() == "u":
            targets = ask_targets("Ziele eingeben (IP, CIDR oder Hostname, Komma getrennt): ")
            if not targets:
                print(Fore.RED + "Keine Ziele angegeben." + Style.RESET_ALL)
                input("Enter zum Fortfahren...")
                continue

            # Default Top-200; allow custom ports but do NOT offer full 1-65535 prompt
            ports_input = input("Ports für UDP-Scan angeben (z. B. 53,161 oder 1-1024). Enter = Top-200: ").strip()
            if not ports_input:
                port_spec = "--top-ports 200"
            else:
                port_spec = f"-p {ports_input}"

            # Timing selection
            timing = ""
            use_timing = input("Timing wählen (T0..T5) ? (j/N): ").strip().lower()
            if use_timing == "j":
                timing = choose_timing_interactive()

            # Ask whether to enable -sV for UDP (optional, default off)
            use_sV = input("UDP Versionsscan (-sV) aktivieren? (empfohlen aus) [j/N]: ").strip().lower()
            sv_flag = ""
            if use_sV == "j":
                sv_flag = "-sV"

            base_opts = f"-sU {port_spec} {sv_flag} {timing}".strip()

            for t in targets:
                label = f"udp"
                txt, xml = make_paths(t, label)
                # include xml output
                opts = f"{base_opts} -oX {shlex.quote(xml)}"
                out = run_nmap_stream(t, opts, txt, live_progress=True)
                for ln in out.splitlines():
                    print(color_port_line(ln))
                print(Fore.CYAN + f"Ergebnis gespeichert: {txt} | {xml}" + Style.RESET_ALL)
            input("Enter zum Fortfahren...")
            continue

        print(Fore.RED + "Unbekannte Option." + Style.RESET_ALL)
        input("Enter zum Fortfahren...")

# -----------------------
# Entrypoint
# -----------------------
def main():
    check_nmap()
    ensure_scan_folder()
    try:
        handle_menu_choice()
    except KeyboardInterrupt:
        print(Fore.CYAN + "\nProgramm beendet. Bis zum nächsten Scan." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + "Unerwarteter Fehler:\n" + str(e) + Style.RESET_ALL)
        traceback.print_exc()

if __name__ == "__main__":
    main()
