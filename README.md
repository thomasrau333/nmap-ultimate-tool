# Nmap Ultimate Tool — v7.0

**Autor:** Thomas Rau
**Version:** v7.0 (2025-10-20)  
**Beschreibung:**  

⚠️ WICHTIG — Rechtliche & ethische Nutzung
Dieses Tool darf ausschließlich **in privaten Prüf‑/Laborumgebungen** oder **in Netzwerken, für die Sie eine schriftliche Erlaubnis** 
(z. B. ausdrückliche Einwilligung des Eigentümers/Betreibers) besitzen, verwendet werden. 
Jeglicher nicht autorisierte Einsatz in fremden Netzen ist untersagt und kann rechtliche Folgen haben.

Dieses Tool bietet eine erweiterte, interaktive Oberfläche für Nmap. 
Es umfasst schnelle Portscans, Versionsscans, OS-Erkennung, Ping Sweeps, All-Hosts Discovery, Stealth Scans, aggressive Scans, SSH-Versionserkennung und einen neuen UDP-Scan auf Standard-Top-Ports. 
Alle Menüfunktionen laufen interaktiv, mit Fortschrittsbalken und optionaler Reverse-DNS Auflösung.

---

# Start: 

Im Programm‑Ordner mit Root‑Rechten starten: sudo python3 nmap_toolv7.0.py

---
## getestet unter Umgebung:

OS: Debian GNU/Linux 13 (trixie) x86_64
Kernel: Linux 6.12.48+deb13-amd64
Shell version bash 5.2.37
Nmap version 7.95 ( https://nmap.org )
Python3 version 3.13.5
colorama version 0.4.6



---

## Features

- **Alle Menüfunktionen 1–9** wie in Nmap Ultimate Tool v7.0 beschrieben.  
- **Option 6 (All-Hosts)** zeigt nur erreichbare Hosts (Status: Up).  
- **Fortschrittsbalken** für Versions- und OS-Scan.  
- **Reverse DNS Auflösung** parallel + gecached.  
- **UDP-Scan** auf Top-Ports verfügbar über Menüpunkt `u`.  
- **Keine Versionsnummeränderung** nötig.  

---

## Voraussetzungen / Benötigte Pakete

Das Tool läuft unter Python3 version 3.13.5 und benötigt folgende Pakete:

- `colorama` — für farbige Terminalausgabe  

Installieren mit:

```bash
sudo apt update
sudo apt install python3-pip nmap
pip3 install colorama


