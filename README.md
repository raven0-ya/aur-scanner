# aur-scanner

A stateless, read-only forensics and audit shell script designed to scan Arch Linux systems for compromised AUR and npm packages related to the June 2026 supply chain attacks.

[![Platform: Arch Linux](https://img.shields.io/badge/Platform-Arch%20Linux-033a5e.svg?logo=arch-linux)](https://archlinux.org)

## Overview

`aur-scanner` is a lightweight, non-intrusive forensic utility built specifically for Arch Linux. Following the June 2026 supply chain and typosquatting campaign that targeted the Arch User Repository (AUR) and npm ecosystems, this tool was designed to help administrators quickly audit their systems without leaving a heavy footprint.

The core philosophy of this tool is to be **completely stateless and read-only**. It does not install any background services, modify system configurations, or deploy a persistent database. Everything is processed dynamically in memory (RAM) and volatile storage (`/tmp`).

## Key Features

1. **Compromised Package Auditing:** Matches installed system packages (specifically foreign/AUR packages) against real-time consolidated blacklists from official security notices and community tracking.
2. **Package File Integrity Verification:** Leverages `pacman -Qkk` parsing to identify modified, missing, or unauthorized alterations to officially managed binaries and files.
3. **Malware Indicator Scanning:** - Inspects `/sys/fs/bpf/` for hidden BPF maps (`hidden_pids`, `hidden_names`, etc.) pointing to modern eBPF rootkits.
   - Scans systemd directory trees for unauthorized persistence models utilizing `Restart=always` with binaries executing from `/var/lib/`, `/dev/shm/`, or `/tmp/`.
   - Audits unusual SUID binaries not owned by any legitimate pacman package.
4. **Language Ecosystem Cache Auditing:** Scans local and global `npm` and `bun` package caches for atomic-lockfile campaign indicators (e.g., `atomic-lockfile`, `lockfile-js`, `js-digest`).
5. **Static Metadata Analysis:** Analyzes stored pacman install scriptlets (`/var/lib/pacman/local/`) for high-risk patterns (`curl|bash`, reverse shells, unauthorized SUID modifications) and known attacker/maintainer account handles.
6. **System Anomaly Scans:** Checks active crontabs, temporary directories, known malicious binary signatures (`deps`), and critical system configuration modifications within a 24-hour window.

## Intelligence Sources

This scanner relies on a dual-layer approach: fetching dynamic remote threat feeds or falling back to a curated embedded list of over 500+ malicious indicators. Remote data sources include:
* Arch Linux Official AUR Security Notice (HedgeDoc Hub)
* `lenucksi/aur-malware-check` community-consolidated indicator registry
* Verified community incident response pastes (`cscs.pastes.sh`)

---

## Installation & Usage

Since this is a portable standalone script, no installation is required.
Use `./arch-scan.sh --help` to see all options.

### Quick Start

Clone the repository and execute a standard scan:

```bash
git clone https://github.com/raven0-ya/aur-scanner.git
cd aur-scanner
chmod +x arch-scan.sh
./arch-scan.sh
