# PyADRecon on Windows

This guide explains how to run **PyADRecon** on Windows, either via the provided **`pyadrecon.exe`** or locally via **Python** (and how to build your own `.exe`).

---

## Quick Start (pyadrecon.exe)

If you use the provided `pyadrecon.exe`, you can run it directly (no Python required).

### NTLM example

```powershell
.\pyadrecon.exe -dc 10.10.10.10 -d vulnad.local -u john -p "P@ssw0rd"
```

### Kerberos (SSPI) example

Kerberos on Windows requires:
- DC **hostname/FQDN** (not IP)
- Existing tickets in the current logon session (`klist`)

```powershell
.\pyadrecon.exe -dc dc1.vulnad.local -d vulnad.local -u john --auth kerberos
```

---

## Kerberos Tickets on Windows (SSPI)

### Check existing tickets

```powershell
klist
```

If you see `krbtgt/<REALM>` (example: `krbtgt/VULNAD.LOCAL`), you have a TGT.

### Unjoined computer (recommended workflow)

If your Windows machine is **not** domain-joined, create a logon session with domain credentials:

```powershell
runas.exe /netonly /noprofile /user:VULNAD\john "powershell.exe -ep bypass"
```

In the new PowerShell window, request Kerberos tickets by accessing a domain resource:

```powershell
dir \\dc1.vulnad.local\NETLOGON
klist
```

Now run PyADRecon from the same window:

```powershell
.\pyadrecon.exe -dc dc1.vulnad.local -d vulnad.local -u john --auth kerberos
```

---

## Requirements

- Windows 10/11 / Windows Server
- Network access to the Domain Controller:
  - LDAP: `389/TCP`
  - LDAPS: `636/TCP` (recommended)
  - Kerberos: `88/TCP` + `88/UDP` (required for Kerberos auth)
  - DNS: `53/TCP` + `53/UDP` (required for reliable AD name resolution / Kerberos SPNs)
- Working DNS resolution for the DC hostname/FQDN (Kerberos requires SPNs like `ldap/dc1.vulnad.local`)
- Time sync within a few minutes between client and DC (Kerberos is time-sensitive)

---

## Run locally with Python (for development / custom builds)

### CAUTION

> [!CAUTION]
> Antivirus / EDR solutions may flag **impacket** (and tools that include it).  
> If you run locally for development/testing, do so in a controlled environment and with appropriate approvals.

### Installation

#### 1) Install Python

Install Python 3.11 (x64) and verify:

```powershell
winget install -e --id Python.Python.3.11
py -V
py -V:3.11 -c "import sys; print(sys.version)"
```

#### 2) Clone the repository

```powershell
cd C:\Temp
git clone https://github.com/l4rm4nd/PyADRecon.git
cd PyADRecon
```

#### 3) Create and activate a virtual environment

```powershell
py -V:3.11 -m venv .venv
.\.venv\Scripts\activate
python -m pip install -U pip setuptools wheel
```

#### 4) Install dependencies

Using `requirements.txt`:

```powershell
python -m pip install -r .\requirements.txt
```

Or install from `pyproject.toml`:

```powershell
python -m pip install .
```

> [!CAUTION]
> Antivirus / EDR solutions may flag **impacket** and brick the installation.  

### Run (Python)

NTLM:

```powershell
python .\pyadrecon.py -dc 10.10.10.10 -d vulnad.local -u john -p "P@ssw0rd"
```

Kerberos (SSPI):

```powershell
python .\pyadrecon.py -dc dc1.vulnad.local -d vulnad.local -u john --auth kerberos
```

---

## Build your own pyadrecon.exe (PyInstaller)

### 1) Install PyInstaller

```powershell
.\.venv\Scripts\activate
python -m pip install -U pyinstaller
```

### 2) Build

Single-file executable:

```powershell
pyinstaller --onefile --name pyadrecon --clean pyadrecon.py
```

Output:

- `dist\pyadrecon.exe`

Test:

```powershell
.\dist\pyadrecon.exe --help
```
---

## Common Pitfalls

### Kerberos fails when using an IP address

Kerberos requires an SPN for the DC hostname (example: `ldap/dc1.vulnad.local`). Use:

```powershell
.\pyadrecon.exe -dc dc1.vulnad.local -d vulnad.local -u john --auth kerberos
```

(or the same with `python .\pyadrecon.py ...`)

### No tickets in `klist`

Trigger ticket acquisition:

```powershell
dir \\dc1.vulnad.local\NETLOGON
klist
```

### DNS resolution

If `dc1.vulnad.local` does not resolve, fix DNS (use AD DNS/DC) or add a hosts entry:

`C:\Windows\System32\drivers\etc\hosts`

```text
10.10.10.10 dc1.vulnad.local dc1
```

---

## Output

PyADRecon creates an output directory like:

- `PyADRecon-Report-YYYYMMDDHHMMSS\`

It writes:

- CSV files per module
- An Excel report (unless `--no-excel` is set)

---

## Help

Show all options:

```powershell
.\pyadrecon.exe --help
# or
python .\pyadrecon.py --help
```
