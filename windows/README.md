# PyADRecon on Windows

A guide for running **PyADRecon** on Windows systems using either the pre-built executable or Python.

---

## Table of Contents

- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
  - [Using Pre-built Executable](#using-pre-built-executable)
  - [Running with Python](#running-with-python)
  - [Building Your Own Executable](#building-your-own-executable)
- [Output](#output)
- [Troubleshooting](#troubleshooting)
- [Help](#help)

---

## Requirements

### System Requirements
- Windows 10/11 or Windows Server
- Python 3.11 (x64) - only if running from source

### Network Requirements

The following ports must be accessible on the Domain Controller:

| Service | Port | Protocol | Required For |
|---------|------|----------|--------------|
| LDAP | 389 | TCP | Unencrypted LDAP (as fall-back) |
| LDAPS | 636 | TCP | Encrypted LDAP (recommended) |
| Kerberos | 88 | TCP/UDP | Kerberos authentication |
| DNS | 53 | TCP/UDP | Name resolution / Kerberos SPNs |

### Additional Requirements
- Working DNS resolution for DC hostname/FQDN
- Time synchronization between client and DC (within a few minutes for Kerberos)

---

## Quick Start

### Using the pre-built executable

#### NTLM Authentication
```powershell
.\pyadrecon.exe -dc 10.10.10.10 -d vulnad.local -u john -p "P@ssw0rd"
```

> [!NOTE]
> NTLM authentication works with DC IP addresses or hostnames.

#### Kerberos Authentication
```powershell
.\pyadrecon.exe -dc dc1.vulnad.local -d vulnad.local -u john --auth kerberos
```

> [!WARNING]
> Kerberos authentication requires:
> - DC hostname or FQDN (not IP address)
> - Valid Kerberos ticket in the current logon session

**Check for existing tickets:**

```powershell
klist
```

Look for `krbtgt/<REALM>` (e.g., `krbtgt/VULNAD.LOCAL`) to confirm you have a TGT.

**Workflow for non-domain-joined computers:**

If your Windows machine is **not** domain-joined, follow these steps:

1. Create a logon session with domain credentials:
```powershell
runas.exe /netonly /noprofile /user:VULNAD\john "powershell.exe -ep bypass"
```

2. In the new PowerShell window, request Kerberos tickets:
```powershell
dir \\dc1.vulnad.local\NETLOGON
klist
```

3. Run PyADRecon from the same window:
```powershell
.\pyadrecon.exe -dc dc1.vulnad.local -d vulnad.local -u john --auth kerberos
```

---

## Installation Methods

### Using Pre-built Executable

No installation required. Simply download and run `pyadrecon.exe`.

See [Quick Start](#quick-start) for usage examples.

---

### Running with Python

For development, testing, or custom builds.

> [!CAUTION]
> Antivirus/EDR solutions may flag **impacket** and related tools. Only run in controlled environments with appropriate approvals.

#### Step 1: Install Python

```powershell
winget install -e --id Python.Python.3.11
```

Verify installation:
```powershell
py -V
py -V:3.11 -c "import sys; print(sys.version)"
```

#### Step 2: Clone the repository

```powershell
cd C:\Temp
git clone https://github.com/l4rm4nd/PyADRecon.git
cd PyADRecon
```

#### Step 3: Create virtual environment

```powershell
py -V:3.11 -m venv .venv
.\.venv\Scripts\activate
python -m pip install -U pip setuptools wheel
```

#### Step 4: Install dependencies

Using `requirements.txt`:
```powershell
python -m pip install -r .\requirements.txt
```

Or from `pyproject.toml`:
```powershell
python -m pip install .
```

> [!CAUTION]
> Antivirus/EDR may block the installation of **impacket**.

#### Step 5: Run PyADRecon

**NTLM:**
```powershell
python .\pyadrecon.py -dc 10.10.10.10 -d vulnad.local -u john -p "P@ssw0rd"
```

**Kerberos:**
```powershell
python .\pyadrecon.py -dc dc1.vulnad.local -d vulnad.local -u john --auth kerberos
```

---

### Building Your Own Executable

Use PyInstaller to create a standalone executable.

#### Step 1: Install PyInstaller

```powershell
.\.venv\Scripts\activate
python -m pip install -U pyinstaller
```

#### Step 2: Build the executable

```powershell
pyinstaller --onefile --name pyadrecon --clean pyadrecon.py
```

#### Step 3: Test the executable

Output location: `dist\pyadrecon.exe`

```powershell
.\dist\pyadrecon.exe --help
```

---

## Output

PyADRecon generates a timestamped output directory:

```
PyADRecon-Report-YYYYMMDDHHMMSS\
```

Contents:
- CSV files for each module
- Excel report (unless `--no-excel` is specified)

---

## Troubleshooting

### Kerberos fails when using an IP address

**Problem:** Kerberos requires an SPN based on the DC hostname (e.g., `ldap/dc1.vulnad.local`).

**Solution:** Use the DC hostname or FQDN instead of an IP address:
```powershell
.\pyadrecon.exe -dc dc1.vulnad.local -d vulnad.local -u john --auth kerberos
```

---

### No tickets in `klist`

**Problem:** No Kerberos tickets are cached.

**Solution:** Trigger ticket acquisition by accessing a domain resource:
```powershell
dir \\dc1.vulnad.local\NETLOGON
klist
```

---

### DNS resolution fails

**Problem:** The DC hostname does not resolve.

**Solutions:**

1. Configure your DNS to use the AD DNS server/DC
2. Add a hosts file entry:

Edit `C:\Windows\System32\drivers\etc\hosts`:
```text
10.10.10.10 dc1.vulnad.local dc1
```

---

## Help

Display all available options:

```powershell
.\pyadrecon.exe --help
```

Or with Python:
```powershell
python .\pyadrecon.py --help
```
