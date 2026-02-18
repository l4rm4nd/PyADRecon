<img src="https://raw.githubusercontent.com/l4rm4nd/PyADRecon/refs/heads/main/.github/pyadrecon.png" alt="pyadrecon" width="300"/>

Python3 implementation of an improved [ADRecon](https://github.com/sense-of-security/ADRecon) for Pentesters and Blue Teams. 

> ADRecon is a tool which gathers information about MS Active Directory and generates an XSLX report to provide a holistic picture of the current state of the target AD environment.

> [!TIP]
> If you are a Red Team, may check out [ADRecon-ADWS](https://github.com/l4rm4nd/PyADRecon-ADWS) instead.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Docker](#docker)
- [Collection Modules](#collection-modules)
- [Acknowledgements](#acknowledgements)
- [License](#license)

## Installation

````bash
# stable release from pypi
pipx install pyadrecon

# latest commit from github
pipx install git+https://github.com/l4rm4nd/PyADRecon
````

Then verify installation:

````bash
pyadrecon --version
````

> [!TIP]
> For Windows, a standalone executable is provided. Look [here](https://github.com/l4rm4nd/PyADRecon/tree/main/windows).

## Usage

````py
usage: pyadrecon.py [-h] [--version] [--generate-excel-from CSV_DIR] [-dc DOMAIN_CONTROLLER] [-u USERNAME] [-p [PASSWORD]] [-d DOMAIN] [--auth {ntlm,kerberos}] [--tgt-file TGT_FILE] [--tgt-base64 TGT_BASE64]
                    [--ssl] [--port PORT] [-o OUTPUT] [--page-size PAGE_SIZE] [--threads THREADS] [--dormant-days DORMANT_DAYS] [--password-age PASSWORD_AGE] [--only-enabled] [--collect COLLECT]
                    [--no-excel] [-v]

PyADRecon - Python Active Directory Reconnaissance Tool

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit  
  --generate-excel-from CSV_DIR
                        Generate Excel report from CSV directory (standalone mode, no AD connection needed)
  -dc, --domain-controller DOMAIN_CONTROLLER
                        Domain Controller IP or hostname
  -u, --username USERNAME
                        Username for authentication
  -p, --password [PASSWORD]
                        Password for authentication (optional if using TGT)
  -d, --domain DOMAIN   Domain name (e.g., DOMAIN.LOCAL) - Required for Kerberos auth
  --auth {ntlm,kerberos}
                        Authentication method (default: ntlm)
  --tgt-file TGT_FILE   Path to Kerberos TGT ccache file (for Kerberos auth)
  --tgt-base64 TGT_BASE64
                        Base64-encoded Kerberos TGT ccache (for Kerberos auth)
  --ssl                 Force SSL/TLS (LDAPS). No LDAP fallback allowed.
  --port PORT           LDAP port (default: 389, use 636 for LDAPS)
  -o, --output OUTPUT   Output directory (default: PyADRecon-Report-<timestamp>)
  --page-size PAGE_SIZE
                        LDAP page size (default: 500)
  --dormant-days DORMANT_DAYS
                        Days for dormant account threshold (default: 90)
  --password-age PASSWORD_AGE
                        Days for password age threshold (default: 180)
  --only-enabled        Only collect enabled objects
  --collect COLLECT     Comma-separated modules to collect (default: all)
  --workstation WORKSTATION
                        Explicitly spoof workstation name for NTLM authentication (default: empty string, bypasses userWorkstations restrictions)  
  --no-excel            Skip Excel report generation
  -v, --verbose         Verbose output

Examples:
  # Basic usage with NTLM authentication
  pyadrecon.py -dc 192.168.1.1 -u admin -p password123 -d DOMAIN.LOCAL

  # With Kerberos authentication (bypasses channel binding)
  pyadrecon.py -dc dc01.domain.local -u admin -p password123 -d DOMAIN.LOCAL --auth kerberos

  # With Kerberos using TGT from file (bypasses channel binding)
  pyadrecon.py -dc dc01.domain.local -u admin -d DOMAIN.LOCAL --auth kerberos --tgt-file /tmp/admin.ccache

  # With Kerberos using TGT from base64 string (bypasses channel binding)
  pyadrecon.py -dc dc01.domain.local -u admin -d DOMAIN.LOCAL --auth kerberos --tgt-base64 BQQAAAw...

  # Only collect specific modules
  pyadrecon.py -dc 192.168.1.1 -u admin -p pass -d DOMAIN.LOCAL --collect users,groups,computers

  # Output to specific directory
  pyadrecon.py -dc 192.168.1.1 -u admin -p pass -d DOMAIN.LOCAL -o /tmp/adrecon_output

  # Generate Excel report from existing CSV files (standalone mode)
  pyadrecon.py --generate-excel-from /path/to/CSV-Files -o report.xlsx
````

>[!TIP]
>PyADRecon always tries LDAPS on TCP/636 first.
>
>If flag `--ssl` is not used, LDAP on TCP/389 may be tried as fallback.

>[!WARNING]
>If LDAP channel binding is enabled, this script will fail with `automatic bind not successful - strongerAuthRequired`, as ldap3 does not support it (see [here](https://github.com/cannatag/ldap3/issues/1049#issuecomment-1222826803)). You must use Kerberos authentication instead.
>
>If you use Kerberos auth under Linux, please create a valid `/etc/krb5.conf` and DC hostname entry in `/etc/hosts`. May read [this](https://cwiki.apache.org/confluence/pages/viewpage.action?pageId=32628#KerberosClientConfiguration-*NIX/etc/krb5.confConfiguration). If you are on Windows, please make sure you have valid Kerberos tickets. May read [this](https://github.com/l4rm4nd/PyADRecon/tree/main/windows#kerberos-authentication). Note that you can provide an already existing TGT ticket to the script via `--tgt-file` or `--tgt-base64`. For example, obtained by Netexec via `netexec smb <TARGET> <ARGS> --generate-tgt <FILEMAME>`.

## Docker

There is also a Docker image available on GHCR.IO.

````
docker run --rm -v /etc/krb5.conf:/etc/krb5.conf:ro -v /etc/hosts:/etc/hosts:ro -v ./:/tmp/pyadrecon_output ghcr.io/l4rm4nd/pyadrecon:latest -dc dc01.domain.local -u admin -p password123 -d DOMAIN.LOCAL -o /tmp/pyadrecon_output
````

## Collection Modules

As default, PyADRecon runs all collection modules. They are referenced to as `default` or `all`.

Though, you can freely select your own collection of modules to run:

| Icon | Meaning |
|------|---------|
| 🛑 | Requires administrative domain privileges (e.g. Domain Admins) |
| ✅ | Requires regular domain privileges (e.g. Authenticated Users) |
| 💥 | New collection modul in beta state. Results may be incorrect. |

**Forest & Domain**
- `forest` ✅
- `domain` ✅
- `trusts` ✅
- `sites` ✅
- `subnets` ✅
- `schema` or `schemahistory` ✅

**Domain Controllers**
- `dcs` or `domaincontrollers` ✅

**Users & Groups**
- `users` ✅
- `userspns` ✅
- `groups` ✅
- `groupmembers` ✅
- `protectedgroups` ✅💥
- `krbtgt` ✅
- `asreproastable` ✅
- `kerberoastable` ✅

**Computers & Printers**
- `computers` ✅
- `computerspns` ✅
- `printers` ✅

**OUs & Group Policy**
- `ous` ✅
- `gpos` ✅
- `gplinks` ✅

**Passwords & Credentials**
- `passwordpolicy` ✅
- `fgpp` or `finegrainedpasswordpolicy` 🛑
- `laps` 🛑
- `bitlocker` 🛑

**Managed Service Accounts**
- `gmsa` or `groupmanagedserviceaccounts` ✅💥
- `dmsa` or `delegatedmanagedserviceaccounts` ✅💥
  - Only works for Windows Server 2025+ AD schema

**Certificates**
- `adcs` or `certificates` ✅💥
  - Detects ESC1, ESC2, ESC3, ESC4 and ESC9

**DNS**
- `dnszones` ✅
- `dnsrecords` ✅

## Acknowledgements

Many thanks to the following folks:
 - [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t) for a first Claude draft of this Python3 port 
- [Sense-of-Security](https://github.com/sense-of-security) for the original ADRecon script in PowerShell
- [cannatag](https://github.com/cannatag) for the awesome ldap3 Python client
- [Forta](https://github.com/fortra) for the awesome impacket suite
- [Anthropic](https://github.com/anthropics) for Claude LLMs

## License

**PyADRecon** is released under the **MIT License**.

The following third-party libraries are used:

| Library     | License        |
|-------------|----------------|
| ldap3       | LGPL v3        |
| openpyxl    | MIT            |
| gssapi      | MIT            |
| impacket    | Apache 2.0     |
| winkerberos | Apache 2.0     |

Please refer to the respective licenses of these libraries when using or redistributing this software.
