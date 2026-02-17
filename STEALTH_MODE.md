# Stealth Mode - EDR Evasion

## Overview

PyADRecon now includes a **Stealth Mode** that helps evade detection by EDR (Endpoint Detection and Response) solutions when collecting Active Directory data via LDAP. Instead of making obvious bulk queries that trigger alerts, stealth mode mimics the behavior of legitimate administrative tools like **Microsoft ADExplorer**.

## Why Stealth Mode?

Traditional AD reconnaissance tools make large, single LDAP queries like:
- `(&(objectCategory=person)(objectClass=user))` → Returns ALL users at once
- `(objectCategory=computer)` → Returns ALL computers at once

These bulk queries are suspicious and often flagged by EDR solutions because:
1. They retrieve thousands of objects in a single request
2. They use generic filters without any targeting
3. They complete too quickly for "normal" admin activity
4. They don't match how legitimate admin tools behave

## How Stealth Mode Works

When enabled, PyADRecon implements several techniques to appear benign:

### 1. **Chunked Queries with Filters**
Instead of bulk queries, data is collected using:
- **Alphabetic filtering**: Queries like `(sAMAccountName=a*)`, `(sAMAccountName=b*)`, etc.
- **Common prefix searches**: Queries for `admin*`, `svc*`, `test*` (mimics searching for specific accounts)
- **OU-based browsing**: Queries each Organizational Unit separately (mimics browsing the directory tree)

### 2. **Random Delays**
Adds random delays between queries (default: 0.5-3.0 seconds) to simulate human interaction rather than automated bulk collection.

### 3. **Query Randomization**
Randomizes the order of chunked queries to avoid predictable patterns that EDR might detect.

### 4. **Mixed Strategy**
Randomly alternates between alphabetic filtering and OU-based browsing to further mimic legitimate admin behavior.

### 5. **Incremental Attribute Collection** ⭐ NEW
Instead of requesting all 25+ attributes at once (suspicious), attributes are fetched in 3 realistic phases:

**Phase 1 - Basic Identification** (looks like initial browsing)
- `distinguishedName`, `sAMAccountName`, `name`, `description`

**Phase 2 - Account Details** (looks like checking account status)
- `userAccountControl`, `pwdLastSet`, `lastLogonTimestamp`, `whenCreated`

**Phase 3 - Security Attributes** (looks like security audit)
- `adminCount`, `servicePrincipalName`, `objectSid`, `msDS-AllowedToDelegateTo`

Each phase has delays between them, mimicking how an admin would progressively explore object properties.

### 6. **Query Type Interleaving** ⭐ NEW
Instead of the suspicious pattern:
```
[Collect ALL users] → [Collect ALL computers] → [Collect ALL groups]
```

Stealth mode randomizes this to:
```
[Collect computers] → [Collect groups] → [Collect users]
```

The order changes each run, making the pattern unpredictable and looking more like ad-hoc exploration.

## Usage

### Basic Stealth Mode

```bash
python3 pyadrecon.py -dc dc01.domain.local -u admin -p password123 -d DOMAIN.LOCAL --stealth
```

This enables stealth mode with default settings:
- Minimum delay: 0.5 seconds
- Maximum delay: 3.0 seconds  
- Chunk size: 50 objects per query

### Custom Stealth Settings

```bash
# Slower, more careful approach (longer delays)
python3 pyadrecon.py -dc dc01.domain.local -u admin -p password123 -d DOMAIN.LOCAL \
  --stealth \
  --stealth-min-delay 2.0 \
  --stealth-max-delay 8.0 \
  --stealth-chunk-size 25

# Faster but still stealthy
python3 pyadrecon.py -dc dc01.domain.local -u admin -p password123 -d DOMAIN.LOCAL \
  --stealth \
  --stealth-min-delay 0.2 \
  --stealth-max-delay 1.5 \
  --stealth-chunk-size 100
```

### Stealth Mode Options

| Option | Description | Default |
|--------|-------------|---------|
| `--stealth` | Enable stealth mode | Disabled |
| `--stealth-min-delay <seconds>` | Minimum delay between queries | 0.5 |
| `--stealth-max-delay <seconds>` | Maximum delay between queries | 3.0 |
| `--stealth-chunk-size <number>` | Objects per query chunk | 50 |

## Performance Considerations

Stealth mode trades speed for operational security:

| Mode | Time for 10,000 users | Notes |
|------|----------------------|-------|
| **Normal mode** | ~5 seconds | Single bulk query |
| **Stealth (basic)** | ~2-5 minutes | Chunked with delays |
| **Stealth (incremental attrs)** | ~4-8 minutes | 3 attribute phases per chunk |
| **Stealth (full: incremental + interleaving)** | ~5-10 minutes | Most realistic, safest |

The exact time depends on:
- Number of objects in the domain
- Delay settings (`--stealth-min-delay` / `--stealth-max-delay`)
- Number of OUs in the directory
- Network latency
- Whether incremental attributes are enabled

## What Gets Stealthified

The following collection modules use stealth mode when enabled:

- ✅ **Users** - Alphabetic/OU-based chunking
- ✅ **Computers** - Alphabetic/OU-based chunking  
- ✅ **Groups** - Alphabetic/OU-based chunking

Other modules (GPOs, DNS, ADCS, etc.) use standard queries as their smaller result sets are less suspicious.

## Detection Evasion Techniques

### Bulk Queries (Flagged by EDR) ❌
```
Query: (&(objectCategory=person)(objectClass=user))
Attributes: sAMAccountName,name,DN,pwdLastSet,adminCount,SPNs,delegation,... (25 attributes)
Results: 10,000 users in 1 query
Time: 2 seconds
Pattern: Single massive request with all attributes
```
**EDR sees:** Suspicious bulk enumeration, all security attributes requested at once

### Stealth Mode with All Features (Appears Legitimate) ✅

**Collection Order (Randomized)**
```
Today: Groups → Computers → Users
Tomorrow: Users → Computers → Groups
```

**Incremental Attributes (Phase 1 - Basic)**
```
Query 1: (&(objectCategory=person)(objectClass=user)(sAMAccountName=a*))
Attributes: distinguishedName,sAMAccountName,name,description (4 basic attrs)
Results: 350 users
[delay 1.2 seconds]
```

**Incremental Attributes (Phase 2 - Account Details)**
```
Query 2: (&(objectCategory=person)(objectClass=user)(sAMAccountName=a*))
Attributes: userAccountControl,pwdLastSet,lastLogonTimestamp,whenCreated (account attrs)
Results: 350 users (same set, additional attributes)
[delay 2.8 seconds]
```

**Incremental Attributes (Phase 3 - Security)**
```
Query 3: (&(objectCategory=person)(objectClass=user)(sAMAccountName=a*))
Attributes: adminCount,SPNs,delegation,objectSid (security attrs)
Results: 350 users (same set, final attributes)
[delay 0.7 seconds]
```

**OU-Based Browsing**
```
Query 4: (Search in OU=Sales,DC=domain,DC=local)
Attributes: Phase 1 basic attributes
Results: 127 users
[delay 1.4 seconds]
```

This pattern continues with:
- Different alphabetic ranges (`b*`, `admin*`, `svc*`, etc.)
- Different OUs (Sales, IT, Finance, etc.)
- Randomized order per run
- Delays between every query and phase
- Different strategies mixed together

**What EDR sees:**
1. ✅ Admin appears to be searching for specific users by name
2. ✅ Admin is browsing through OUs  
3. ✅ Admin is checking basic info first, then drilling down to details
4. ✅ Natural delays between queries (human behavior)
5. ✅ Collection order changes between sessions
6. ✅ Query patterns are unpredictable
7. ✅ Attribute requests are incremental (basic → detailed → sensitive)

This looks like a sysadmin:
- Searching for users by name patterns
- Browsing through the directory structure
- Progressively exploring object properties (not dumping everything at once)
- Taking time between actions
- Following no predictable systematic pattern

## Recommendations

### For Red Team Operations
Use stealth mode when:
- Operating in a monitored environment with EDR
- Time is not critical  
- You need to avoid detection while maintaining access

```bash
# Recommended stealth settings for red team
python3 pyadrecon.py -dc dc01.domain.local -u admin -p password123 -d DOMAIN.LOCAL \
  --stealth \
  --stealth-min-delay 1.0 \
  --stealth-max-delay 5.0 \
  --stealth-chunk-size 30
```

### For Penetration Testing
Choose based on engagement scope:
- **Internal audit with coordination**: Normal mode is fine
- **Assumed breach scenario**: Use stealth mode
- **Purple team exercise**: Test both modes to validate EDR detection

### For Blue Team Testing
Run in both modes to test your EDR:
1. Baseline with normal mode - should be detected
2. Test with stealth mode - validate if still detected
3. Tune EDR rules based on what you learn

## Combining with Other Evasion Techniques

Stealth mode works well with other PyADRecon evasion features:

```bash
# Stealth + Kerberos (bypasses channel binding) + Workstation spoofing
python3 pyadrecon.py -dc dc01.domain.local -u admin -p password123 -d DOMAIN.LOCAL \
  --auth kerberos \
  --workstation ADMIN-PC \
  --stealth \
  --stealth-min-delay 1.5 \
  --stealth-max-delay 4.0
```

## Limitations

Stealth mode does NOT:
- ❌ Hide the fact that LDAP queries are being made
- ❌ Bypass network monitoring (queries are still visible on the wire)
- ❌ Prevent authentication logs
- ❌ Make you invisible to host-based monitoring on the DC

It DOES:
- ✅ Make query patterns look like legitimate admin activity
- ✅ Reduce the likelihood of triggering behavioral EDR alerts
- ✅ Blend in with normal administrative LDAP traffic
- ✅ Avoid obvious "bulk data exfiltration" signatures

## Monitoring/Logging Impact

Even in stealth mode, the following will still be logged:
- Authentication events (Windows Event ID 4624, 4768, 4769)
- LDAP binds (if DC logging is enabled)
- Total volume of LDAP queries (over time)

However, individual query patterns will appear more legitimate and spread out over time.

## Technical Details

### Query Chunking Implementation

The stealth engine uses two strategies:

**Strategy 1: Alphabetic Filtering**
- Generates filters for a-z, 0-9, and common prefixes
- Each filter returns a subset of total objects
- Example: `(&(objectCategory=user)(sAMAccountName=s*))` returns only users starting with 's'

**Strategy 2: OU-Based Browsing**  
- Enumerates all OUs first (normal admin activity)
- Queries each OU separately with SUBTREE scope
- Mimics browsing through AD structure in management tools

**Deduplication**
- Tracks DNs (Distinguished Names) to ensure no duplicates
- Final result contains all unique objects from all chunks

### Randomization
- Query order is randomized within each strategy
- Strategy selection (alphabetic vs OU-based) is randomized per module
- Delays are uniformly distributed between min/max values

## Example Output

```
[*] STEALTH MODE ENABLED - Queries will be chunked and delayed to evade EDR detection
[*] Delay range: 1.0-5.0s | Chunk size: 30
...
[-] [STEALTH MODE] Collecting principal objects in interleaved order...
    Randomized collection order: groups → computers → users
[-] Collecting Groups...
    [STEALTH MODE] Using chunked queries with delays...
    Using OU-based stealth strategy
    Queried Base DN: 12 objects
    Queried OU: IT: 5 objects
    [STEALTH MODE] Collected 56 unique objects
    Found 56 groups
[-] Collecting Computers - May take some time...
    [STEALTH MODE] Using chunked queries with delays...
    [STEALTH MODE] Using incremental attribute collection (3 passes)...
    Phase 1: Fetching 8 basic attributes...
    Using alphabetic stealth strategy
    Phase 1: Collected 3 objects
    Phase 2: Fetching 10 account attributes...
    Using OU-based stealth strategy
    Phase 2: Merged attributes for 3 objects
    Phase 3: Fetching 9 security attributes...
    Using alphabetic stealth strategy
    Phase 3: Merged attributes for 3 objects
    [STEALTH MODE] Incremental collection complete: 3 objects with all attributes
    Found 6 computers
[-] Collecting Users - May take some time...
    [STEALTH MODE] Using chunked queries with delays...
    [STEALTH MODE] Using incremental attribute collection (3 passes)...
    Phase 1: Fetching 8 basic attributes...
    Using OU-based stealth strategy
    Queried Base DN: 342 objects
    Queried OU: Sales: 156 objects
    Phase 1: Collected 660 objects
    Phase 2: Fetching 10 account attributes...
    Using alphabetic stealth strategy  
    Phase 2: Merged attributes for 660 objects
    Phase 3: Fetching 12 security attributes...
    Using OU-based stealth strategy
    Phase 3: Merged attributes for 660 objects
    [STEALTH MODE] Incremental collection complete: 660 objects with all attributes
    Found 660 users
```

## Contributing

If you have ideas for additional stealth techniques or improvements, please submit a pull request or open an issue on GitHub.

## Disclaimer

This feature is intended for authorized security testing and Red Team operations only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before using this tool.
