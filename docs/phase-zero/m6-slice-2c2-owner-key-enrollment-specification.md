# M6 Slice 2C.2 — Owner Key Enrollment for Native Codex Digest Statements

Status: documentation-only enrollment specification, prepared 2026-08-12;
approved by the owner on 2026-08-12 for the exact committed bytes identified
below. Owner-only key generation, encrypted backup, generation-1 public
enrollment, adversarial review/publication, and separate fingerprint approval
were completed by 2026-08-14. Gates 5-7 have not been performed.

```text
OWNER_KEY_ENROLLMENT_SPEC_APPROVED=YES
OWNER_KEY_ENROLLMENT_SPEC_COMMIT=a9bbbedc9104f59170268e3870b6de3bd11e5376
OWNER_KEY_ENROLLMENT_SPEC_SHA256=c78b6bdbe956238aff9a8976b9d830fab4da248747ca63b313a0fea43563c156
OWNER_KEY_GENERATED=YES
OWNER_PRIVATE_KEY_HANDLED_BY_OWNER_DURING_OFFLINE_CEREMONY=YES
OWNER_PRIVATE_KEY_ACCESSED_BY_AGENT=NO
OWNER_PUBLIC_KEY_ENROLLED=YES
OWNER_PUBLIC_KEY_ENROLLMENT_COMMIT=3214251452e85549dedb0e97b0aeddc3df251e95
OWNER_FINGERPRINT_APPROVED=YES
OWNER_FINGERPRINT=SHA256:LQBNgC3HqdwfSWZr/7mvLlSUBwhodPOM0tFDdKZpIs4
OWNER_DIGEST_RECEIVED=NO
OWNER_DIGEST_STATEMENT_SIGNED=NO
OWNER_DIGEST_STATEMENT_VALIDATED=NO
GATE_A_APPROVED=YES
BYTE_AUTHORITY_BRANCH=INDEPENDENT_OWNER_DIGEST
BYTE_AUTHORITY_BRANCH_STATUS=BLOCKED_NO_APPROVED_PREEXISTING_AUTHORITY
BRANCH_S_SWITCH_DECISION=REJECTED_BLOCKED_MISSING_TARGET_ARCHIVE_MEMBER_BINDING
GATE_B_APPROVED=NO
ARTIFACT_ACQUIRED_OR_EXECUTED=NO
CODEX_OR_SIGSTORE_ACQUIRED_OR_EXECUTED=NO
REAL_AUTHENTICATION_OR_PROVIDER_ACCESS=NO
```

This document specifies and now records completed public enrollment of one
dedicated owner key for signing exact `AOSCODEXOWNERDIGEST/1` statements. It
refines the
independent-owner-digest branch selected in the
[artifact-authorization packet](m6-slice-2c2-native-codex-artifact-authorization.md)
and its
[trust-policy addendum](m6-slice-2c2-native-codex-sigstore-trust-policy-addendum.md).
Those documents remain controlling. Gate A and Branch O are approved. Gate B
remains blocked and unapproved.

Owner decision received 2026-08-12: the owner approved the exact specification
at commit `a9bbbedc9104f59170268e3870b6de3bd11e5376`, path
`docs/phase-zero/m6-slice-2c2-owner-key-enrollment-specification.md`, whose
blob has SHA-256
`c78b6bdbe956238aff9a8976b9d830fab4da248747ca63b313a0fea43563c156`.
The approved purpose is creation and enrollment of one dedicated Ed25519 owner
key solely for signing canonical `AOSCODEXOWNERDIGEST/1` statements under the
exact SSHSIG identity, namespace, protection, custody, backup, verification,
rotation, and revocation rules in those committed bytes. This completes Gate 1
only and permits the owner—not an agent—to proceed separately to the manual
Gate 2 ceremony outside every agent session.

This approval does not authorize an agent to generate or access the private
key or passphrase. It does not authorize Codex or Sigstore acquisition, Gate B,
installation, Codex execution, authentication, provider access, production
integration, self-hosting, Git signing, SSH login, controller runtime use, or
any other use of the key. All later gates remain separate.

On 2026-08-14, the owner completed the approved offline ceremony and handled
the private key without any agent, model, or controller access to private-key
material. Generation-1 public evidence was published at commit
`3214251452e85549dedb0e97b0aeddc3df251e95`, and the owner separately approved
fingerprint `SHA256:LQBNgC3HqdwfSWZr/7mvLlSUBwhodPOM0tFDdKZpIs4`.

The 2026-08-14 Gate 5 review found no approved pre-existing independent OpenAI
authority for the raw-member digest, so Branch O remains selected but blocked.
The proposed Branch S switch was rejected and remains blocked because the
existing raw-byte signature does not cryptographically bind the exact
`x86_64-unknown-linux-musl` target, archive, and member identity. Gate B remains
unapproved.

No command marked for the later owner ceremony was executed while preparing
the original 2026-08-12 specification. At that preparation boundary, no key,
passphrase, recovery material, public enrollment, digest statement, or
signature had been created or accessed.

## 1. Decision and authority boundary

The sole candidate is a dedicated, passphrase-protected Ed25519 key generated
manually by the owner with the installed Windows OpenSSH `ssh-keygen.exe`. The
key signs with the OpenSSH SSHSIG protocol through `ssh-keygen -Y sign` and is
verified through `ssh-keygen -Y verify`.

| Field | Exact policy |
|---|---|
| Logical identity | `agenticos-owner-digest-v1` |
| SSHSIG namespace | `agenticos-owner-digest-v1` |
| Key type | `ssh-ed25519` only |
| Ed25519 key size | fixed 256-bit public key; `-b` is not used |
| Private-key format | OpenSSH private-key format only |
| Private-key cipher | `aes256-gcm@openssh.com` |
| Private-key KDF | bcrypt PBKDF, exactly 100 rounds (`-a 100`) |
| Public-key comment | `agenticos-owner-digest-v1` |
| Message hash inside SSHSIG | `sha512` only (`-O hashalg=sha512`) |
| SSH signature algorithm | `ssh-ed25519` only |
| Permitted statement schema | `AOSCODEXOWNERDIGEST/1` only, as fixed in §7 |
| Initial enrollment generation | integer `1` |
| Maximum active lifetime | 366 days from the enrolled `valid-after` time |

RSA, DSA, ECDSA, FIDO/security-key variants, SSH certificates, CAs, PEM private
keys, other ciphers, other KDF counts, other SSHSIG hashes, multiple active
keys, wildcard identities, wildcard namespaces, and fallback keys are
forbidden. A valid signature under any forbidden parameter is still rejected.

This key grants no Git signing, GitHub, SSH login, SSH host, SSH certificate,
Windows login, provider, Codex, Sigstore, controller, task, installation,
execution, network, or credential authority. It must never be configured as
`user.signingKey`, added to an SSH agent, placed in `authorized_keys`, used as
an SSH identity, exposed through `SSH_AUTH_SOCK`, registered with a provider,
or made available to controller runtime code. Possession of the public key is
not Gate B approval.

## 2. Passive host-tool qualification

The following facts were recorded passively on 2026-08-12. Version, help,
algorithm-list, package-query, path, file-version, and file-hash operations
were used. No key operation, installation, update, authentication, or network
operation was performed.

### 2.1 Windows signing host

| Fact | Observed value |
|---|---|
| Windows kernel version reported to PowerShell | `Microsoft Windows NT 10.0.26200.0` |
| Owner account | `BELEGION5\brand` |
| Owner SID | `S-1-5-21-638881961-3295533396-4048788350-1001` |
| PowerShell | `7.6.3`, Core edition |
| `ssh.exe` path | `C:\Windows\System32\OpenSSH\ssh.exe` |
| `ssh-keygen.exe` path | `C:\Windows\System32\OpenSSH\ssh-keygen.exe` |
| OpenSSH runtime version | `OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2` |
| `ssh.exe` product/file version | `OpenSSH_9.5p2 for Windows`; `9.5.6.1` |
| `ssh-keygen.exe` product/file version | `OpenSSH_9.5p2 for Windows`; `9.5.6.1` |
| `ssh.exe` SHA-256 | `6250fd52163fe99a0dc49403ed1b4bbef9b764bdb7bada017a93d057d9376a42` |
| `ssh-keygen.exe` SHA-256 | `44c6809b7bbc917f1310ba92857f983e2788e9b0015aa7896fa0362eddb6338b` |

Windows help advertises all five SSHSIG operations:
`find-principals`, `match-principals`, `check-novalidate`, `sign`, and
`verify`. `ssh -Q sig` advertises `ssh-ed25519`; `ssh -Q cipher` advertises
`aes256-gcm@openssh.com`. The help also advertises algorithms this policy
forbids; tool support is not an allowlist.

### 2.2 WSL verification host

| Fact | Observed value |
|---|---|
| Distribution | Ubuntu 26.04 LTS (Resolute Raccoon) |
| `openssh-client` package | `1:10.2p1-2ubuntu3` |
| OpenSSH runtime version | `OpenSSH_10.2p1 Ubuntu-2ubuntu3, OpenSSL 3.5.5 27 Jan 2026` |
| `ssh` path | `/usr/bin/ssh` |
| `ssh-keygen` path | `/usr/bin/ssh-keygen` |
| `/usr/bin/ssh` SHA-256 | `1273ad81517ad439453301c07c60bae7f17ad6077fc6be40b2ab2d0c4d24e2ed` |
| `/usr/bin/ssh-keygen` SHA-256 | `247431ace4f419ced87ebd0e9536985bdf96cc246609cbbfa66f969b8d34c306` |

WSL help advertises the same five SSHSIG operations and `ssh -Q sig`
advertises `ssh-ed25519`. WSL is qualified here only as a passive compatibility
fact and a possible public-data verifier after enrollment. The owner private
key, encrypted backup, passphrase, password-vault entry, recovery keys, and
private-key paths must never enter WSL.

Any changed executable path, executable SHA-256, product/package version,
owner SID, command syntax, supported algorithm, or host requires a new passive
qualification and owner review before key generation or signing. The facts
above do not qualify OpenSSH generally and do not claim that it is free of
vulnerabilities.

## 3. Exact storage and custody

### 3.1 Primary private key

The private key exists only on a dedicated owner-controlled removable NTFS
volume with:

- BitLocker protection already enabled by the owner outside any agent session;
- exact volume label `AOSOWNERKEY`;
- temporary Windows drive letter `R:` while the owner ceremony is active; and
- no automatic mount, WSL exposure, sharing, indexing, synchronization, cloud
  backup, repository mapping, or controller access.

Exact private-key path while mounted:

```text
R:\AgenticOSOwner\owner-digest-v1\owner-digest-ed25519
```

The corresponding public key is initially created at:

```text
R:\AgenticOSOwner\owner-digest-v1\owner-digest-ed25519.pub
```

The owner records the primary volume's hardware identity and BitLocker volume
identity in a private offline custody record. The label or drive letter alone
does not authenticate the volume. After every ceremony the owner ejects the
volume before starting Codex, another model/agent, WSL, or controller work.

### 3.2 Public working copy

Only the one-line public key may be copied to the fixed Windows path:

```text
C:\Users\brand\AppData\Local\AgenticOSOwner\public\owner-digest-v1\owner-digest-ed25519.pub
```

The fingerprint is a derived public value and may be stored beside it as:

```text
C:\Users\brand\AppData\Local\AgenticOSOwner\public\owner-digest-v1\owner-digest-ed25519.sha256
```

Neither local public file is enrollment. Enrollment exists only after the
public evidence in §6 passes adversarial review, is committed, pushed,
independently observed on GitHub, and synchronized into both clones.

### 3.3 Backup and passphrase custody

Before public enrollment, the owner creates exactly one backup of the already
encrypted OpenSSH private-key file on a second, physically separate,
owner-controlled removable NTFS BitLocker volume. Its exact volume label is
`AOSOWNERBACKUP`, its temporary ceremony drive letter is `S:`, and its exact
backup path is:

```text
S:\AgenticOSOwner\owner-digest-v1\owner-digest-ed25519
```

The backup volume is unmounted and stored separately from the primary. No
third private-key copy is permitted. The public key may accompany the backup
only to support an offline fingerprint check.

The passphrase is unique to this key and has at least 128 bits of
password-manager-generated entropy. It is entered only into the interactive
`ssh-keygen.exe` prompt. It is stored once under the exact private-vault entry
name `AgenticOS / owner digest v1 / key passphrase`; the vault is outside the
repository, workspace, WSL, shell history, logs, clipboard history, model
context, and both key volumes. BitLocker recovery material and the private
custody record follow the same exclusion rule and are not stored with the
passphrase.

If the owner does not have two qualifying encrypted volumes and a qualifying
private vault, key generation remains blocked. A different volume label,
drive letter, filesystem, location, copy count, vault entry, or backup policy
requires amendment and owner approval of this specification before use.

## 4. Filesystem permissions

Both removable volumes must use NTFS. The primary and backup key directories
and private-key files have inheritance disabled and exactly one discretionary
access-control entry granting full control to owner SID
`S-1-5-21-638881961-3295533396-4048788350-1001`. No `Users`,
`Authenticated Users`, `Administrators`, service, WSL, agent, controller, or
other SID receives access. Mandatory integrity labels may exist but must not
add read authority. The owner account must own the directory and file.

The local public directory may grant read access to the owner and normal
repository tooling because its content is public, but it must not contain a
private-key file, backup, passphrase, vault export, recovery data, or custody
record. Repository enrollment files receive ordinary repository permissions
and contain public data only.

An ACL command succeeding is not sufficient. Before copying public data or
signing, the owner visually checks `icacls.exe` output for the exact volume,
directory, private file, and backup file. An unexpected ACE, filesystem, owner,
volume identity, reparse point, or extra directory entry blocks the ceremony.

### 4.1 Common fail-closed ceremony preflight

Every later Windows command block requires these functions to be pasted into
the same fresh PowerShell 7.6.3 console first. Each block invokes the tool
check immediately before its first `ssh-keygen.exe` operation; signing and
verification invoke it again immediately before private-key or signature use.
The owner enters expected volume and disk identities from the private offline
custody record through `Read-Host`, never a command argument or transcript.

> **DO NOT RUN DURING THIS DOCUMENTATION SLICE.** This is common code for a
> later owner-only ceremony. It reads metadata and ACLs, never private-key
> bytes, a passphrase, or recovery material.

```powershell
function Assert-QualifiedWindowsHost {
    $ExpectedPath = 'C:\Windows\System32\OpenSSH\ssh-keygen.exe'
    if ($PSVersionTable.PSVersion.ToString() -cne '7.6.3' -or $PSVersionTable.PSEdition -cne 'Core') {
        throw 'PowerShell identity drift'
    }
    $ResolvedPath = (Resolve-Path -LiteralPath $ExpectedPath -ErrorAction Stop).Path
    if ($ResolvedPath -cne $ExpectedPath) { throw 'ssh-keygen path drift' }
    $VersionInfo = (Get-Item -LiteralPath $ResolvedPath -Force -ErrorAction Stop).VersionInfo
    if ($VersionInfo.FileVersion -cne '9.5.6.1') { throw 'ssh-keygen file-version drift' }
    if ($VersionInfo.ProductVersion -cne 'OpenSSH_9.5p2 for Windows') {
        throw 'ssh-keygen product-version drift'
    }
    $ToolHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ResolvedPath).Hash.ToLowerInvariant()
    if ($ToolHash -cne '44c6809b7bbc917f1310ba92857f983e2788e9b0015aa7896fa0362eddb6338b') {
        throw 'ssh-keygen SHA-256 drift'
    }
}

function Assert-NoReparseAncestor {
    param([Parameter(Mandatory)][string]$Path)
    $FullPath = [IO.Path]::GetFullPath($Path)
    $Root = [IO.Path]::GetPathRoot($FullPath)
    $Current = $Root
    if ((Get-Item -LiteralPath $Current -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw ('Reparse-point root: ' + $Current)
    }
    $Remainder = $FullPath.Substring($Root.Length)
    foreach ($Component in $Remainder.Split(@('\','/'), [StringSplitOptions]::RemoveEmptyEntries)) {
        $Current = Join-Path $Current $Component
        if (Test-Path -LiteralPath $Current) {
            $Item = Get-Item -LiteralPath $Current -Force -ErrorAction Stop
            if ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw ('Reparse-point ancestor: ' + $Current)
            }
        }
    }
}

function Assert-QualifiedVolume {
    param(
        [Parameter(Mandatory)][char]$DriveLetter,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$ExpectedVolumeUniqueId,
        [Parameter(Mandatory)][string]$ExpectedDiskUniqueId
    )
    if ([string]::IsNullOrWhiteSpace($ExpectedVolumeUniqueId) -or
        [string]::IsNullOrWhiteSpace($ExpectedDiskUniqueId)) {
        throw 'Expected volume or disk identity is empty'
    }
    $Volume = @(Get-Volume -DriveLetter $DriveLetter -ErrorAction Stop)
    if ($Volume.Count -ne 1) { throw 'Volume cardinality mismatch' }
    if ($Volume[0].FileSystemLabel -cne $Label -or $Volume[0].FileSystemType -cne 'NTFS') {
        throw 'Volume label or filesystem mismatch'
    }
    if ([string]::IsNullOrWhiteSpace($Volume[0].UniqueId) -or
        $Volume[0].UniqueId -cne $ExpectedVolumeUniqueId) {
        throw 'Volume identity mismatch'
    }
    $Partition = Get-Partition -DriveLetter $DriveLetter -ErrorAction Stop
    $Disk = Get-Disk -Number $Partition.DiskNumber -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($Disk.UniqueId) -or
        $Disk.UniqueId -cne $ExpectedDiskUniqueId) {
        throw 'Disk identity mismatch'
    }
    $BitLocker = Get-BitLockerVolume -MountPoint ($DriveLetter + ':') -ErrorAction Stop
    if ($BitLocker.ProtectionStatus -ne 'On' -or $BitLocker.VolumeStatus -ne 'FullyEncrypted') {
        throw 'BitLocker is not fully encrypted with protection on'
    }
    Assert-NoReparseAncestor -Path ($DriveLetter + ':\')
}

function Set-AndAssertOwnerOnlyAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OwnerSid,
        [Parameter(Mandatory)][bool]$Container
    )
    $Icacls = 'C:\Windows\System32\icacls.exe'
    & $Icacls $Path '/setowner' "*${OwnerSid}"
    if ($LASTEXITCODE -ne 0) { throw ('Failed to set owner: ' + $Path) }
    $Grant = if ($Container) { "*${OwnerSid}:(OI)(CI)F" } else { "*${OwnerSid}:F" }
    & $Icacls $Path '/inheritance:r' '/grant:r' $Grant
    if ($LASTEXITCODE -ne 0) { throw ('Failed to set ACL: ' + $Path) }
    $Acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $Owner = ([Security.Principal.NTAccount]$Acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($Owner -cne $OwnerSid -or -not $Acl.AreAccessRulesProtected) {
        throw ('Owner or inheritance mismatch: ' + $Path)
    }
    $Rules = @($Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($Rules.Count -ne 1) { throw ('ACL cardinality mismatch: ' + $Path) }
    $Rule = $Rules[0]
    if ($Rule.IdentityReference.Value -cne $OwnerSid -or $Rule.IsInherited -or
        $Rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $Rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) {
        throw ('ACL rule mismatch: ' + $Path)
    }
    $ExpectedInheritance = if ($Container) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    if ($Rule.InheritanceFlags -ne $ExpectedInheritance -or
        $Rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
        throw ('ACL inheritance flags mismatch: ' + $Path)
    }
    Assert-NoReparseAncestor -Path $Path
}
```

## 5. Manual owner-only generation ceremony

The ceremony occurs only after the owner explicitly approves this
specification. The owner closes Codex and all model/agent/controller processes,
closes WSL, disables clipboard history for the ceremony, confirms no terminal
transcript is being recorded, mounts only the already-encrypted primary volume
as `R:`, and opens a new interactive PowerShell 7 console. The owner types the
passphrase at both prompts. The passphrase is never supplied through `-N`,
`-P`, a variable, stdin redirection, an environment variable, a script,
clipboard automation, or command-line argument.

> **DO NOT RUN DURING THIS DOCUMENTATION SLICE.** These commands are for the
> owner alone, after approval, outside every agent session. They deliberately
> omit `-N` so `ssh-keygen.exe` must prompt interactively.

```powershell
$ErrorActionPreference = 'Stop'
$OwnerSid = 'S-1-5-21-638881961-3295533396-4048788350-1001'
$Identity = 'agenticos-owner-digest-v1'
$KeyRoot = 'R:\AgenticOSOwner'
$KeyDir = 'R:\AgenticOSOwner\owner-digest-v1'
$PrivateKey = 'R:\AgenticOSOwner\owner-digest-v1\owner-digest-ed25519'
$PublicKey = 'R:\AgenticOSOwner\owner-digest-v1\owner-digest-ed25519.pub'
$PublicOwnerRoot = 'C:\Users\brand\AppData\Local\AgenticOSOwner'
$PublicRoot = 'C:\Users\brand\AppData\Local\AgenticOSOwner\public'
$PublicDir = 'C:\Users\brand\AppData\Local\AgenticOSOwner\public\owner-digest-v1'
$PublicCopy = 'C:\Users\brand\AppData\Local\AgenticOSOwner\public\owner-digest-v1\owner-digest-ed25519.pub'
$FingerprintCopy = 'C:\Users\brand\AppData\Local\AgenticOSOwner\public\owner-digest-v1\owner-digest-ed25519.sha256'
$SshKeygen = 'C:\Windows\System32\OpenSSH\ssh-keygen.exe'
$Icacls = 'C:\Windows\System32\icacls.exe'

$ExpectedPrimaryVolumeId = Read-Host 'Enter the private custody record volume identity for AOSOWNERKEY'
$ExpectedPrimaryDiskId = Read-Host 'Enter the private custody record disk identity for AOSOWNERKEY'
Assert-QualifiedWindowsHost
Assert-QualifiedVolume -DriveLetter 'R' -Label 'AOSOWNERKEY' `
    -ExpectedVolumeUniqueId $ExpectedPrimaryVolumeId -ExpectedDiskUniqueId $ExpectedPrimaryDiskId
Assert-NoReparseAncestor -Path $KeyRoot
Assert-NoReparseAncestor -Path $KeyDir
Assert-NoReparseAncestor -Path $PublicOwnerRoot
Assert-NoReparseAncestor -Path $PublicRoot
Assert-NoReparseAncestor -Path $PublicDir
if (Test-Path -LiteralPath $KeyRoot) { throw 'Primary key root already exists' }
if (Test-Path -LiteralPath $KeyDir) { throw 'Primary key directory already exists' }
if (Test-Path -LiteralPath $PublicOwnerRoot) { throw 'Public owner root already exists' }
if (Test-Path -LiteralPath $PublicRoot) { throw 'Public root already exists' }
if (Test-Path -LiteralPath $PublicDir) { throw 'Public working directory already exists' }
if (Test-Path -LiteralPath $PrivateKey) { throw 'Private-key path already exists' }
if (Test-Path -LiteralPath $PublicKey) { throw 'Public-key path already exists' }
if (Test-Path -LiteralPath $PublicCopy) { throw 'Public-copy path already exists' }
if (Test-Path -LiteralPath $FingerprintCopy) { throw 'Fingerprint path already exists' }

New-Item -ItemType Directory -Path $KeyRoot -ErrorAction Stop | Out-Null
Set-AndAssertOwnerOnlyAcl -Path $KeyRoot -OwnerSid $OwnerSid -Container $true
New-Item -ItemType Directory -Path $KeyDir -ErrorAction Stop | Out-Null
Set-AndAssertOwnerOnlyAcl -Path $KeyDir -OwnerSid $OwnerSid -Container $true

Assert-QualifiedWindowsHost
& $SshKeygen -q -t ed25519 -a 100 -Z 'aes256-gcm@openssh.com' `
    -C $Identity -f $PrivateKey
if ($LASTEXITCODE -ne 0) { throw 'Key generation failed' }

Set-AndAssertOwnerOnlyAcl -Path $PrivateKey -OwnerSid $OwnerSid -Container $false
Set-AndAssertOwnerOnlyAcl -Path $PublicKey -OwnerSid $OwnerSid -Container $false

New-Item -ItemType Directory -Path $PublicOwnerRoot -ErrorAction Stop | Out-Null
Set-AndAssertOwnerOnlyAcl -Path $PublicOwnerRoot -OwnerSid $OwnerSid -Container $true
New-Item -ItemType Directory -Path $PublicRoot -ErrorAction Stop | Out-Null
Set-AndAssertOwnerOnlyAcl -Path $PublicRoot -OwnerSid $OwnerSid -Container $true
New-Item -ItemType Directory -Path $PublicDir -ErrorAction Stop | Out-Null
Set-AndAssertOwnerOnlyAcl -Path $PublicDir -OwnerSid $OwnerSid -Container $true
[IO.File]::Copy($PublicKey, $PublicCopy, $false)
Set-AndAssertOwnerOnlyAcl -Path $PublicCopy -OwnerSid $OwnerSid -Container $false
$FingerprintLine = (& $SshKeygen -l -E sha256 -f $PublicCopy 2>&1)
if ($LASTEXITCODE -ne 0) { throw 'Public-key fingerprint computation failed' }
$FingerprintBytes = [Text.UTF8Encoding]::new($false).GetBytes($FingerprintLine + "`n")
$FingerprintStream = [IO.File]::Open(
    $FingerprintCopy, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None
)
try {
    $FingerprintStream.Write($FingerprintBytes, 0, $FingerprintBytes.Length)
    $FingerprintStream.Flush($true)
} finally {
    $FingerprintStream.Dispose()
}
Set-AndAssertOwnerOnlyAcl -Path $FingerprintCopy -OwnerSid $OwnerSid -Container $false

& $Icacls $KeyDir
& $Icacls $PrivateKey
& $Icacls $PublicKey
& $Icacls $PublicDir
& $Icacls $PublicCopy
& $Icacls $FingerprintCopy
Get-Content -Raw -LiteralPath $PublicCopy
$FingerprintLine
```

The owner must enter a nonempty passphrase satisfying §3.3. Pressing Enter at
an empty passphrase prompt invalidates the ceremony; before any enrollment the
owner securely removes only the just-created, identity-confirmed key files and
restarts the ceremony with fresh key material. That recovery operation is
owner-only and is not delegated to an agent.

The public key must be exactly one LF-terminated ASCII line matching:

```text
ssh-ed25519 BASE64_KEY agenticos-owner-digest-v1
```

`BASE64_KEY` is exactly 68 standard Base64 characters representing one
OpenSSH `ssh-ed25519` public-key blob. No certificate, options, extra field,
second line, blank line, NUL, non-ASCII byte, or alternate comment is allowed.

The fingerprint command is exactly:

```powershell
Assert-QualifiedWindowsHost
& 'C:\Windows\System32\OpenSSH\ssh-keygen.exe' -l -E sha256 `
    -f 'C:\Users\brand\AppData\Local\AgenticOSOwner\public\owner-digest-v1\owner-digest-ed25519.pub'
```

Its sole line must match:

```text
256 SHA256:FINGERPRINT agenticos-owner-digest-v1 (ED25519)
```

`FINGERPRINT` is exactly 43 unpadded standard Base64 characters. Enrollment
records the complete `SHA256:FINGERPRINT` token. MD5, a visual randomart image,
the key comment, a file hash, or a shortened fingerprint is not a substitute.

After the public copy and fingerprint agree, the owner mounts the already
qualified backup volume as `S:`, checks label `AOSOWNERBACKUP`, NTFS, BitLocker,
volume identity, emptiness of the exact destination, and ACL policy, copies
only the encrypted private-key file and its public key, rechecks both
public fingerprints, and ejects both volumes. Backup commands are deliberately
not generalized into a recursive copy: the owner must copy the one exact
private file to the one exact §3.3 path and inspect the result. Any extra file
or identity mismatch blocks enrollment.

> **DO NOT RUN DURING THIS DOCUMENTATION SLICE.** The owner runs this exact
> non-recursive backup block only after the primary ceremony above and only
> while every agent/model/controller process and WSL remain stopped. It does
> not print private-key bytes or their file hash.

```powershell
$ErrorActionPreference = 'Stop'
$OwnerSid = 'S-1-5-21-638881961-3295533396-4048788350-1001'
$PrimaryPrivateKey = 'R:\AgenticOSOwner\owner-digest-v1\owner-digest-ed25519'
$PrimaryPublicKey = 'R:\AgenticOSOwner\owner-digest-v1\owner-digest-ed25519.pub'
$BackupRoot = 'S:\AgenticOSOwner'
$BackupDir = 'S:\AgenticOSOwner\owner-digest-v1'
$BackupPrivateKey = 'S:\AgenticOSOwner\owner-digest-v1\owner-digest-ed25519'
$BackupPublicKey = 'S:\AgenticOSOwner\owner-digest-v1\owner-digest-ed25519.pub'
$Icacls = 'C:\Windows\System32\icacls.exe'
$SshKeygen = 'C:\Windows\System32\OpenSSH\ssh-keygen.exe'

$ExpectedBackupVolumeId = Read-Host 'Enter the private custody record volume identity for AOSOWNERBACKUP'
$ExpectedBackupDiskId = Read-Host 'Enter the private custody record disk identity for AOSOWNERBACKUP'
Assert-QualifiedWindowsHost
Assert-QualifiedVolume -DriveLetter 'S' -Label 'AOSOWNERBACKUP' `
    -ExpectedVolumeUniqueId $ExpectedBackupVolumeId -ExpectedDiskUniqueId $ExpectedBackupDiskId
Assert-NoReparseAncestor -Path $BackupRoot
Assert-NoReparseAncestor -Path $BackupDir
if (Test-Path -LiteralPath $BackupRoot) { throw 'Backup key root already exists' }
if (Test-Path -LiteralPath $BackupDir) { throw 'Backup key directory already exists' }
if (Test-Path -LiteralPath $BackupPrivateKey) { throw 'Backup private-key path already exists' }
if (Test-Path -LiteralPath $BackupPublicKey) { throw 'Backup public-key path already exists' }

New-Item -ItemType Directory -Path $BackupRoot -ErrorAction Stop | Out-Null
Set-AndAssertOwnerOnlyAcl -Path $BackupRoot -OwnerSid $OwnerSid -Container $true
New-Item -ItemType Directory -Path $BackupDir -ErrorAction Stop | Out-Null
Set-AndAssertOwnerOnlyAcl -Path $BackupDir -OwnerSid $OwnerSid -Container $true
[IO.File]::Copy($PrimaryPrivateKey, $BackupPrivateKey, $false)
[IO.File]::Copy($PrimaryPublicKey, $BackupPublicKey, $false)
Set-AndAssertOwnerOnlyAcl -Path $BackupPrivateKey -OwnerSid $OwnerSid -Container $false
Set-AndAssertOwnerOnlyAcl -Path $BackupPublicKey -OwnerSid $OwnerSid -Container $false

$PrimaryPrivateHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $PrimaryPrivateKey).Hash
$BackupPrivateHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $BackupPrivateKey).Hash
if ($PrimaryPrivateHash -cne $BackupPrivateHash) { throw 'Encrypted private-key backup differs' }
Assert-QualifiedWindowsHost
$PrimaryFingerprint = (& $SshKeygen -l -E sha256 -f $PrimaryPublicKey 2>&1)
if ($LASTEXITCODE -ne 0) { throw 'Primary public-key fingerprint failed' }
$BackupFingerprint = (& $SshKeygen -l -E sha256 -f $BackupPublicKey 2>&1)
if ($LASTEXITCODE -ne 0) { throw 'Backup public-key fingerprint failed' }
if ($PrimaryFingerprint -cne $BackupFingerprint) { throw 'Backup public key differs' }

& $Icacls $BackupDir
& $Icacls $BackupPrivateKey
& $Icacls $BackupPublicKey
Remove-Variable PrimaryPrivateHash,BackupPrivateHash -ErrorAction SilentlyContinue
```

## 6. Bounded public enrollment evidence

Only the public-key line and SHA-256 fingerprint may leave the owner ceremony.
The private key, encrypted private-key bytes, passphrase, volume identity,
BitLocker recovery data, vault data, and custody record never enter a model
message, repository, workspace, WSL, log, shell history, or review packet.

Initial enrollment adds exactly these public files:

```text
docs/phase-zero/owner-key-enrollment/
  agenticos-owner-digest-v1-g0001.pub
  agenticos-owner-digest-v1-g0001.fingerprint
  agenticos-owner-digest-v1.allowed_signers
  agenticos-owner-digest-v1.revoked_keys
  agenticos-owner-digest-v1.state.json
```

Bounds and formats:

- `g0001.pub`: exactly the one public-key line from §5, LF terminated, at most
  128 bytes;
- `g0001.fingerprint`: exactly `SHA256:FINGERPRINT` plus LF, at most 52 bytes;
- `allowed_signers`: while state is `active`, exactly one line in the format
  below, LF terminated, at most 320 bytes; when state is not active, zero
  bytes;
- `revoked_keys`: zero bytes for the initial enrollment; later, at most 64
  exact one-line `ssh-ed25519` public keys, each LF terminated, total at most
  8,192 bytes; and
- `state.json`: one-line ASCII JSON, LF terminated, at most 2,048 bytes, exact
  schema `AOSOWNERKEYENROLLMENT/1`, no unknown or duplicate keys.

The exact allowed-signers line is:

```text
agenticos-owner-digest-v1 namespaces="agenticos-owner-digest-v1",valid-after="VALID_AFTER",valid-before="VALID_BEFORE" ssh-ed25519 BASE64_KEY
```

`VALID_AFTER` and `VALID_BEFORE` are exact UTC OpenSSH timestamps in
`YYYYMMDDHHMMSSZ` form. `VALID_AFTER` is the owner-approved enrollment start;
`VALID_BEFORE` is no more than 366 days later. They become immutable public
values at enrollment. No wildcard, comma-separated principal, second
namespace, `cert-authority`, second key, comment, or other option is allowed.

The exact state key order is:

```text
schema,identity,namespace,generation,status,public_key_file,fingerprint,valid_after,valid_before,previous_state_sha256
```

For generation 1, values are fixed as follows:

- `schema`: `AOSOWNERKEYENROLLMENT/1`;
- `identity` and `namespace`: `agenticos-owner-digest-v1`;
- `generation`: integer `1`;
- `status`: `active`;
- `public_key_file`: `agenticos-owner-digest-v1-g0001.pub`;
- `fingerprint`: the complete enrolled `SHA256:FINGERPRINT`;
- `valid_after` and `valid_before`: the same exact timestamps used by
  `allowed_signers`; and
- `previous_state_sha256`: JSON `null`.

The five files must cross-agree byte for byte. Review recomputes the public-key
fingerprint with both qualified Windows and WSL `ssh-keygen`, confirms the
allowed-signers key is exactly the enrolled key, rejects duplicate identity or
namespace entries anywhere in the active file, and searches repository history
for a prior generation or revocation. Initial enrollment is rejected if any
prior `agenticos-owner-digest-v1` state exists unless the change is the explicit
rotation procedure in §10.

Enrollment must complete before the owner receives or supplies an independent
binary digest. Combining key generation, public enrollment, digest delivery,
or statement signing into one commit, one agent turn, or one approval is
forbidden. The enrollment commit is not effective until its exact SHA is
pushed, independently observed with `git ls-remote`, synchronized into both
clones, both trees are clean and 0/0 divergent, and the owner separately
approves the public fingerprint.

At that stable boundary the owner stores one external last-seen checkpoint in
the exact private-vault entry `AgenticOS / owner digest v1 / enrollment
checkpoint`. It contains only schema `AOSOWNERKEYCHECKPOINT/1`, generation,
status, complete fingerprint, enrollment/revocation commit SHA, `state.json`
SHA-256, `allowed_signers` SHA-256, `revoked_keys` SHA-256, `valid_before`, and,
after Gate 7 first succeeds, statement-index sequence/SHA-256, last decision
ID, and exact acceptance commit SHA. These are public values, but the
checkpoint's owner-controlled location is the rollback anchor. It is never
read by an agent or copied into the repository, workspace, WSL, log, shell
history, or model context. Before digest delivery, signing, validation,
rotation, or revocation, the owner manually confirms that the current
repository state is not older than or inconsistent with this checkpoint.
Absence or ambiguity blocks.

## 7. Byte-exact `AOSCODEXOWNERDIGEST/1` statement

The signed message is exactly one ASCII JSON object with no BOM, indentation,
space, tab, CR, LF, trailing newline, or bytes before or after the object. It is
at most 4,096 bytes. The exact key order is:

```text
schema,publisher,repository,version,tag,source_commit,target,archive_asset_id,archive_name,member_name,uncompressed_sha256,owner_decision_id
```

The serialization is exactly the following concatenation, where `DIGEST` and
`DECISION_ID` are the only variable values:

```text
{"schema":"AOSCODEXOWNERDIGEST/1","publisher":"OpenAI","repository":"openai/codex","version":"0.120.0","tag":"rust-v0.120.0","source_commit":"65319eb1400cbd2890c43d572263dabd25f18ba9","target":"x86_64-unknown-linux-musl","archive_asset_id":393784170,"archive_name":"codex-x86_64-unknown-linux-musl.tar.gz","member_name":"codex-x86_64-unknown-linux-musl","uncompressed_sha256":"DIGEST","owner_decision_id":"DECISION_ID"}
```

`DIGEST` is exactly 64 lowercase hexadecimal characters and is the owner's
independently obtained SHA-256 of the raw uncompressed member. `DECISION_ID`
is unique, non-secret, and matches exactly:

```text
AOS-CODEX-0.120.0-YYYYMMDD-NNNN
```

The date is a real Gregorian UTC date in basic `YYYYMMDD` form equal to the
owner's decision date, and `NNNN` is a four-digit owner sequence. Lexical match
without calendar validation is insufficient. The identifier is not derived
from GitHub, the release API, a sidecar, acquired bytes, verifier output, or
the later acquisition operation.

The parser rejects different key order, whitespace, alternate escaping,
uppercase hex, JSON numbers encoded as strings, duplicate/unknown/missing
keys, Unicode, controls, BOM, trailing newline, a different artifact field,
another schema, a second digest, or another statement even if the enrolled key
signed those bytes. Cryptographic verification never replaces semantic and
canonical-byte validation.

## 8. Exact later statement and signing commands

The owner obtains the digest only after enrollment has completed. The owner
then closes every agent/model/controller process, closes WSL, mounts the exact
primary volume as `R:`, revalidates volume identity, BitLocker, NTFS, ACLs,
private/public fingerprint equality, active enrollment generation, validity
window, empty revocation status, and repository synchronization, and opens a
fresh non-recorded interactive PowerShell 7 console.

> **DO NOT RUN DURING THIS DOCUMENTATION SLICE.** These commands create only a
> later public statement and SSHSIG signature. They read the private key only
> inside the owner-controlled manual ceremony and prompt interactively for its
> passphrase. They never print the private key or passphrase.

```powershell
$ErrorActionPreference = 'Stop'
$OwnerSid = 'S-1-5-21-638881961-3295533396-4048788350-1001'
$Namespace = 'agenticos-owner-digest-v1'
$PrivateKey = 'R:\AgenticOSOwner\owner-digest-v1\owner-digest-ed25519'
$SourcePublicKey = 'R:\AgenticOSOwner\owner-digest-v1\owner-digest-ed25519.pub'
$EnrolledPublicKey = 'C:\AgenticOS\docs\phase-zero\owner-key-enrollment\agenticos-owner-digest-v1-g0001.pub'
$EnrolledFingerprint = 'C:\AgenticOS\docs\phase-zero\owner-key-enrollment\agenticos-owner-digest-v1-g0001.fingerprint'
$OwnerDataRoot = 'C:\Users\brand\AppData\Local\AgenticOSOwner'
$StatementsRoot = 'C:\Users\brand\AppData\Local\AgenticOSOwner\statements'
$StatementRoot = 'C:\Users\brand\AppData\Local\AgenticOSOwner\statements\owner-digest-v1'
$SshKeygen = 'C:\Windows\System32\OpenSSH\ssh-keygen.exe'

$ExpectedPrimaryVolumeId = Read-Host 'Enter the private custody record volume identity for AOSOWNERKEY'
$ExpectedPrimaryDiskId = Read-Host 'Enter the private custody record disk identity for AOSOWNERKEY'
Assert-QualifiedWindowsHost
Assert-QualifiedVolume -DriveLetter 'R' -Label 'AOSOWNERKEY' `
    -ExpectedVolumeUniqueId $ExpectedPrimaryVolumeId -ExpectedDiskUniqueId $ExpectedPrimaryDiskId
Set-AndAssertOwnerOnlyAcl -Path $PrivateKey -OwnerSid $OwnerSid -Container $false
if ((Get-Content -Raw -LiteralPath $SourcePublicKey) -cne
    (Get-Content -Raw -LiteralPath $EnrolledPublicKey)) {
    throw 'Mounted public key differs from enrolled generation'
}
$ComputedFingerprintLine = (& $SshKeygen -l -E sha256 -f $SourcePublicKey 2>&1)
if ($LASTEXITCODE -ne 0) { throw 'Mounted public-key fingerprint failed' }
$ComputedFingerprint = ($ComputedFingerprintLine -split ' ')[1]
if ($ComputedFingerprint -cne (Get-Content -Raw -LiteralPath $EnrolledFingerprint).Trim()) {
    throw 'Mounted key fingerprint differs from enrollment'
}

$Digest = (Read-Host 'Enter the independently obtained uncompressed SHA-256').Trim()
if ($Digest -cnotmatch '^[0-9a-f]{64}$') { throw 'Digest is not 64 lowercase hex characters' }
$DecisionId = (Read-Host 'Enter owner decision ID AOS-CODEX-0.120.0-YYYYMMDD-NNNN').Trim()
if ($DecisionId -cnotmatch '^AOS-CODEX-0\.120\.0-[0-9]{8}-[0-9]{4}$') {
    throw 'Owner decision ID is not canonical'
}
$DecisionDateText = $DecisionId.Substring('AOS-CODEX-0.120.0-'.Length, 8)
$DecisionDate = [DateTime]::MinValue
$DateStyle = [Globalization.DateTimeStyles]::AssumeUniversal -bor
    [Globalization.DateTimeStyles]::AdjustToUniversal
if (-not [DateTime]::TryParseExact(
    $DecisionDateText, 'yyyyMMdd', [Globalization.CultureInfo]::InvariantCulture,
    $DateStyle, [ref]$DecisionDate
)) {
    throw 'Owner decision ID contains an invalid Gregorian date'
}
if ($DecisionDateText -cne [DateTime]::UtcNow.ToString('yyyyMMdd')) {
    throw 'Owner decision ID date is not the current owner decision UTC date'
}

$Statement = [ordered]@{
    schema = 'AOSCODEXOWNERDIGEST/1'
    publisher = 'OpenAI'
    repository = 'openai/codex'
    version = '0.120.0'
    tag = 'rust-v0.120.0'
    source_commit = '65319eb1400cbd2890c43d572263dabd25f18ba9'
    target = 'x86_64-unknown-linux-musl'
    archive_asset_id = 393784170
    archive_name = 'codex-x86_64-unknown-linux-musl.tar.gz'
    member_name = 'codex-x86_64-unknown-linux-musl'
    uncompressed_sha256 = $Digest
    owner_decision_id = $DecisionId
}
$CanonicalJson = ConvertTo-Json -InputObject $Statement -Compress -Depth 2
if ($CanonicalJson.Length -gt 4096) { throw 'Statement exceeds 4,096 bytes' }
if ($CanonicalJson -cmatch '[^\x20-\x7e]') {
    throw 'Statement is not printable ASCII'
}
$ExpectedCanonicalJson = '{"schema":"AOSCODEXOWNERDIGEST/1","publisher":"OpenAI","repository":"openai/codex","version":"0.120.0","tag":"rust-v0.120.0","source_commit":"65319eb1400cbd2890c43d572263dabd25f18ba9","target":"x86_64-unknown-linux-musl","archive_asset_id":393784170,"archive_name":"codex-x86_64-unknown-linux-musl.tar.gz","member_name":"codex-x86_64-unknown-linux-musl","uncompressed_sha256":"' + $Digest + '","owner_decision_id":"' + $DecisionId + '"}'
if ($CanonicalJson -cne $ExpectedCanonicalJson) {
    throw 'Serializer output differs from the exact canonical statement'
}

$DecisionDir = Join-Path $StatementRoot $DecisionId
Assert-NoReparseAncestor -Path $DecisionDir
if (Test-Path -LiteralPath $DecisionDir) { throw 'Decision directory already exists' }
Set-AndAssertOwnerOnlyAcl -Path $OwnerDataRoot -OwnerSid $OwnerSid -Container $true
if (-not (Test-Path -LiteralPath $StatementsRoot)) {
    New-Item -ItemType Directory -Path $StatementsRoot -ErrorAction Stop | Out-Null
}
Set-AndAssertOwnerOnlyAcl -Path $StatementsRoot -OwnerSid $OwnerSid -Container $true
if (-not (Test-Path -LiteralPath $StatementRoot)) {
    New-Item -ItemType Directory -Path $StatementRoot -ErrorAction Stop | Out-Null
}
Set-AndAssertOwnerOnlyAcl -Path $StatementRoot -OwnerSid $OwnerSid -Container $true
New-Item -ItemType Directory -Path $DecisionDir -ErrorAction Stop | Out-Null
Set-AndAssertOwnerOnlyAcl -Path $DecisionDir -OwnerSid $OwnerSid -Container $true
$StatementPath = Join-Path $DecisionDir 'statement.json'
$SignaturePath = $StatementPath + '.sig'
if (Test-Path -LiteralPath $StatementPath) { throw 'Statement path already exists' }
if (Test-Path -LiteralPath $SignaturePath) { throw 'Signature path already exists' }
$StatementBytes = [Text.UTF8Encoding]::new($false).GetBytes($CanonicalJson)
$StatementStream = [IO.File]::Open(
    $StatementPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None
)
try {
    $StatementStream.Write($StatementBytes, 0, $StatementBytes.Length)
    $StatementStream.Flush($true)
} finally {
    $StatementStream.Dispose()
}
Set-AndAssertOwnerOnlyAcl -Path $StatementPath -OwnerSid $OwnerSid -Container $false

Assert-QualifiedWindowsHost
& $SshKeygen -Y sign -f $PrivateKey -n $Namespace -O 'hashalg=sha512' $StatementPath
if ($LASTEXITCODE -ne 0) { throw 'SSHSIG signing failed' }
if (-not (Test-Path -LiteralPath $SignaturePath -PathType Leaf)) {
    throw 'Expected SSHSIG file was not created'
}
Set-AndAssertOwnerOnlyAcl -Path $SignaturePath -OwnerSid $OwnerSid -Container $false

(Get-FileHash -Algorithm SHA256 -LiteralPath $StatementPath).Hash.ToLowerInvariant()
(Get-FileHash -Algorithm SHA256 -LiteralPath $SignaturePath).Hash.ToLowerInvariant()
```

`ConvertTo-Json` is permitted only with the exact ordered object and PowerShell
7.6.3 qualified in §2. An owner must compare the resulting bytes to §7 before
signing. A changed PowerShell or serializer requires renewed byte-level review;
manually reformatting the file is forbidden.

`ssh-keygen.exe` writes the signature to the statement path plus `.sig`. The
passphrase is entered only at its interactive prompt. The owner ejects `R:`
immediately after signing and before any agent session resumes. Only the
statement, signature, their SHA-256 values, decision ID, and bounded validation
record may later enter the repository or model context.

## 9. Signature envelope bounds and exact verification

The signature file is public. Before invoking OpenSSH, the validator requires:

- total size from 256 through 2,048 bytes;
- 7-bit ASCII only;
- exactly one `-----BEGIN SSH SIGNATURE-----` line;
- exactly one `-----END SSH SIGNATURE-----` line;
- only standard Base64 and either LF for every line ending or CRLF for every
  line ending in the complete envelope;
- exactly one terminal line ending after the footer and zero bytes after it;
- no NUL, leading bytes, second block, trailing whitespace, mixed line ending,
  or line longer than 128 bytes;
- decoded SSHSIG size from 128 through 1,024 bytes;
- SSHSIG magic `SSHSIG`, format version `1`, empty reserved field, exact
  namespace `agenticos-owner-digest-v1`, hash algorithm `sha512`, one
  `ssh-ed25519` public key equal to the enrolled key, and one
  `ssh-ed25519` signature; and
- no certificate, unknown field, concatenated object, or trailing decoded byte.

Armor line-ending acceptance does not change the signed message: OpenSSH
verifies the untouched statement bytes streamed on stdin. The canonical JSON
file itself is never newline-normalized.

The validator first validates the exact state, public key, fingerprint,
allowed-signers line, revocation file, validity time, statement syntax, fixed
artifact fields, decision-ID uniqueness, and envelope bounds. It then invokes
the exact enrolled Windows `ssh-keygen.exe` with byte-preserving stdin:

> **DO NOT RUN DURING THIS DOCUMENTATION SLICE.** This is the later acceptance
> verification command. It reads public evidence only.

```powershell
$ErrorActionPreference = 'Stop'
$SshKeygen = 'C:\Windows\System32\OpenSSH\ssh-keygen.exe'
$AllowedSigners = 'C:\AgenticOS\docs\phase-zero\owner-key-enrollment\agenticos-owner-digest-v1.allowed_signers'
$RevokedKeys = 'C:\AgenticOS\docs\phase-zero\owner-key-enrollment\agenticos-owner-digest-v1.revoked_keys'
$FingerprintFile = 'C:\AgenticOS\docs\phase-zero\owner-key-enrollment\agenticos-owner-digest-v1-g0001.fingerprint'
$Identity = 'agenticos-owner-digest-v1'
$Namespace = 'agenticos-owner-digest-v1'
$DecisionId = 'AOS-CODEX-0.120.0-YYYYMMDD-NNNN'
$DecisionDir = Join-Path 'C:\Users\brand\AppData\Local\AgenticOSOwner\statements\owner-digest-v1' $DecisionId
$StatementPath = Join-Path $DecisionDir 'statement.json'
$SignaturePath = $StatementPath + '.sig'
$TimeoutSeconds = 10
$MaximumOutputBytes = 512
$Fingerprint = (Get-Content -Raw -LiteralPath $FingerprintFile).Trim()

$Arguments = @(
    '-Y', 'verify',
    '-f', $AllowedSigners,
    '-I', $Identity,
    '-n', $Namespace,
    '-s', $SignaturePath,
    '-r', $RevokedKeys
)

Assert-QualifiedWindowsHost
$Process = $null
$StdoutSink = $null
$StderrSink = $null
try {
    $StartInfo = [Diagnostics.ProcessStartInfo]::new()
    $StartInfo.FileName = $SshKeygen
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardInput = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true
    foreach ($Argument in $Arguments) { [void]$StartInfo.ArgumentList.Add($Argument) }
    $Process = [Diagnostics.Process]::new()
    $Process.StartInfo = $StartInfo
    if (-not $Process.Start()) { throw 'Failed to start ssh-keygen verifier' }

    $InputFile = [IO.File]::OpenRead($StatementPath)
    try {
        $InputFile.CopyTo($Process.StandardInput.BaseStream)
    } finally {
        $InputFile.Dispose()
        $Process.StandardInput.Close()
    }

    $StdoutSink = [IO.MemoryStream]::new($MaximumOutputBytes)
    $StderrSink = [IO.MemoryStream]::new($MaximumOutputBytes)
    $StdoutBuffer = [byte[]]::new(128)
    $StderrBuffer = [byte[]]::new(128)
    $StdoutTask = $Process.StandardOutput.BaseStream.ReadAsync($StdoutBuffer, 0, $StdoutBuffer.Length)
    $StderrTask = $Process.StandardError.BaseStream.ReadAsync($StderrBuffer, 0, $StderrBuffer.Length)
    $StdoutClosed = $false
    $StderrClosed = $false
    $TimeoutClock = [Diagnostics.Stopwatch]::StartNew()

    while (-not ($Process.HasExited -and $StdoutClosed -and $StderrClosed)) {
        if ($TimeoutClock.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            & 'C:\Windows\System32\taskkill.exe' /PID $Process.Id /T /F *> $null
            throw 'SSHSIG verification timed out'
        }
        if (-not $StdoutClosed -and $StdoutTask.IsCompleted) {
            $Count = $StdoutTask.GetAwaiter().GetResult()
            if ($Count -eq 0) {
                $StdoutClosed = $true
            } else {
                if ($StdoutSink.Length + $Count -gt $MaximumOutputBytes) {
                    & 'C:\Windows\System32\taskkill.exe' /PID $Process.Id /T /F *> $null
                    throw 'SSHSIG stdout exceeded its bound'
                }
                $StdoutSink.Write($StdoutBuffer, 0, $Count)
                $StdoutTask = $Process.StandardOutput.BaseStream.ReadAsync(
                    $StdoutBuffer, 0, $StdoutBuffer.Length
                )
            }
        }
        if (-not $StderrClosed -and $StderrTask.IsCompleted) {
            $Count = $StderrTask.GetAwaiter().GetResult()
            if ($Count -eq 0) {
                $StderrClosed = $true
            } else {
                if ($StderrSink.Length + $Count -gt $MaximumOutputBytes) {
                    & 'C:\Windows\System32\taskkill.exe' /PID $Process.Id /T /F *> $null
                    throw 'SSHSIG stderr exceeded its bound'
                }
                $StderrSink.Write($StderrBuffer, 0, $Count)
                $StderrTask = $Process.StandardError.BaseStream.ReadAsync(
                    $StderrBuffer, 0, $StderrBuffer.Length
                )
            }
        }
        if (-not $Process.HasExited) {
            Start-Sleep -Milliseconds 5
            $Process.Refresh()
        } elseif (-not $StdoutClosed -or -not $StderrClosed) {
            Start-Sleep -Milliseconds 1
        }
    }
    $Process.WaitForExit()
    $StdoutBytes = $StdoutSink.ToArray()
    $StderrBytes = $StderrSink.ToArray()
    if (@($StdoutBytes + $StderrBytes | Where-Object { $_ -gt 0x7f }).Count -ne 0) {
        throw 'SSHSIG verification output was not ASCII'
    }
    if ($Process.ExitCode -ne 0) { throw 'SSHSIG verification returned nonzero' }
    if ($StderrBytes.Length -ne 0) { throw 'SSHSIG verification emitted unexpected stderr' }
    $StdoutText = [Text.Encoding]::ASCII.GetString($StdoutBytes)
    $ExpectedStdout = 'Good "' + $Namespace + '" signature for ' + $Identity +
        ' with ED25519 key ' + $Fingerprint
    if ($StdoutText -cne ($ExpectedStdout + "`n") -and
        $StdoutText -cne ($ExpectedStdout + "`r`n")) {
        throw 'SSHSIG verification success output grammar mismatch'
    }
    $ExpectedStdout
} finally {
    if ($null -ne $Process -and -not $Process.HasExited) {
        & 'C:\Windows\System32\taskkill.exe' /PID $Process.Id /T /F *> $null
        if (-not $Process.WaitForExit(2000)) {
            throw 'Failed to terminate ssh-keygen process tree'
        }
    }
    if ($null -ne $StdoutSink) { $StdoutSink.Dispose() }
    if ($null -ne $StderrSink) { $StderrSink.Dispose() }
    if ($null -ne $TimeoutClock) { $TimeoutClock.Stop() }
    if ($null -ne $Process) { $Process.Dispose() }
}
```

The filename's `YYYYMMDD-NNNN` is replaced only with the already validated
decision identifier; it is not a shell pattern or discovery rule. Success is
OpenSSH exit code zero plus every preceding policy check. Text such as “Good
signature” with a nonzero or missing exit code is failure. Unknown, truncated,
oversized, or ambiguous stdout/stderr is failure and is retained only in a
bounded, sanitized digest record.

A verifier running after key expiration may use
`-O verify-time=YYYYMMDDHHMMSSZ` only for historical revalidation at the exact
acceptance time already preserved in the reviewed statement record. It may not
choose a time to make an otherwise invalid signature pass. New acceptance
always uses current trusted UTC and must fall within the active enrollment
window.

### 9.1 Append-only statement acceptance index

The authoritative uniqueness ledger is the public file:

```text
docs/phase-zero/owner-digest-statements/agenticos-owner-digest-v1.index.json
```

Each accepted decision also adds exactly three immutable files named with the
complete canonical decision ID:

```text
docs/phase-zero/owner-digest-statements/DECISION_ID.json
docs/phase-zero/owner-digest-statements/DECISION_ID.json.sig
docs/phase-zero/owner-digest-statements/DECISION_ID.acceptance.json
```

The index is one-line LF-terminated ASCII JSON, at most 65,536 bytes, schema
`AOSOWNERDIGESTINDEX/1`, with exact top-level key order
`schema,sequence,previous_index_sha256,entries`. It contains at most 64 entries
in strictly increasing integer sequence order. `sequence` equals the entry
count. `previous_index_sha256` is JSON `null` for the first acceptance and
otherwise the lowercase SHA-256 of the complete prior LF-terminated index.

Every entry and matching acceptance record use exact key order:

```text
sequence,owner_decision_id,statement_file,signature_file,statement_sha256,signature_sha256,enrollment_generation,enrollment_fingerprint,accepted_at_utc,validation_result,enrollment_commit_sha,repository_baseline_sha
```

Digests are 64 lowercase hex; `accepted_at_utc` is trusted RFC 3339 UTC with
seconds and `Z`; `validation_result` is exactly `accepted`; enrollment
generation/fingerprint equal the active state; `enrollment_commit_sha` is the
40-character SHA of the already published public enrollment; and
`repository_baseline_sha` is the 40-character parent SHA on which the
acceptance commit is built. The acceptance commit cannot non-circularly name
its own SHA; after publication its exact SHA is added to the external owner
checkpoint described in §6 before Gate 7 is complete.

Before creating any of the three immutable files, validation fetches all
repository refs, checks the complete current index chain, searches all locally
reachable Git history for the exact decision ID and both public-object hashes,
compares sequence/index/commit state to the owner's external last-seen
checkpoint, and requires all three destination paths to be absent. Any prior
decision ID is duplicate whether its digest is the same or different. Any
lower sequence, broken prior-index digest, missing historical object, reused
file/hash, unreachable checkpoint commit, rewritten history, or unrecognized
entry blocks acceptance and Gate B consideration.

The three immutable files and updated index are adversarially reviewed and
committed together. After GitHub observation and two-clone synchronization,
the owner updates the checkpoint with index sequence, index SHA-256, last
decision ID, and exact acceptance commit SHA. Rejected attempts never enter the
accepted index and grant no authority; only a bounded content-free failure
code and hashes may be retained separately.

## 10. Loss, compromise, expiration, rotation, and revocation

The only permitted current-state statuses are `active` and `revoked`.
Expiration is derived from `valid_before`; loss and compromise use the
`revoked` transition. Every transition replaces `state.json` in the exact §6
key order, retains all earlier generation `.pub` and `.fingerprint` files
unchanged, and sets `previous_state_sha256` to the 64-character lowercase
SHA-256 of the complete immediately preceding LF-terminated `state.json`.
Only the initial generation has JSON `null` for that field.

`revoked_keys` is ordered by strictly increasing generation. It contains each
retired or revoked generation's exact `.pub` line exactly once and no active
key. Every line must correspond to one immutable generation `.pub` and
`.fingerprint` pair whose recomputed fingerprint agrees. Duplicate key bytes,
fingerprints, generations, lines, reordered lines, absent prior generations,
or a key without immutable evidence are rejection conditions.

| Prior state | Event | Next generation/status | Exact file transition |
|---|---|---|---|
| no state | initial enrollment | `1`, `active` | add `g0001.pub` and `.fingerprint`; one-line allowed signers for g0001; zero-byte revocation file; state links JSON `null` |
| generation G `active` | normal rotation | G+1, `active` | preserve all old generation files; append G public key exactly once to revocations; add G+1 public files; replace allowed signers with only G+1; new state points to G+1 and links prior state |
| generation G `active` | loss, compromise, or owner revocation | G, `revoked` | preserve generation files; append G key exactly once; make allowed signers zero bytes; keep G key/fingerprint/validity fields in state; link prior state |
| generation G `revoked` | replacement after revocation | G+1, `active` | do not append G again; preserve revocations and all old files; add G+1 public files; set sole allowed signer to G+1; new state points to G+1 and links revoked state |
| any state | expiry only | unchanged | no automatic file mutation; verification rejects current time outside the interval; a later owner-reviewed revocation or rotation uses one row above |

For `active`, `public_key_file`, `fingerprint`, `valid_after`, and
`valid_before` name and equal the current generation, and allowed signers has
its sole exact line. For `revoked`, those four fields remain equal to the
revoked current generation, that key occurs exactly once in `revoked_keys`,
and allowed signers is zero bytes. No other field value, transition, skipped
generation, in-place generation-file replacement, deletion, or combined
transition is permitted.

### 10.1 Loss

Loss of the primary, backup, passphrase, recovery material, or ability to prove
volume identity immediately blocks new signing and every pending Gate B
consideration. The owner marks the generation revoked through the procedure
below. There is no passphrase reset, private-key reconstruction, agent-assisted
recovery, or fallback channel. A replacement requires the complete approval,
generation, enrollment, review, publication, and synchronization gates again.

### 10.2 Suspected or confirmed compromise

Suspicion is sufficient to revoke. Stop accepting statements immediately,
preserve public evidence, do not inspect or transmit the private key, and
assume every uncommitted or unvalidated signature is invalid. Re-review any
statement accepted since the last known-good custody event. Gate B remains or
becomes blocked; revocation does not silently approve a replacement.

### 10.3 Expiration

No new signature is accepted at or after `valid-before`. Rotation planning
starts at least 30 days before expiration. Expiration never extends itself and
does not select another key. If rotation has not completed, the independent
owner-digest path is unavailable and acquisition stays blocked.

### 10.4 Rotation

Normal rotation generates a fresh Ed25519 key through the complete owner-only
ceremony. It increments `generation` by exactly one, creates immutable public
files with the corresponding four-digit generation, and sets
`previous_state_sha256` to the lowercase SHA-256 of the complete prior
LF-terminated `state.json`. The rotation commit simultaneously:

1. adds the prior public-key line to `revoked_keys`;
2. adds the new generation's immutable `.pub` and `.fingerprint` files;
3. replaces the sole allowed-signers line with the new key and new validity
   window; and
4. replaces `state.json` with exactly one new `active` generation linked to
   the complete prior state digest.

There is never a grace period with two active keys. A new key does not validate
old signatures, and the old key does not authorize the new enrollment. The
owner must explicitly approve the new public fingerprint through the same
separate enrollment gate. If the old key was compromised, no cross-signature
from it is trusted.

### 10.5 Revocation

Revocation is a public, append-only state transition. The exact revoked
`ssh-ed25519` public-key line is added to `revoked_keys`; active state becomes
`revoked`; `allowed_signers` becomes a zero-byte file; and the replacement
state record links the prior state digest. The revocation commit must be
reviewed, pushed, GitHub-observed, synchronized, and recorded in the owner's
external last-seen checkpoint before it is considered durable.

Verification always checks both active state and `revoked_keys`; a key listed
as revoked is rejected even if an old allowed-signers file, signature, or Git
commit would otherwise verify. Rollback to a lower generation, a prior state
digest, an absent revocation, an earlier `valid-before`, or a repository commit
older than the owner's external last-seen enrollment/revocation checkpoint is
failure. Git history alone is not a rollback oracle.

Private material on a compromised or retired volume is handled only by the
owner under a separately approved media-destruction procedure. This document
does not authorize an agent to delete, overwrite, decrypt, inspect, mount, or
dispose of it.

## 11. Required adversarial tests

No test in this documentation slice uses or generates a key. The following
matrix is normative for the later public-enrollment review and statement
validation. Tests use public fixtures or separately controlled test keys; the
owner private key never enters a test harness, agent process, WSL, CI, or log.

| Case | Mutation | Required result |
|---|---|---|
| wrong key | valid SSHSIG from any non-enrolled Ed25519 key | reject; OpenSSH nonzero or precheck failure |
| wrong identity | verify with any `-I` value other than `agenticos-owner-digest-v1` | reject |
| wrong namespace | embedded or command namespace differs by one byte, case, suffix, or prefix | reject |
| wrong algorithm | RSA, ECDSA, certificate, Ed25519-SK, SHA-256 SSHSIG hash, or unknown algorithm | reject |
| altered bytes | change one JSON byte, key order, number type, whitespace, case, or terminal newline after signing | reject |
| wrong statement | correctly signed different schema, artifact, target, asset, member, commit, or extra key | reject before authority use |
| malformed signature | truncate, oversize, corrupt Base64, duplicate armor block, add decoded trailing bytes, unknown version, or non-ASCII | reject before or during OpenSSH verification |
| duplicate enrollment | second active key, duplicate identity/namespace/key, repeated generation, or multiple allowed-signers lines | reject enrollment |
| rollback | restore an older active state, allowed-signers line, empty revocation file, validity window, or repository commit | reject against linked state and external last-seen checkpoint |
| replacement | modify `.pub`, fingerprint, state, or allowed-signers key without an exact next-generation rotation | reject all cross-checks |
| revoked key | valid old signature with the key in `revoked_keys` or current state not `active` | reject even if historical allowed-signers content is supplied |
| expired/not-yet-valid | verification time outside enrolled interval | reject |
| mixed evidence | state from one generation with public key, fingerprint, signature, or revocation data from another | reject |
| duplicate decision | reuse an accepted `owner_decision_id` with the same or different digest | reject |
| tool drift | executable path, version, SHA-256, output grammar, or supported operation differs from §2 | stop for passive requalification |

Each negative test proves a nonzero terminal decision and no fallback. A crash,
timeout, skipped case, unavailable fixture, parser disagreement, output
truncation, or ambiguous result is a failure, not a pass. Before public
enrollment is committed, a fresh reviewer must inspect these cases against the
actual public evidence. Before a statement is recorded, validation reruns all
applicable canonical, identity, namespace, key, algorithm, expiry, revocation,
replacement, and rollback checks.

## 12. Seven separate gates

The process is deliberately non-atomic. Completion of one gate grants no later
gate.

1. **Approve this enrollment specification.** The owner reviews the exact
   committed specification and explicitly approves or rejects it. Current
   state: approved on 2026-08-12 for exact commit
   `a9bbbedc9104f59170268e3870b6de3bd11e5376` and specification SHA-256
   `c78b6bdbe956238aff9a8976b9d830fab4da248747ca63b313a0fea43563c156`.
2. **Owner manually generates the key outside the agent session.** The owner
   performs §§3–5 with all agents stopped. Current state: completed by the
   owner during the approved offline ceremony; no agent, model, or controller
   accessed private-key material.
3. **Record only the public key and fingerprint.** The owner supplies only the
   bounded public values; no digest is received. Current state: completed for
   generation 1; no owner digest was received.
4. **Adversarially review and commit the public enrollment.** Resolve every
   Critical and Important finding, publish the exact public-enrollment commit,
   synchronize both clones, and obtain separate owner fingerprint approval.
   Current state: completed and published at commit
   `3214251452e85549dedb0e97b0aeddc3df251e95`; fingerprint
   `SHA256:LQBNgC3HqdwfSWZr/7mvLlSUBwhodPOM0tFDdKZpIs4` separately approved.
5. **Owner later obtains the independent binary digest.** Its authority is
   independent of GitHub release hosting, release metadata, the OpenAI
   sidecar, and the later acquisition. Current state: Gates 2–4 are complete,
   but Gate 5 is blocked because no approved pre-existing independent OpenAI
   raw-member digest authority currently exists; no digest was obtained.
6. **Owner manually signs the exact canonical statement.** Use §§7–8 outside
   the agent session and disclose only public statement/signature evidence.
   Current state: blocked on Gate 5; no statement was created or signed.
7. **Validate and record the statement before separately considering Gate B.**
   Apply §§9–11, commit only bounded public evidence, publish/synchronize it,
   and then stop. Gate B remains unapproved and requires a later explicit owner
   decision. Current state: blocked on Gates 5–6; no statement was validated
   or recorded.

No gate may be combined with its successor, inferred from silence, backdated,
or treated as approval of acquisition, installation, execution,
authentication, provider access, or runtime work.

## 13. Explicit non-claims

- No owner key was generated, accessed, or enrolled by this approval-recording
  task, and no public-key evidence was received.
- No passphrase, private key, encrypted private-key bytes, backup, recovery
  material, volume identity, vault entry, or custody record was observed.
- No independent uncompressed-binary digest was received, validated, signed,
  or recorded.
- No owner identity is proven beyond future possession of the separately
  enrolled key under this procedure.
- NTFS ACLs do not protect against code already running as the owner; the
  offline unmounted-volume ceremony and procedural prohibition are essential.
- Passphrase protection does not make exfiltration of encrypted private-key
  bytes acceptable.
- SSHSIG authenticates exact statement bytes under the enrolled key and
  namespace. It does not timestamp the signature, prove source provenance,
  reproducibility, build-runner integrity, target safety, digest correctness,
  owner custody, or benign runtime behavior.
- Public enrollment does not qualify Windows or WSL OpenSSH generally, approve
  use of another OpenSSH build, authorize Git/SSH login, or grant controller
  runtime access to signing operations.
- No Codex archive, Sigstore bundle, verifier, binary, installer, package,
  provider route, credential, or authentication material was acquired,
  installed, executed, or accessed.
- Gate A, Branch O, and Gate 1 approval of the exact owner-key enrollment
  specification are the only approved decisions. Gate B and every acquisition,
  installation, execution, qualification, authentication, provider,
  production, self-hosting, other-artifact, other-target, and other-version
  authority remain blocked.

## 14. Adversarial review record

A fresh independent read-only review inspected this specification, its plan,
the complete artifact-authorization packet, the complete trust-policy
addendum, and the repository-preservation contract. It generated no key,
accessed no private key, executed no ceremony command, and mutated no file,
index, ref, or external state.

The first pass found zero Critical and seven Important issues. All Important
issues were resolved before staging:

| Finding | Resolution |
|---|---|
| verify-side `hashalg` would make Windows OpenSSH reject valid signatures | removed the verify option; retained mandatory `sha512` envelope parsing |
| verifier output and time were unbounded | added concurrent fixed-memory capture, monotonic 10-second timeout, process-tree termination, exact output grammar, and zero-stderr checks |
| exact commands omitted host-tool drift checks | added and invoked exact PowerShell/path/version/SHA-256 preflight before key generation, fingerprinting, signing, and verification |
| custody scripts did not prove ancestry, volume, ownership, ACL, or no-replace invariants | added volume/disk identity, BitLocker/NTFS, reparse, one-by-one creation, owner/DACL enumeration, and create-new controls |
| lifecycle transitions were ambiguous | added exact initial, rotation, revocation, replacement-after-revocation, and expiry transitions plus ordered exact-once revocation rules |
| decision-ID uniqueness had no authoritative ledger | added bounded hash-linked `AOSOWNERDIGESTINDEX/1`, immutable public objects, history search, and external checkpoint integration |
| plan diff commands ignored untracked new files | changed pre-stage review to `--no-index` and final review to exact-path staged/cached diff, check, and stat commands |

The review's two Minor observations were also resolved: canonical decision
dates and ASCII serialization are now strict; signature armor is exact; the
verification timeout is monotonic; and empty volume/disk identities are
rejected. Scoped re-review confirmed every prior finding addressed, zero new
Critical, and zero new Important findings. A final exact-byte confirmation of
this recorded revision is required before staging; any later content change
invalidates that confirmation and requires another review.

A fresh read-only review of the later Gate 1 approval-recording diff inspected
the complete governing authorization packet, trust-policy addendum, approved
specification, execution plan, and preservation contract. It found zero
Critical and zero Important issues. Its one Minor finding was that the plan's
Gate-ledger step omitted Gate 5 even though the normative ledger correctly kept
Gate 5 blocked; the plan now names Gate 5 explicitly. A scoped exact-byte
re-review of this resolution and review record is required before staging. Any
later content change invalidates that re-review.

## 15. Decision and exact next owner action

The owner approved the exact committed specification identified above on
2026-08-12. Gate 1 is complete. No key was generated, accessed, or enrolled by
this approval-recording task.

The exact next action is Gate 2, performed manually by the owner outside this
agent session. Before beginning, the owner stops this session and every other
agent/model/controller process, provisions and identifies the exact
`AOSOWNERKEY` and `AOSOWNERBACKUP` encrypted volumes and private vault required
by §§3–4, and then follows the exact §5 ceremony. The owner must not disclose or
provide the private key, passphrase, backup, or recovery material to an agent;
after Gate 2, only the bounded public evidence required by Gate 3 may be
provided for separate review.

Gate B remains unapproved after enrollment, digest receipt, signature, and
validation. It can be considered only through a later separate owner decision.
