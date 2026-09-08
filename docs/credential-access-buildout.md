# Credential Access — Tactic Buildout Plan

**Author:** Yara (Technology Strategist) · **Date:** 2026-09-08 · **Status:** Proposal, not yet greenlit
**Scope:** ATT&CK Credential Access (TA0006), Windows only.
**Companion to:** `docs/windows-detection-roadmap.md` — read that first for the cross-tactic
argument. This document does **not** re-argue tactic priority; that decision is made (Credential
Access) and this is the execution plan for it.

> Same standing caveat as the roadmap: this is a strategy proposal written by the ideation role,
> not architecture documentation. It describes what should be built and in what order.

## What changed since the roadmap was written

The roadmap ranked Credential Access **8th of 12** and recommended "verification, not content,"
largely because its highest-value remaining techniques are native-Windows-log detections and the
`service: security` → `splunk_windows` pipeline branch had never carried a production rule.

Two facts have since been confirmed that change the calculus:

1. **The lab has a DC and a domain-joined victim, both already wired into CI.**
   `ci_dev_workflow.yml` defines `atomic_verify_dc` on `runs-on: [self-hosted, X64, Windows, dc,
   windows-dc]`, and `check_test_routing.py` derives the serviced matrix as
   **`atomic/windows-dc, atomic/windows-victim, emulation/windows-victim`**. DC-side atomics are
   already routable — three rules (0024, 0030, 0031) are already declared against `windows-dc`.
2. **The DC Security log is already being forwarded to Splunk**, and is high-volume. Log-noise
   tuning is therefore a first-class design constraint in this plan, not an afterthought.

What has **not** changed: no rule in this repo has ever been *converted or deployed* against a
non-Sysmon index. Section 5 splits the plan on exactly that line.

---

## 1 · Technique inventory

Credential Access has **17 techniques / 50 sub-techniques** (attack.mitre.org TA0006 and this repo's
`outputs/reports/mitre_technique_map.json` agree exactly — no renumbering divergence in this tactic,
unlike the `T1562`→`T1685` case documented in the roadmap preamble).

Legend — **Cov:** ✅ covered · 🟡 partial · ❌ none. **Src:** where the detection realistically lives.

| Technique / sub | Win? | Cov | Src | Sysmon | Native Windows log | Notes |
|---|---|---|---|---|---|---|
| **T1003 OS Credential Dumping** | | | | | | |
| .001 LSASS Memory | ✔ | ✅ 0019–0022, 0025 | Sysmon | EID 10 (`GrantedAccess` on lsass), 1, 11 | Object Access → Kernel Object + SACL on the lsass process — **impractical** | Sysmon is decisively the right source |
| .002 Security Account Manager | ✔ | ✅ 0023, 0026, 0027 | Sysmon | EID 1, 11 | 4656/4663 + SACL on `\SAM` — impractical | |
| .003 NTDS | ✔ | ✅ 0024, 0030, 0031 | Sysmon | EID 1, 11 | 4662 on the NTDS object (noisy) | DC-side atomics already routed |
| .004 LSA Secrets | ✔ | ✅ 0023 | Sysmon | EID 1, 12/13 | — | |
| .005 Cached Domain Credentials | ✔ | ✅ 0028 | Sysmon | EID 1 | — | |
| .006 DCSync | ✔ | 🟡 0029 *(tool-name only)* | **Native** | EID 1 (cmdlet name only) | **Security 4662** + replication GUIDs | **The canonical detection is native and missing.** See §2. |
| .007/.008 (Linux) | ✘ | — | — | — | — | Out of scope |
| **T1040 Network Sniffing** | ✔ | ❌ | Sysmon | EID 1 (`netsh trace`, `pktmon`, `dumpcap`), 3 | — | 1 rule |
| **T1056 Input Capture** | | | | | | |
| .001 Keylogging | ✔ | ❌ | Sysmon | EID 8, 7 | — | Weak from either source |
| .002 GUI Input Capture | ✔ | ❌ | Sysmon | EID 1 (`Get-Credential` prompt abuse) | — | Low value, high FP |
| .004 Credential API Hooking | ✔ | ❌ | Sysmon | EID 7, 8 | — | Weak |
| **T1110 Brute Force** | | | | | | |
| .001 Password Guessing | ✔ | ❌ | **Native only** | — *(Sysmon has no auth events)* | **4625, 4771, 4776** | Rate detection — see §6 |
| .002 Password Cracking | ✔ | ❌ | *offline* | — | — | **Out of reach** — see §7 |
| .003 Password Spraying | ✔ | ❌ | **Native only** | — | **4625, 4771** (many accounts, few tries) | Rate detection |
| .004 Credential Stuffing | ✔ | ❌ | **Native only** | — | 4625/4776 | Folds into .001/.003 |
| **T1111 MFA Interception** | ✘/cloud | ❌ | — | — | — | Not endpoint-observable here |
| **T1187 Forced Authentication** | ✔ | ❌ | Both | EID 3, 22 (outbound SMB/WebDAV), 11 (`.scf`/`.url`/`.lnk` drop) | 4624 NTLM from unexpected source | 1 rule, Sysmon-led |
| **T1212 Exploitation for Cred Access** | ✔ | ❌ | — | EID 1 (weak) | — | No reliable signature |
| **T1528 Steal App Access Token** | cloud | ❌ | — | — | — | Out of scope |
| **T1539 Steal Web Session Cookie** | ✔ | ❌ | Sysmon | EID 10, 11 (browser cookie DB access) | — | 1 rule |
| **T1552 Unsecured Credentials** | | | | | | |
| .001 Credentials In Files | ✔ | ❌ | Sysmon | EID 1 (`findstr /si password`, `Select-String`) | — | Fold into one rule |
| .002 Credentials in Registry | ✔ | ❌ | Sysmon | EID 1 (`reg query … /f password`), 12/13 | — | Fold |
| .004 Private Keys | ✔ | ❌ | Sysmon | EID 1, 11 (`.pfx`, `.key`, `.pem` harvesting) | — | Fold |
| .006 Group Policy Preferences | ✔ | ❌ | Sysmon | EID 1 (`Get-GPPPassword`, SYSVOL `cpassword`) | Object Access → File Share on SYSVOL (noisy) | Fold |
| .003/.005/.007/.008 | ✘/cloud | — | — | — | — | Out of scope |
| **T1555 Credentials from Password Stores** | | | | | | |
| .003 Credentials from Web Browsers | ✔ | ❌ | Sysmon | EID 10, 11 (`Login Data`, `logins.json`) | — | Fold into one rule |
| .004 Windows Credential Manager | ✔ | 🟡 0028 *(cmdkey only)* | Sysmon | EID 1 (`vaultcmd`, `Get-StoredCredential`), 11 (`\Vault\`, `\Credentials\`) | — | Fold |
| .005 Password Managers | ✔ | ❌ | Sysmon | EID 10, 11 (KeePass/1Password DB paths) | — | Fold |
| .001/.002/.006 | ✘/cloud | — | — | — | — | Out of scope |
| **T1556 Modify Authentication Process** | | | | | | |
| .001 DC Authentication (skeleton key) | ✔ | 🟡 0022 *(`misc::skeleton` string)* | Both | EID 7 (DLL into lsass), 10 | — | Shared with Persistence |
| .002 Password Filter DLL | ✔ | ❌ | Sysmon | EID 12/13 (`Notification Packages`), 7 | — | Shared with Persistence |
| .005 Reversible Encryption | ✔ | ❌ | **Native** | — | **4738** (UAC flag change) | Low volume, clean |
| .008 Network Provider DLL | ✔ | ❌ | Sysmon | EID 12/13 (`NetworkProvider\Order`) | — | Shared with Persistence |
| .003/.004/.006/.007/.009 | ✘/cloud | — | — | — | — | Out of scope |
| **T1557 Adversary-in-the-Middle** | | | | | | |
| .001 Name Resolution Poisoning / SMB Relay | ✔ | ❌ | Both | EID 1 (Responder/Inveigh), 3, 22 | 4624 Type 3 NTLM relay patterns | 1 rule, Sysmon-led |
| .002 ARP Cache Poisoning | ✔ | ❌ | — | EID 1 (tool names only) | — | Weak |
| .003 DHCP Spoofing | ✔ | ❌ | — | — | System log (DHCP server role) | Marginal |
| **T1558 Steal or Forge Kerberos Tickets** | | | | | | |
| .001 Golden Ticket | ✔ | 🟡 0022 *(`kerberos::golden`)* | Native | EID 1 (tool string) | 4769/4768 anomaly + 4627 — **correlation-dependent** | Hard; see §6 |
| .002 Silver Ticket | ✔ | 🟡 0022 *(`kerberos::silver`)* | — | EID 1 (tool string) | **none — never touches the DC** | **Out of reach**, see §7 |
| .003 Kerberoasting | ✔ | ⚠ *tag claimed by 0022 on `Rubeus.exe` filename only* | **Native** | EID 1 (tool names) | **4769** + RC4 encryption type | Rate detection; the flagship native rule |
| .004 AS-REP Roasting | ✔ | ❌ | **Native** | EID 1 (tool names) | **4768** pre-auth type 0 | Near-single-event; cleanest native win |
| .005 Ccache Files | ✔ | ❌ | Sysmon | EID 11 (`.kirbi`, `.ccache` writes) | — | Fold into the endpoint tooling rule |
| **T1606 Forge Web Credentials** | cloud | ❌ | — | — | — | Out of scope |
| **T1621 MFA Request Generation** | cloud | ❌ | — | — | — | Out of scope |
| **T1649 Steal or Forge Auth Certificates** | ✔ | ❌ | Native | EID 1 (`Certify`, `Certipy` names) | 4886/4887 — **needs an AD CS server** | **Out of reach**, see §7 |

**Read of the table:** the Sysmon half of this tactic is largely *already built* (13 rules across
T1003) — what remains on Sysmon is peripheral credential theft (browsers, vaults, unsecured
credentials, sniffing). Everything of first-rank value that is still missing — **DCSync-by-4662,
Kerberoasting, AS-REP roasting, password spraying** — is native-log only. That is the shape of this
buildout: a modest Sysmon track and a high-value native track that is gated on pipeline work.

---

## 2 · Native-log detection reference

Every native detection this plan proposes, with what must be enabled to produce the event.

**Tier** = where the event is generated: **DC** (domain controller only), **Member** (any
domain-joined server/workstation), **Any**.

| # | Detection | Event ID(s) | auditpol category → subcategory (S/F) | Tier | Volume | Tuning approach |
|---|---|---|---|---|---|---|
| N1 | **DCSync** (T1003.006) | **4662** | DS Access → **Audit Directory Service Access** (Success) **+ SACL** (see §3) | **DC** | **Low if the SACL is scoped; catastrophic if not** | Filter `Properties` to the three replication GUIDs. Exclude DC machine accounts (`*$` that are members of Domain Controllers) and directory-sync service accounts (`MSOL_*`, Azure AD Connect, `AAD_*`). **Reduce at the SACL, not in SPL.** |
| N2 | **Kerberoasting** (T1558.003) | **4769** | Account Logon → **Audit Kerberos Service Ticket Operations** (Success) | **DC** | **Very high** — one event per service-ticket request | Ticket Encryption Type `0x17`/`0x18` (RC4) only; `Failure Code = 0x0`; exclude `Service Name = krbtgt`; **exclude machine accounts** (`Service Name` ending `$`) — this alone removes the bulk. Then **threshold**: distinct service names per account per window. |
| N3 | **AS-REP Roasting** (T1558.004) | **4768** | Account Logon → **Audit Kerberos Authentication Service** (Success) | **DC** | Moderate | `Pre-Authentication Type = 0` **and** Ticket Encryption Type `0x17`. Very few legitimate accounts have pre-auth disabled — inventory them once and allowlist. Near-zero FP after that. |
| N4 | **Password spraying / brute force** (T1110.001/.003/.004) | **4625**, **4771**, **4776** | Logon/Logoff → **Audit Logon** (Failure); Account Logon → **Audit Kerberos Authentication Service** (Failure); Account Logon → **Audit Credential Validation** (Failure) | **DC** + Member | **High** | Spraying is *many accounts × few failures*, guessing is *one account × many failures* — they need **different aggregations**, not one rule. Exclude machine accounts and known service-account churn. Threshold on distinct-target-count per source per window. Status/sub-status codes (`0xC000006A` bad password vs `0xC0000064` bad user) separate spray from enumeration. |
| N5 | **Reversible encryption enabled** (T1556.005) | **4738** | Account Management → **Audit User Account Management** (Success) | **DC** | Low | Filter on the `userAccountControl` change containing `ENCRYPTED_TEXT_PASSWORD_ALLOWED`. Genuinely rare; almost no tuning needed. |
| N6 | **Golden Ticket indicators** (T1558.001) | **4769**, **4768**, **4627** | Kerberos Service Ticket Ops (S); Kerberos Auth Service (S); Logon/Logoff → **Audit Group Membership** (Success) | **DC** | High | Hard. Requires correlating a 4769 against the *absence* of a preceding 4768 for the same account — a stateful join, not a filter. Cheaper partial signals: anomalous ticket lifetime, a domain field that doesn't match, RID 500 in 4627 where it shouldn't be. **Treat as stretch, not committed scope.** |
| N7 | **NTLM relay / forced auth** (T1557.001, T1187) | **4624** (Type 3) | Logon/Logoff → **Audit Logon** (Success) | Member + DC | **Very high** | Only viable with tight scoping: `Authentication Package = NTLM` where the workstation name and source do not correspond. Sysmon EID 3/22 is the better primary; treat this as corroboration only. |

### On volume, given the DC log is already high-volume

Three of the seven (N2, N4, N7) sit on the noisiest subcategories on a domain controller. The
principle to apply, in order of preference:

1. **Reduce at the source.** Scope the 4662 SACL narrowly (§3). Do **not** enable *Audit Detailed
   File Share* (5145) for this tactic — nothing here needs it and it is the single largest volume
   generator on a DC.
2. **Reduce at ingest.** Forwarder-side `props.conf`/`transforms.conf` filtering (drop machine-account
   4769s before indexing) is far cheaper than filtering in every rule. This is a Splunk-admin task,
   not a detection-content task, and should be settled before N2 ships.
3. **Reduce in the rule.** Encryption-type and `$`-suffix filters, then thresholds.

Getting this order wrong means paying for the noise forever in license volume, and it is a decision
that has to be made once, up front — which is why §3 is a prerequisite list rather than a rule task.

---

## 3 · DC audit policy checklist *(prerequisite — hand to whoever administers the DC)*

None of the native rules in §5's Track B can be written, let alone verified, until these are in
place. **This is a hand-off list, not work for this team.**

### 3.1 Advanced audit policy — set via GPO on the Domain Controllers OU

`Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy
Configuration → Audit Policies`

| Category | Subcategory | Setting | Needed for |
|---|---|---|---|
| Account Logon | **Kerberos Service Ticket Operations** | **Success** | N2 Kerberoasting, N6 |
| Account Logon | **Kerberos Authentication Service** | **Success and Failure** | N3 AS-REP, N4 (4771), N6 |
| Account Logon | **Credential Validation** | **Success and Failure** | N4 (4776) |
| Logon/Logoff | **Logon** | **Success and Failure** | N4 (4625), N7 (4624) |
| Logon/Logoff | **Group Membership** | Success | N6 (4627) — optional, stretch |
| Account Management | **User Account Management** | **Success** | N5 (4738) |
| DS Access | **Directory Service Access** | **Success** | **N1 DCSync (4662)** |
| DS Access | Directory Service Changes | Success | Not used by this plan; listed to say *don't* enable it for us |

Equivalent `auditpol` verification (run on the DC — **use this to verify, set via GPO**, because a
local `auditpol /set` is overwritten at the next policy refresh):

```
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
auditpol /get /subcategory:"Kerberos Authentication Service"
auditpol /get /subcategory:"Credential Validation"
auditpol /get /subcategory:"Logon"
auditpol /get /subcategory:"User Account Management"
auditpol /get /subcategory:"Directory Service Access"
```

Each should report the Success / Success and Failure setting from the table above.

### 3.2 The SACL requirement for 4662 (DCSync) — the part that is always missed

**Enabling "Audit Directory Service Access" alone produces no DCSync events.** 4662 is only emitted
for objects that carry a matching System Access Control List entry. Without the SACL below, N1 is
silently dead — the rule deploys, the audit policy looks correct, and nothing ever fires.

On the **domain naming context object** (the domain root, e.g. `DC=corp,DC=example,DC=com`):

1. ADSI Edit → connect to *Default naming context* → right-click the domain object → **Properties**
   → **Security** → **Advanced** → **Auditing**.
2. **Add** an audit entry:
   - **Principal:** `Everyone`
   - **Type:** `Success`
   - **Applies to:** `This object only`
   - **Permissions:** tick **only** these three:
     - **Replicating Directory Changes** (`DS-Replication-Get-Changes`)
     - **Replicating Directory Changes All** (`DS-Replication-Get-Changes-All`)
     - **Replicating Directory Changes In Filtered Set** (`DS-Replication-Get-Changes-In-Filtered-Set`)

**Scope it exactly this narrowly.** "Applies to: This object only" plus three specific permissions
is the difference between a low-volume, high-signal event stream and flooding the Security log with
4662 for every directory read in the domain. Broad 4662 auditing is a well-known way to render a DC's
Security log unusable.

The GUIDs the rule will filter on (they appear in 4662's `Properties` field):

| Right | GUID |
|---|---|
| DS-Replication-Get-Changes | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-All | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-In-Filtered-Set | `89e95b76-444d-4c62-991a-0facbeda640c` |

### 3.3 Not required — stated so nobody enables them "to be safe"

- **Audit Detailed File Share (5145)** — very large volume, nothing in this plan uses it.
- **Audit Process Creation (4688)** — the estate already gets process telemetry from Sysmon EID 1;
  4688 would duplicate it at DC volume for no gain here.
- **SACLs on LSASS / SAM / NTDS files** for T1003.001–.005 — technically produces 4656/4663, but is
  impractical to scope and is already covered better by Sysmon EID 10/11.
- **Audit Certification Services** — requires an AD CS server, which the lab does not have (§7).

### 3.4 Forwarder-side

Confirm with the Splunk admin, before Track B starts:
- Which index the DC Security channel lands in (this becomes each rule's `custom.splunk.index` —
  see §6 for why that is a per-rule data value and needs no code change).
- Whether machine-account 4769 events can be dropped at the forwarder rather than indexed.

---

## 4 · Existing-rule verification campaign (0019–0031)

### The finding that reframes this section

All 13 rules are `NOT_VERIFIED`. **This is not 13 individually-blocked rules — it is one forgotten
follow-up.** Commit `ef39dce` (2026-08-17):

> `chore(rules): disable atomic testing on all rules except DETECT-2026-0007`
> *"Temporary, mechanical only … Keeps the dev pipeline's live attack+verify cycle scoped to the one
> rule under active investigation (the search-prefix dispatch fix) … **Re-enable once the pipeline
> fix is verified working.**"*

The search-prefix dispatch fix **is** verified working — it is documented in
`sigma_to_spl.py::_inject_index_prefix` and DETECT-2026-0009 passed against it on 2026-09-07. Rules
have been re-enabled one at a time since (0008, 0009), but the blanket re-enable never happened.
**Three weeks of "unverified" is bookkeeping debt, not a technical blocker.**

Every one of the 13 already carries a complete, correctly-routed `custom.testing` block with atomic
test numbers. `check_test_routing.py` reports **0 unrouted rules**. The runner does `-GetPrereqs`
before and `-Cleanup` after each test by default (`run_atomic.ps1`).

**Register drift worth flagging to Kwame:** remediation item 2.8 states *"Ma egy szabály sincs ilyen
állapotban"* (no rule is in the `type: atomic, enabled: false` state) — written 2026-08-06, eleven
days before `ef39dce` put 22 rules into exactly that state. The item's reasoning is still sound; its
factual claim is stale.

### Group A — Quick wins (flip `enabled: true`, nothing else) — 9 rules

Atomics already specified, runner already serviced, technique safe on a lab VM.

| Rule | Technique | Atomics | Runner | Note |
|---|---|---|---|---|
| 0020 LSASS via comsvcs MiniDump | T1003.001 | test 2 | windows-victim | |
| 0021 LSASS via ProcDump | T1003.001 | tests 1, 9 | windows-victim | `-GetPrereqs` fetches ProcDump |
| 0023 SAM/LSA registry hive export | T1003.002/.004 | 1, 8 / 1 | windows-victim | |
| 0026 SAM/LSA hive copy via esentutl | T1003.002 | test 3 | windows-victim | |
| 0027 Credential hive via VSS | T1003.002 | test 5 | windows-victim | Creates a shadow copy — confirm `-Cleanup` removes it |
| 0028 Cached credential enum via cmdkey | T1003.005 | test 1 | windows-victim | Trivially safe |
| **0024 NTDS dump attempt** | T1003.003 | 3, 6, 9 | **windows-dc** | Already correctly routed to the DC job |
| **0030 Symlink to VSS device path** | T1003.003 | test 8 | **windows-dc** | |
| **0031 Low-level NTFS acquisition** | T1003.003 | 10, 11 | **windows-dc** | |

**Recommended action:** re-enable as a single batch on one dev run, then triage whatever fails.
Doing them individually costs nine CI cycles to learn the same thing. Expect some genuine FAILs —
that is the point of the campaign, and a FAIL on a rule that has never been tested is information,
not a regression.

### Group B — Needs work (3 rules)

| Rule | Blocker | What it takes |
|---|---|---|
| **0019** LSASS access by non-standard process | `type: emulation` with **no emulation commands defined**. `run_atomic.ps1` skips it with *"tester is 'emulation' but no custom tests are defined"*, and the schema **requires** `custom.testing.custom[]` when `enabled: true` + `type: emulation` — so flipping the flag **fails CI schema validation**. It has been non-functional since creation. | Either write a `custom[]` emulation command (a benign `OpenProcess` against lsass with a matching `GrantedAccess` mask), **or** convert it to `type: atomic` reusing T1003.001 tests. The latter is cheaper and is what the sibling rules do. |
| **0025** LSASS dump via Task Manager / file create | Identical blocker to 0019. The Task Manager path is inherently GUI-driven, which is *why* it was made emulation. | Write a `custom[]` command that produces the file artefact directly (e.g. a MiniDumpWriteDump to `*lsass*.dmp`), since the rule's second branch keys on `TargetFilename` regardless of the producing process. |
| **0022** Known credential dumping tool execution | Atomics **download and execute Mimikatz** (T1003.001 tests 3, 4, 6, 10). Defender will quarantine it — `-GetPrereqs` fails, the test reports a false FAIL, and the runner accumulates detections. | A **policy decision, not a code change**: an AV exclusion path on the victim runner, or accepting that this rule stays emulation-verified only. Escalate to the user — this is a lab-security tradeoff nobody on the team should make unilaterally. |

### Group C — Re-scope, not retire (0 retirements)

Nothing here should be deleted. Two items need a scope correction rather than a verification fix:

- **0022's MITRE tags overclaim.** It tags `T1558.001/.002/.003` (Golden/Silver/Kerberoasting).
  `.001`/`.002` are defensible via the `kerberos::golden` / `kerberos::silver` CLI strings, but
  **`.003` Kerberoasting rests solely on the string `Rubeus.exe` appearing as an image name.** Once
  0038 (real 4769-based Kerberoasting) ships, this tag should move to it. Related to the tag-vs-logic
  audit already proposed for Bjorn in the main roadmap.
- **0029's DCSync detection** keys on the DSInternals cmdlet name only. Its atomic (T1003.006 test 2)
  is routed to `windows-victim`, which is *correct for this rule* — the detection is on the invoking
  host's process telemetry — but it requires Domain Admin credentials on the victim runner to
  actually execute. **Credential provisioning question for the lab owner.** The rule is not wrong;
  it is just not the canonical DCSync detection, which is 4662 (rule 0037 below).

---

## 5 · New-rule sequencing

### ⚠ DETECT-id collision — Gaz to resolve

`docs/windows-detection-roadmap.md` tentatively assigns **0033–0041** to nine *non*-Credential-Access
rules (service creation, scheduled tasks, UAC bypass, …). None of those exist yet — they are labels
in a proposal document, not allocated IDs, and `scripts/new_rule.py` computes the next free ID at
scaffold time regardless of what any document says.

**Recommendation: this Credential Access plan takes 0033–0041, and the roadmap's block is marked
superseded** — IDs should reflect actual build order, and Credential Access is the tactic that was
chosen. The roadmap's summary table should get a one-line note rather than being renumbered in place.
If Gaz prefers the opposite, the CA plan renumbers to 0042–0050 with no other change.

*(Historical note so nobody is confused reading `git log`: `DETECT-2026-0033` was used once before
and renumbered away in commit `3a5caea` — `chore(rules): renumber DETECT-2026-0033 -> DETECT-2026-0001`.
It is genuinely free; `discover()` only sees files that exist.)*

### Track A — buildable today on Sysmon (no pipeline work, no prerequisites)

Ship these while Track B's audit policy and pipeline work is in flight.

| ID | Rule | Techniques | Sysmon | Notes |
|---|---|---|---|---|
| **0033** | **Credentials from Password Stores** | T1555.003, .004, .005 | EID 1, 10, 11 | Browser `Login Data`/`logins.json` access, `vaultcmd`/`Get-StoredCredential`, `\AppData\…\Vault\`, KeePass/1Password DB reads. Complements 0028 (which covers `cmdkey` enumeration only). |
| **0034** | **Unsecured Credential Harvesting** | T1552.001, .002, .004, .006 | EID 1, 11 | `findstr /si password`, `Select-String -Pattern password`, `reg query … /f password`, `.pfx`/`.pem` sweeps, `Get-GPPPassword` / SYSVOL `cpassword`. High-precision command forms only. |
| **0035** | **Kerberos Ticket Tooling on the Endpoint** | T1558.003, .004, .005 | EID 1, 11 | Rubeus `kerberoast`/`asreproast`/`ptt`/`dump`, `Invoke-Kerberoast`, `Get-DomainSPNTicket`, `.kirbi`/`.ccache` file writes. **Explicitly the endpoint half** — the DC half is 0038/0039. Must state non-overlap with 0018 and 0022. |
| **0036** | **Network Sniffing and AitM Tooling** | T1040, T1557.001 | EID 1, 3 | `netsh trace start`, `pktmon`, `dumpcap`, Responder/Inveigh invocation. |

### Track B — needs the `service: security` pipeline proven first

Ordered so the **simplest possible native rule proves the pipeline**, before anything depends on
aggregation.

| ID | Rule | Techniques | Event | Prereq | Notes |
|---|---|---|---|---|---|
| **0037** | **DCSync via Directory Replication** | T1003.006 | **4662** | §3.1 DS Access + **§3.2 SACL** | **The pipeline proof-point.** Single-event match, no aggregation, low volume once scoped, and it closes the real gap 0029 leaves. Do this first in Track B — if the `splunk_windows` path has a problem, find it on the simplest rule. |
| **0038** | **AS-REP Roasting** | T1558.004 | **4768** | Kerberos Auth Service (S) | Second-simplest: a field filter (`Pre-Auth Type = 0` + RC4), no threshold. Near-zero FP once pre-auth-disabled accounts are inventoried. |
| **0039** | **Kerberoasting via Service Ticket Anomaly** | T1558.003 | **4769** | Kerberos Svc Ticket Ops (S) | **First aggregation rule — `raw_query`, see §6.** Also the rule that lets 0022's `.003` tag be corrected. |
| **0040** | **Password Spraying and Brute Force** | T1110.001, .003, .004 | **4625, 4771, 4776** | Audit Logon (F), Kerberos Auth (F), Credential Validation (F) | **Aggregation, `raw_query`.** Likely *two* rules in practice — spray (many accounts × few) and guessing (one account × many) need different aggregations. Budget for two. |
| **0041** | **Authentication Process Tampering** | T1556.005, .002, .008 | **4738** + Sysmon 12/13 | Audit User Account Mgmt (S) | Hybrid: reversible-encryption flag from 4738, password-filter/network-provider DLL from Sysmon registry. May need splitting if a rule cannot span two log sources cleanly — a question 0037 will answer. |

**Stretch, not committed:** Golden Ticket (N6) needs stateful correlation across 4768/4769 and is
described in §6 as beyond current pipeline capability. Do not schedule it.

### Recommended interleave

1. **Immediately, in parallel:** Group A re-enable batch (§4) · hand §3 checklist to the DC admin.
2. **Track A 0033–0034** while waiting on audit policy.
3. **0037** as soon as the audit policy and SACL land — this is the go/no-go on the native pipeline.
4. Everything else follows 0037's outcome.

---

## 6 · The aggregation-rule question

**Kerberoasting, spraying and brute force are rate/threshold detections, not single-event matches.**
Whether the pipeline can express them was checked against the code, not assumed.

### Finding: Sigma correlation rules cannot be used in this repo — verified

The toolchain *supports* them: `.github/requirements.txt` pins **pySigma 1.5.0** and
**pysigma-backend-splunk 2.1.0**, both of which have Sigma correlation support. **The blocker is
repo integration, not the library.** Four independent obstacles, each verified in the source:

1. **Single-document YAML loading.** `scripts/lib/rules.py:119` and
   `scripts/convert/sigma_to_spl.py:490` both call `yaml.safe_load`. Sigma correlation rules are
   **multi-document** YAML (base rules plus a correlation document, `---`-separated). `safe_load`
   raises on a multi-document stream. A correlation rule cannot even be *read*.
2. **One-rule-one-file, keyed by `detect_id`.** `discover()` globs `rules/sigma/*.yml` and every
   downstream consumer (converter, validator, stats generator, meta sidecar, verification verdict
   store) assumes exactly one `detect_id` per file. A correlation set is inherently N documents.
3. **The schema has no `name` field.** Correlation documents reference their base rules by Sigma's
   `name:` key. `docs/schemas/sigma_schema.json`'s allowed top-level properties are
   `author, custom, date, description, detect_id, detection, falsepositives, fields, level,
   logsource, modified, references, status, tags, title, version` — no `name`.
4. **`detection` is schema-`required`.** A pure correlation document has no `detection:` block.

**This is a real, unsolved pipeline capability gap.** It is worth raising as its own roadmap item —
not because this plan is blocked (it isn't, see below), but because the workaround has costs that
compound with every aggregation rule added.

### The workaround: `custom.splunk.raw_query` — and it works cleanly

`custom.splunk.raw_query` takes raw SPL and emits it verbatim. Verified behaviour:

- **The backend is bypassed entirely.** `sigma_to_spl.py:524-530` — *"A raw_query rule never reaches
  the backend."* No pySigma involvement, so none of the four obstacles above apply.
- **The index prefix is still enforced.** `enforce_index_prefix` runs for raw_query rules too
  (`sigma_to_spl.py:542-545`), and `_inject_index_prefix` **replaces** a leading `index=…` with the
  rule's `custom.splunk.index`. **This is the important good news for Track B:** pointing a rule at
  the DC Security index is a *per-rule data value*, not a code change. `config/backends.yml` already
  routes `service: security` → `splunk_windows`.
- **Caveat — generating commands.** A query opening with `| tstats` is left alone and only warns if
  it names no index (`_GENERATING_COMMANDS`). If an aggregation rule uses `tstats` for performance,
  it must name its own index explicitly. A `| stats` **after** a base search is fine and gets the
  prefix normally.
- **Caveat — placeholder `detection:`.** A raw_query rule still needs a schema-valid `detection:`
  block that is never evaluated (documented in `.claude/skills/sigma-rule-authoring`).
- **Caveat — review surface.** Bjorn reviews raw SPL text, not a `detection:` block. Worth flagging
  on the dispatch so the review is scoped correctly.
- **Caveat — version bumps.** Per the authoring skill, a change to `raw_query` **does** trigger a
  version bump; changes to other `custom` fields do not.

### Practical consequence

- 0037, 0038, 0041 — single-event field matches → **normal Sigma `detection:` blocks**.
- 0039, 0040 — rate/threshold → **`custom.splunk.raw_query` with `| stats … | where count > N`**.
- Golden Ticket (N6) — needs a stateful *absence* join across event types. Expressible in raw SPL in
  principle, but fragile and expensive. **Out of committed scope.**

**Flag for Gaz:** if Credential Access is followed by more rate-based work, native Sigma correlation
support becomes a genuine pipeline item (touching `lib/rules.py`, `sigma_to_spl.py`,
`validate_sigma.py`, `generate_stats.py`, and the schema). Two raw_query rules is an acceptable
workaround; ten would be technical debt. Not proposing it now — recording the threshold at which it
stops being a workaround.

---

## 7 · What stays out of reach

Listed so nobody plans for them or counts them as gaps.

| Item | Technique | Why |
|---|---|---|
| **AD CS / certificate abuse (ESC1–ESC8)** | **T1649** | The lab has **no Certificate Authority**. Events 4886/4887 and the *Audit Certification Services* subcategory require an AD CS role that does not exist. Detecting the client-side tooling (`Certify.exe`, `Certipy`) is possible via Sysmon EID 1, but that is tool-name matching, not technique coverage — do not tag T1649 on the strength of it (the same mistake 0022 made with T1558.003). |
| **Silver Tickets** | **T1558.002** | Structural, not a lab limitation. A silver ticket is forged for a *service* account and presented directly to the target service — **it never contacts the KDC**, so no DC event is generated by design. Detection requires service-side ticket validation telemetry the estate does not collect. `kerberos::silver` in a command line (already in 0022) is the only realistic signal, and that only catches Mimikatz being used to *make* one. |
| **Offline password cracking** | **T1110.002** | Happens on adversary-controlled infrastructure after the hash leaves the estate. Nothing on the endpoint or the DC observes it. The detectable step is the *theft* (T1003, T1558.003), which is covered. |
| **Cloud credential techniques** | T1528, T1606, T1621, T1552.005, T1555.006, T1556.007/.009 | No cloud identity provider in scope. These are Entra/AWS/GCP audit-log detections with no Windows endpoint or DC footprint. |
| **Linux credential access** | T1003.007, .008, T1552.003, T1556.003 | No Linux victim in CI. Note the schema *permits* `runner: linux-victim` in anticipation, but `check_test_routing.py` confirms no job services it. |
| **MFA interception / MITM on MFA** | T1111 | Requires network-path telemetry not collected. |
| **Native LSASS/SAM file-access auditing** | T1003.001–.005 via 4656/4663 | Technically possible with SACLs on the LSASS process and hive files, but impractical to scope and comprehensively worse than the Sysmon EID 10/11 coverage already built. Deliberately declined, not overlooked. |

---

## Provenance

Every claim about repo behaviour in this document was verified against source, not inferred:

- `.github/workflows/ci_dev_workflow.yml` — `atomic_verify_dc` job, runner labels, `ATOMIC_RUNNER` /
  `ATOMIC_TESTER_TYPE` per job
- `scripts/validate/check_test_routing.py` (executed) — serviced matrix
  `atomic/windows-dc, atomic/windows-victim, emulation/windows-victim`; 0 unrouted rules
- `scripts/convert/sigma_to_spl.py` — `yaml.safe_load` (L490), raw_query bypass (L524–530),
  `enforce_index_prefix` for both branches (L542–545), `_inject_index_prefix` semantics (L189–304)
- `scripts/lib/rules.py:119` — `yaml.safe_load` in the shared loader
- `scripts/atomic/run_atomic.ps1` — `-GetPrereqs` / `-Cleanup` defaults, emulation-test collection
  and the "no custom tests are defined" skip path
- `docs/schemas/sigma_schema.json` — allowed top-level properties, `custom.splunk`
  (`additionalProperties: false`), `custom.testing` conditional requirements
- `config/backends.yml` — `by_service: security → splunk_windows`
- `.github/requirements.txt` — pySigma 1.5.0, pysigma-backend-splunk 2.1.0, sigma-cli 3.1.0
- `git show ef39dce`, `git log` — the 2026-08-17 bulk testing disable and its stated intent
- `outputs/reports/stats.json`, `rules/sigma/*.yml` — verdicts and `custom.testing` blocks
- `audit/remediation-plan.md` item 2.8 — the stale "no rule is in this state" claim
- attack.mitre.org TA0006 + `outputs/reports/mitre_technique_map.json` — technique enumeration (17/50, identical)

**Not verified empirically:** the `splunk_windows` pipeline's field-mapping output. `sigma-cli` and
pySigma are not installed in this environment, so no test conversion could be run. Whether that
pipeline's CIM field names match the forwarded DC Security data is **the single biggest unknown in
Track B**, and is exactly what rule 0037 is sequenced first to answer.
