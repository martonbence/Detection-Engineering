---
mitre_id: T1003
mitre_type: technique
name: OS Credential Dumping
aliases:
  - T1003
  - OS Credential Dumping
url: https://attack.mitre.org/techniques/T1003/
tactic:
  - "[[TA0006 - Credential Access]]"
subtechnique_count: 8
platforms:
  - Windows
  - Linux
  - macOS
de_priority: kritikus
coverage: részleges
status: kész
---
# T1003 — OS Credential Dumping

## Lényeg

A támadó az operációs rendszer **saját hitelesítőadat-tárolóiból** próbál felhasználóneveket, jelszó-hasheket vagy cleartext jelszavakat kinyerni. A közös nevező nem az eszköz és nem a módszer, hanem a **cél tárolója**: minden altechnika ugyanarra a kérdésre más választ ad — *hol tartja a Windows a hitelesítő adatot, és hogyan lehet hozzáférni.*

Ez a különbség a detekció szempontjából is meghatározó: mindegy, hogy Mimikatz, ProcDump vagy egy saját írású eszköz csinálja, a tárolóhoz **ugyanazon a néhány úton** lehet hozzáférni (LSASS folyamat megnyitása, registry hive kiexportálása, NTDS.dit fájl kimásolása).

Szinte minden altechnika **helyi rendszergazdai vagy SYSTEM jogot feltételez**, tehát a technika megjelenése önmagában azt is jelenti, hogy a támadó már túl van a [Privilege Escalation]-n. A

> [!quote] MITRE definíció
> Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password.

## Mihez vezet

A megszerzett hitelesítő adatot (hash, ticket, jelszó) a támadó tipikusan a [TA0008 - Lateral Movement] felé viszi: célja, hogy a lopott azonosítóval — pass-the-hash vagy pass-the-ticket úton — további rendszerekre terjeszkedjen a hálózaton belül, immár legitim bejelentkezésnek látszó módon.

## Altechnikák

- [[T1003.001 - LSASS Memory]] — a **futó** LSASS folyamat memóriájából, ahol az aktív munkamenetek hitelesítő adatai vannak; a legértékesebb, mert itt cleartext jelszó és Kerberos ticket is lehet
- [[T1003.002 - Security Account Manager]] — a **helyi** fiókok hasheiből, a SAM registry hive-ból; domainen kevés értéke van, de a helyi admin jelszó újrafelhasználása miatt mégis veszélyes
- [[T1003.003 - NTDS]] — a **teljes domain** összes fiókjának hashe, az NTDS.dit adatbázisból; a DC-n, és ez a maximum, amit el lehet érni
- [[T1003.004 - LSA Secrets]] — a SECURITY hive-ban tárolt **szolgáltatásfiók-jelszavak** és gyorsítótárazott titkok, gyakran cleartextben visszafejthetően
- [[T1003.005 - Cached Domain Credentials]] — a végponton **offline bejelentkezéshez** eltárolt domain hitelesítő adatok (mscash); lassan törhető, de nem hálózatképes
- [[T1003.006 - DCSync]] — nem a lemezről olvas, hanem **DC-nek adja ki magát** és a replikációs protokollon kéri le a hasheket; nem kell hozzá kód a DC-n
- **T1003.007 / T1003.008** (Proc Filesystem, /etc/passwd és /etc/shadow) — Linux, ebben a környezetben hatókörön kívül

## Összehasonlítás

|                    | [[T1003.001 - LSASS Memory\|.001 LSASS]]                        | [[T1003.002 - Security Account Manager\|.002 SAM]] | [[T1003.003 - NTDS\|.003 NTDS]]      | [[T1003.004 - LSA Secrets\|.004 LSA]]               | [[T1003.005 - Cached Domain Credentials\|.005 Cached]] | [[T1003.006 - DCSync\|.006 DCSync]]               |
| ------------------ | --------------------------------------------------------------- | -------------------------------------------------- | ------------------------------------ | --------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------- |
| **Hol tárolódik**  | LSASS folyamat memóriája                                        | `HKLM\SAM` hive                                    | `%SystemRoot%\NTDS\ntds.dit`         | `HKLM\SECURITY\Policy\Secrets`                      | `HKLM\SECURITY\Cache`                                  | AD adatbázis, replikáción keresztül               |
| **Mit szerez meg** | aktív munkamenetek: NTLM hash, Kerberos ticket, néha cleartext jelszó | helyi fiókok NTLM hashei                           | a **teljes domain** összes hashe     | szolgáltatásfiók-jelszavak, gyakran cleartextben | domain hashek offline használatra (mscash2)            | tetszőleges domain fiók hashe, akár `krbtgt`      |
| **Hol fut**        | bármely végpont                                                 | bármely végpont                                    | **DC**                               | bármely végpont                                     | bármely domain-tag végpont                             | **bármely gép** — a DC csak válaszol              |
| **Jogosultság**    | admin / SYSTEM                                                  | admin / SYSTEM                                     | DC admin                             | admin / SYSTEM                                      | admin / SYSTEM                                         | replikációs jog (DS-Replication-Get-Changes)      |
| **Eszközök**       | Mimikatz, comsvcs.dll, ProcDump, nanodump, Task Manager         | `reg save`, esentutl, VSS, Impacket secretsdump    | ntdsutil, VSS, esentutl, DSInternals | Mimikatz `lsadump::secrets`, secretsdump            | Mimikatz `lsadump::cache`, secretsdump                 | Mimikatz `lsadump::dcsync`, DSInternals, Impacket |
| **Telemetria**     | Sysmon EID 10, 1, 11                                            | Sysmon EID 1, 11                                   | Sysmon EID 1, 11                     | Sysmon EID 1, 12/13                                 | Sysmon EID 1                                           | **natív: Security 4662** (Sysmon vak rá)          |
| **Detekció helye** | végpont                                                         | végpont                                            | DC végpont                           | végpont                                             | végpont                                                | **DC címtár-audit**                               |
| **DE prioritás**   | kritikus                                                        | magas                                              | kritikus                             | magas                                               | alacsony                                               | kritikus                                          |

A táblázat legfontosabb sora a **Telemetria**: öt altechnika végponti folyamat-telemetriából látszik, a hatodik (DCSync) viszont **egyáltalán nem** — ott nem indul folyamat a DC-n, csak egy hálózati replikációs kérés érkezik. Ezért a T1003 lefedése nem oldható meg egyetlen adatforrásból.

## Mitigáció

A hitelesítőadat-tárolók léte magának az operációs rendszernek a működéséből fakad, ezért a technika nem szüntethető meg — a támadási felület viszont érdemben csökkenthető:

- **Credential Guard** (VBS-alapú izoláció) — kiveszi a titkokat az LSASS címteréből, ezzel a .001 nagy részét használhatatlanná teszi
- **LSA Protection / RunAsPPL** — az LSASS védett folyamatként fut, így a szokásos `OpenProcess` hívások nem kapnak olvasási jogot
- **WDigest kikapcsolása** (`UseLogonCredential = 0`) — megszünteti a cleartext jelszó memóriában tartását
- **A helyi admin jogok korlátozása** — mivel szinte minden altechnika emelt jogot igényel, ez a leghatékonyabb egyetlen kontroll
- **LAPS** — a helyi admin jelszó gépenkénti egyedivé tétele; nem akadályozza meg a .002-t, de értéktelenné teszi a zsákmányt
- **DCSync esetén:** a replikációs jogok auditálása és szűkítése — itt nem végponti kontroll, hanem AD jogosultság-kezelés a védelem

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás                          | Típus            | Megjegyzés                                                                            | Érintett altechnika               |
| ----------------------------------- | ---------------- | ------------------------------------------------------------------------------------- | --------------------------------- |
| Sysmon EID 10 (ProcessAccess)       | Process          | `TargetImage` = lsass.exe + `GrantedAccess` bitmaszk — a legkorábbi és legpontosabb jel | .001                              |
| Sysmon EID 1 (ProcessCreate)        | Process          | Parancssor: dump-eszközök, `reg save`, `ntdsutil`, `vssadmin`, `esentutl`             | .001–.006                         |
| Sysmon EID 11 (FileCreate)          | File             | A kiírt dump/hive fájl megjelenése (`.dmp`, `sam.hiv`, `ntds.dit` másolat)             | .001, .002, .003, .004            |
| Sysmon EID 12/13 (Registry)         | Registry         | `HKLM\SECURITY\Policy\Secrets` olvasása/exportja                                       | .004                              |
| Sysmon EID 7 (ImageLoad)            | Module           | Idegen DLL betöltése az LSASS-be (skeleton key, SSP-injektálás)                        | .001, átfed T1556-tal              |
| **Windows Security 4662**           | Directory Access | Replikációs GUID-ok a `Properties` mezőben — **SACL szükséges** a DC-n                  | **.006**                          |

### Detekciós lehetőség

A technika detekciója **három, egymást erősítő rétegre** épül, és a jó lefedettséghez mindhárom kell:

1. **Hozzáférés-alapú** (a legerősebb) — a tároló megnyitásának ténye. Ez a .001-nél a Sysmon EID 10 `GrantedAccess` bitmaszkja: az `OpenProcess` hívás akkor is látszik, ha utána semmit nem olvasnak ki. Nem kerülhető meg átnevezéssel vagy obfuszkációval, mert nem a *nevet* nézi, hanem a *műveletet*.
2. **Végeredmény-alapú** — a kiírt fájl megjelenése (EID 11). Későbbi jel, viszont akkor is megfog, ha a hozzáférés maga elkerülte a figyelést; jó másodlagos háló.
3. **Eszköznév-alapú** (a leggyengébb) — ismert eszközök neve/paramétere a parancssorban. Egy `mimikatz.exe` → `svc.exe` átnevezés kicsúszik alóla, tehát ez **soha nem lehet az egyetlen szabály** egy altechnikára. A repóban ezt a szerepet a 0022 tölti be, tudatosan kiegészítő jelleggel.

A közös zajforrás mindhárom rétegben ugyanaz és jól nevesíthető: **AV/EDR ügynökök**, a Windows hibajelentő (`WerFault.exe`), biztonsági mentési szoftver és a rendszergazda által kézzel futtatott diagnosztikai eszközök. Ezért itt az `SourceImage` alapú allowlist hatékony — de karbantartást igényel, mert minden új EDR-gyártó új útvonalat hoz.

**Amit a Sysmon nem lát:** a .006 DCSync. Ott a támadó gépén legfeljebb egy eszköz elindulása látszik (ezt fogja a 0029), maga a hitelesítőadat-lopás viszont egy **hálózati replikációs kérés**, aminek az egyetlen megbízható nyoma a DC Security logjában lévő 4662 esemény. Ez ma nincs megépítve.

## Kapcsolódó szabályok

| detect_id       | Szabály                                                | Altechnika              | Telemetria      | Szint    |
| --------------- | ------------------------------------------------------ | ----------------------- | --------------- | -------- |
| [DETECT-2026-0019](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0019_LSASS-Memory-Access-by-Non-Standard-Process.yml) | LSASS Memory Access by Non-Standard Process           | .001                    | Sysmon EID 10   | critical |
| [DETECT-2026-0020](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0020_LSASS-Dump-via-comsvcs-MiniDump.yml) | LSASS Credential Dump via comsvcs.dll MiniDump        | .001                    | Sysmon EID 1    | critical |
| [DETECT-2026-0021](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0021_LSASS-Dump-via-ProcDump.yml) | LSASS Dump via ProcDump                                | .001                    | Sysmon EID 1    | critical |
| [DETECT-2026-0025](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0025_LSASS-Dump-via-TaskManager-and-FileCreate.yml) | LSASS Memory Dump via Task Manager or Suspicious File Creation | .001            | Sysmon EID 11   | critical |
| [DETECT-2026-0023](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0023_SAM-and-LSA-Secrets-Dump-via-Registry-Hive-Export.yml) | SAM and LSA Secrets Dump via Registry Hive Export     | .002, .004              | Sysmon EID 1    | critical |
| [DETECT-2026-0026](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0026_SAM-and-LSA-Hive-Copy-via-esentutl.yml) | SAM and LSA Credential Hive Copy via esentutl         | .002, .004              | Sysmon EID 1    | critical |
| [DETECT-2026-0027](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0027_Credential-Hive-Access-via-Volume-Shadow-Copy.yml) | Credential Hive Access via Volume Shadow Copy         | .002                    | Sysmon EID 1    | critical |
| [DETECT-2026-0024](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0024_NTDS-Credential-Dump-Attempt.yml) | NTDS.dit Credential Dump Attempt                       | .003                    | Sysmon EID 1    | critical |
| [DETECT-2026-0030](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0030_Symlink-Creation-to-Volume-Shadow-Copy-Device-Path.yml) | Symlink Creation to Volume Shadow Copy Device Path    | .003                    | Sysmon EID 1    | critical |
| [DETECT-2026-0031](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0031_Credential-Hive-Access-via-Low-Level-NTFS-Acquisition.yml) | Credential Hive Access via Low-Level NTFS Acquisition | .003                    | Sysmon EID 1    | critical |
| [DETECT-2026-0028](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0028_Cached-Credential-Enumeration-via-Cmdkey.yml) | Cached Credential Enumeration via Cmdkey              | .005                    | Sysmon EID 1    | low      |
| [DETECT-2026-0029](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0029_DCSync-via-DSInternals-Get-ADReplAccount.yml) | DCSync via DSInternals Get-ADReplAccount              | .006                    | Sysmon EID 1    | high     |
| [DETECT-2026-0022](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0022_Known-Credential-Dumping-Tool-Execution.yml) | Known Credential Dumping Tool Execution                | .001–.006 (eszköznév)   | Sysmon EID 1    | critical |

**Nem fedett:** a .006 natív detekciója (Security 4662 + replikációs GUID-ok) — a technika egyetlen olyan altechnikája, amit a jelenlegi szabálykészlet érdemben nem lát.

## Kapcsolódó jegyzetek


## Saját feljegyzések

