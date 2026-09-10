---
mitre_id: TA0006
mitre_type: tactic
name: Credential Access
aliases:
  - TA0006
  - Credential Access
url: https://attack.mitre.org/tactics/TA0006/
matrix_position: 6
technique_count: 17
de_priority: kritikus
coverage: részleges
---
# TA0006 — Credential Access

## Cél

A támadó érvényes hitelesítő adatokat (felhasználónév–jelszó pár, jelszó-hash, Kerberos ticket, token, tanúsítvány) próbál megszerezni. Ennek az az értéke, hogy a lopott azonosítóval végzett tevékenység **legitim felhasználói tevékenységnek látszik** — nem kell hozzá exploit, nem kell malware-t futtatni, és a legtöbb védelmi kontroll elengedi. Egy megszerzett domain admin hash lényegében kiváltja az összes további privilege escalationt.

Ezért ez a taktika a támadási lánc fordulópontja: innentől a támadó nem "betör", hanem **bejelentkezik**. Detection engineering szempontból pedig épp ezért itt éri meg a legtöbbet befektetni — a Credential Access az utolsó pont, ahol a tevékenység még egyértelműen rosszindulatúnak látszik, mielőtt beleolvadna a normál forgalomba.

> [!quote] MITRE definíció
> The adversary is trying to steal account names and passwords.

## Hely a támadási láncban

- **Előtte tipikusan:** [TA0004 - Privilege Escalation] — a legtöbb hitelesítőadat-lopás (LSASS, SAM, NTDS) **helyi rendszergazdai vagy SYSTEM jogot feltételez**, tehát ez ritkán az első lépés
- **Utána tipikusan:** [TA0008 - Lateral Movement] — a megszerzett hash/ticket közvetlenül itt kerül felhasználásra (pass-the-hash, pass-the-ticket)
- **Mit feltételez:** kódfuttatás a végponton ([TA0002 - Execution]) és jellemzően már emelt jogosultság. Kivétel a hálózati oldal (T1110 brute force, T1557 relay), ami kívülről, jogosultság nélkül is működik

## Technikák

| ID                                                         | DE prioritás | Lefedettség | Megjegyzés                                                                     |
| ---------------------------------------------------------- | :----------- | :---------- | :----------------------------------------------------------------------------- |
| [[T1003 - OS Credential Dumping]]                          | kritikus     | részleges   | 13 szabály; a Sysmon-oldal kész, a .006 DCSync natív detekciója hiányzik       |
| [[T1558 - Steal or Forge Kerberos Tickets]]                | kritikus     | nincs       | Kerberoasting / AS-REP roasting — natív DC log (4769/4768), a legnagyobb hiány |
| [[T1110 - Brute Force]]                                    | magas        | nincs       | Password spraying — natív log (4625/4771/4776), küszöb-alapú                   |
| [[T1552 - Unsecured Credentials]]                          | közepes      | nincs       | Fájlban/registryben hagyott jelszó; egy szabályba összevonható                 |
| [[T1555 - Credentials from Password Stores]]               | közepes      | részleges   | Böngésző, Credential Manager, jelszókezelők                                    |
| [[T1556 - Modify Authentication Process]]                  | magas        | részleges   | Átfed a Persistence taktikával                                                 |
| [[T1557 - Adversary-in-the-Middle]]                        | magas        | részleges   | .001 megvan (DNS-hiba → SMB korreláció); .002/.003 hálózati eszköz oldali, nem SIEM-kérdés |
| [[T1187 - Forced Authentication]]                          | közepes      | nincs       | Kifelé irányuló SMB/WebDAV kényszerített hitelesítés                           |
| [[T1040 - Network Sniffing]]                               | közepes      | nincs       | `netsh trace`, `pktmon`, `dumpcap`                                             |
| [[T1539 - Steal Web Session Cookie]]                       | közepes      | nincs       | Böngésző cookie-adatbázis olvasása                                             |
| [[T1056 - Input Capture]]                                  | alacsony     | nincs       | Keylogging — gyenge detekciós esély bármelyik forrásból                        |
| [[T1212 - Exploitation for Credential Access]]             | alacsony     | nincs       | Nincs megbízható szignatúra                                                    |
| [[T1649 - Steal or Forge Authentication Certificates]]     | —            | nincs       | AD CS szervert igényel — jelenleg hatókörön kívül                              |
| [[T1111 - Multi-Factor Authentication Interception]]       | —            | nincs       | Nem végponton megfigyelhető                                                    |
| [[T1621 - Multi-Factor Authentication Request Generation]] | —            | nincs       | Cloud — hatókörön kívül                                                        |
| [[T1528 - Steal Application Access Token]]                 | —            | nincs       | Cloud — hatókörön kívül                                                        |
| [[T1606 - Forge Web Credentials]]                          | —            | nincs       | Cloud — hatókörön kívül                                                        |

## Detekciós stratégia (taktikai szint)

Ez a taktika **két, élesen elkülönülő telemetria-világra** esik szét, és ez határozza meg, hogy mi építhető meg ma és mi nem:

- **Végponti oldal (Sysmon).** Minden, ami a helyi gépen tárolt hitelesítő adathoz nyúl: LSASS memória, SAM/SECURITY registry hive, NTDS.dit, böngésző-adatbázisok. A jelet a folyamat-hozzáférés (EID 10), a folyamatindítás parancssora (EID 1) és a fájlírás (EID 11) hordozza. **Ez a rész magas fidelitású**: nagyon kevés legitim ok van arra, hogy egy nem-rendszerfolyamat olvassa az LSASS memóriáját.
- **Címtár-oldal (natív Windows Security log, DC).** Minden, ami a Kerberos vagy az NTLM hitelesítési folyamattal manipulál: Kerberoasting (4769), AS-REP roasting (4768), DCSync (4662), password spraying (4625/4771/4776). **Ez a rész eseményszinten zajos**, és nem szűréssel, hanem *küszöb- és arányszámítással* detektálható — plusz előfeltétele, hogy a megfelelő `auditpol` alkategória és (DCSync esetén) a SACL be legyen állítva a DC-n.

Közös FP-jellemző: a legitim zaj forrása szinte mindig **egy ismert, névvel azonosítható entitás** — AV/EDR ügynök, biztonsági mentés, címtár-szinkron szolgáltatásfiók, gépfiók. Ezért itt az allowlist-alapú szűrés kivételesen jól működik, szemben pl. a [TA0043 - Reconnaissance]-szel, ahol a zaj anonim és végtelen.

Amit ezen a szinten **nem** lehet látni: az offline jelszótörés (T1110.002) és a Silver Ticket (T1558.002) — egyik sem generál eseményt a védett infrastruktúrán, mert nem is érinti azt.

## Lefedettség ebben a repóban

Jelenleg **14 szabály**: 13 (DETECT-2026-0019 … 0031) [[T1003 - OS Credential Dumping]] alatt, plusz **DETECT-2026-0034**, az első szabály [[T1557 - Adversary-in-the-Middle]] alatt (`experimental`, folyamatindítás-alapú, T1040-nel közös — a támadó eszközét fogja meg, ha az monitorozott gépen fut). A korábbi DETECT-2026-0033 (DNS-hiba → SMB korreláció) 2026-09-10-én törölve, nem igazolt előfeltevés miatt. Ez azt jelenti, hogy a Sysmon-alapú végponti oldal két technikán már megkezdett, a natív DC-log oldal ([[T1558 - Steal or Forge Kerberos Tickets]], DCSync, spraying) viszont teljesen üres.

A legnagyobb egyedi hiány a **DCSync natív detekciója** (4662 + replikációs GUID-ok): a meglévő 0029-es szabály csak egy eszköz nevét (`Get-ADReplAccount`) fogja meg, tehát bármelyik másik DCSync-implementáció kicsúszik alóla. Utána sorrendben a **Kerberoasting** (4769, RC4) és az **AS-REP roasting** (4768, pre-auth 0) jön — mindkettő natív log, tehát pipeline-oldali előfeltétele van (`service: security` ág).

Részletes ütemterv: `docs/credential-access-buildout.md` a repóban.

## Saját feljegyzések

