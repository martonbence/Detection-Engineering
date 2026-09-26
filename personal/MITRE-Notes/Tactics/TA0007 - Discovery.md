---
mitre_id: TA0007
mitre_type: tactic
name: Discovery
aliases:
  - TA0007
  - Discovery
url: https://attack.mitre.org/tactics/TA0007/
matrix_position: 10
technique_count: 34
de_priority: közepes
coverage: részleges
---
# TA0007 — Discovery

## Cél

A támadó azt próbálja megtudni, **hova érkezett**. A behatolás pillanatában semmit nem tud a környezetről azon túl, amit kívülről látott: nem tudja, milyen gépen van, milyen jogosultsággal, milyen domainben, ki van még bejelentkezve, hol van az adat, amit keres, és mi az, ami megfigyeli őt. A Discovery ezt a hiányt pótolja.

Ez a taktika azért különleges, mert **szinte kizárólag legitim, beépített eszközökkel zajlik**: `whoami`, `net user`, `nltest`, `systeminfo`, `tasklist`, `ipconfig`, `net share` — semmi nem exploit, semmi nem malware, mindegyik pontosan arra használódik, amire készült. A támadó itt nem tör be semmibe, csak *kérdez*, és a rendszer válaszol neki, mert joga van hozzá.

Detection engineering szempontból ebből két dolog következik, és mindkettő fontos. Egyrészt a **fidelitás alacsony**: egyetlen `whoami` futása önmagában teljesen normális, és a Discovery-technikák egyedi detekciója ezért jellemzően nem actionable. Másrészt viszont a **minta nagyon jellegzetes**: az emberi támadó (vagy a felderítő szkriptje) rövid időn belül *sok, egymáshoz kapcsolódó* felderítő parancsot futtat egymás után — és ez a *sűrűség* olyan jel, ami legitim adminisztratív tevékenységnél ritkán áll elő. A Discovery detekciója tehát nem szűrés, hanem **aggregáció**.

> [!quote] MITRE definíció
> The adversary is trying to figure out your environment.

## Hely a támadási láncban

- **Előtte tipikusan:** [TA0002 - Execution] — felderítéshez parancsot kell futtatni; illetve [TA0003 - Persistence], mert a támadó jellemzően először biztosítja a hozzáférését, és csak utána néz körül  *(taktika-hivatkozás szándékosan egykapcsos: ne kösse össze a taktikákat a gráf nézetben)*
- **Utána tipikusan:** [TA0008 - Lateral Movement] — a felderítés célja a következő ugrás célpontjának kiválasztása; illetve [TA0006 - Credential Access], ha a felderítés során kiderül, melyik fiók/gép érdemes a hitelesítőadat-lopásra
- **Mit feltételez:** kódfuttatási képességet a gépen, de **emelt jogosultságot jellemzően nem** — a Discovery nagy része sima felhasználói kontextusban is működik, mert a Windows és a címtár alapból olvashatóvá teszi a saját konfigurációját a hitelesített felhasználóknak. Kivétel a hálózati oldal: a [[T1040 - Network Sniffing]] helyi rendszergazdai jogot igényel (a capture driver telepítéséhez vagy a raw socket megnyitásához)

## Technikák

| ID                                                       | DE prioritás | Lefedettség | Megjegyzés                                                                                                                 |
| -------------------------------------------------------- | :----------- | :---------- | :------------------------------------------------------------------------------------------------------------------------- |
| [[T1087 - Account Discovery]]                              | magas        | részleges   | 4 altechnika; a `.002` (Domain Account) fedett: DETECT-2026-0004, natív 4625/4768/4771 hitelesítési válaszkódok alapján     |
| [[T1040 - Network Sniffing]]                               | közepes      | részleges   | DETECT-2026-0044; egyszerre Credential Access és Discovery — lásd [TA0006 - Credential Access]                              |
| [[T1482 - Domain Trust Discovery]]                         | magas        | nincs       | `nltest /domain_trusts`, `Get-ADTrust` — a lateral movement előkészítése, magas fidelitású parancsminta                     |
| [[T1069 - Permission Groups Discovery]]                    | magas        | nincs       | 3 altechnika; `net group "Domain Admins" /domain` — a klasszikus következő lépés a T1087 után                               |
| [[T1018 - Remote System Discovery]]                        | magas        | nincs       | `net view`, `ping` sweep, AD-számítógép-lista — a célpontválasztás lépése                                                    |
| [[T1135 - Network Share Discovery]]                        | magas        | nincs       | `net share`, `net view \\host` — gyakran közvetlenül adat-hozzáféréshez vezet                                               |
| [[T1083 - File and Directory Discovery]]                   | közepes      | nincs       | `dir /s`, `Get-ChildItem -Recurse` — ransomware-láncok szokásos előszobája                                                   |
| [[T1057 - Process Discovery]]                              | közepes      | nincs       | `tasklist`, `Get-Process` — gyakran AV/EDR-keresés céljából                                                                  |
| [[T1082 - System Information Discovery]]                   | közepes      | nincs       | `systeminfo`, `wmic os get` — szinte minden felderítő szkript első lépése                                                    |
| [[T1016 - System Network Configuration Discovery]]         | közepes      | nincs       | 2 altechnika; `ipconfig /all`, `route print`, `arp -a`                                                                       |
| [[T1049 - System Network Connections Discovery]]            | közepes      | nincs       | `netstat -ano`, `Get-NetTCPConnection`                                                                                       |
| [[T1033 - System Owner-User Discovery]]                    | közepes      | nincs       | `whoami`, `query user` — a legalacsonyabb fidelitású, de leggyakoribb felderítő parancs                                     |
| [[T1012 - Query Registry]]                                 | közepes      | nincs       | `reg query` — registry-telemetriát igényel a mélyebb változata                                                               |
| [[T1518 - Software Discovery]]                             | közepes      | nincs       | 2 altechnika, köztük a `.001` Security Software Discovery — az AV/EDR felderítése a kikapcsolás előtt                        |
| [[T1201 - Password Policy Discovery]]                      | közepes      | nincs       | `net accounts /domain` — a password spraying előkészítése (lockout-küszöb kiolvasása), lásd [[T1110.003 - Password Spraying]] |
| [[T1046 - Network Service Discovery]]                      | közepes      | nincs       | Belső port scan; a külső párja [[T1595.001 - Scanning IP Blocks]]                                                            |
| [[T1007 - System Service Discovery]]                       | alacsony     | nincs       | `sc query`, `net start`                                                                                                      |
| [[T1615 - Group Policy Discovery]]                         | alacsony     | nincs       | `gpresult`, SYSVOL-olvasás — GPO-alapú félrekonfigurációk keresése                                                            |
| [[T1654 - Log Enumeration]]                                | alacsony     | nincs       | `wevtutil`, `Get-WinEvent` — a támadó azt keresi, mit naplóztak róla                                                          |
| [[T1217 - Browser Information Discovery]]                  | alacsony     | nincs       | Böngésző-előzmények/bookmarkok olvasása                                                                                      |
| [[T1010 - Application Window Discovery]]                   | alacsony     | nincs       | Nyitott ablakok címének olvasása                                                                                             |
| [[T1120 - Peripheral Device Discovery]]                    | alacsony     | nincs       | Csatlakoztatott eszközök listázása                                                                                            |
| [[T1124 - System Time Discovery]]                          | alacsony     | nincs       | `net time`, `w32tm` — időzóna-alapú célzás vagy sandbox-ellenőrzés                                                            |
| [[T1497 - Virtualization-Sandbox Evasion]]                 | alacsony     | nincs       | 3 altechnika; átfed a Stealth taktikával — a labban minden gép VM, tehát itt strukturálisan zajos                            |
| [[T1622 - Debugger Evasion]]                               | alacsony     | nincs       | `IsDebuggerPresent`-szintű ellenőrzés — API-hívás, folyamatindítás-logból láthatatlan                                         |
| [[T1652 - Device Driver Discovery]]                        | alacsony     | nincs       | `driverquery` — jellemzően EDR-driver keresése                                                                                |
| [[T1614 - System Location Discovery]]                      | alacsony     | nincs       | 1 altechnika; nyelvi/regionális beállítás kiolvasása (célzott ransomware szokása)                                            |
| [[T1673 - Virtual Machine Discovery]]                      | alacsony     | nincs       | Hipervizoron futó VM-ek listázása                                                                                            |
| [[T1680 - Local Storage Discovery]]                        | alacsony     | nincs       | Helyi tárolók/kötetek felderítése                                                                                             |
| [[T1613 - Container and Resource Discovery]]               | —            | nincs       | Konténer — hatókörön kívül                                                                                                   |
| [[T1526 - Cloud Service Discovery]]                        | —            | nincs       | Cloud — hatókörön kívül                                                                                                      |
| [[T1538 - Cloud Service Dashboard]]                        | —            | nincs       | Cloud — hatókörön kívül                                                                                                      |
| [[T1580 - Cloud Infrastructure Discovery]]                 | —            | nincs       | Cloud — hatókörön kívül                                                                                                      |
| [[T1619 - Cloud Storage Object Discovery]]                 | —            | nincs       | Cloud — hatókörön kívül                                                                                                      |

## Detekciós stratégia (taktikai szint)

Ez a taktika **három adatforrásból** látható, és a repo jelenlegi két szabálya épp két különbözőt használ — ami jól mutatja, hogy a Discovery nem egy homogén detekciós probléma:

- **Folyamatindítás (Sysmon EID 1).** A felderítő parancsok döntő része beépített segédprogram meghívása, tehát folyamatindítás-eseményt generál. Itt a jel **nem az egyedi parancs, hanem a sűrűség és a sorrend**: `whoami` → `net user /domain` → `net group "Domain Admins" /domain` → `nltest /domain_trusts` egy percen belül, ugyanattól a felhasználótól, egy irodai munkaállomáson — ez a minta. Ennek a helyes detekciós formája **aggregáció** (n különböző felderítő parancs egy időablakon belül, gépenként/felhasználónként), nem külön szabály parancsonként; ez `custom.splunk.raw_query` terület, ugyanaz a szerkezet, mint a [[T1110.003 - Password Spraying]] számosság-alapú szabályánál. Egyedi parancsszabályokat csak ott érdemes írni, ahol a parancs önmagában is szokatlan (`nltest /domain_trusts`, `net accounts /domain`) — egy `whoami`-ra soha.
- **Natív Windows Security log (DC-oldal).** A **címtár felé** irányuló felderítés nem a támadó gépén, hanem a domain controlleren látszik — és ez a Discovery detekciójának a legalulértékeltebb lába. A repo egyetlen "klasszikus" Discovery-szabálya (DETECT-2026-0004) pontosan ezt teszi: nem parancsot keres, hanem a **hitelesítési válaszok mintáját** — azt, hogy egy forrás sok, nem létező felhasználónévre kap "nincs ilyen fiók" típusú választ. Ez a felhasználó-enumeráció jele, és a támadó gépén nem hagy nyomot egyáltalán. Az előfeltétele ugyanaz, mint a brute-force szabályoknál: a megfelelő `auditpol` alkategória a DC-n.
- **Hálózati/promiszkuus oldal.** A [[T1040 - Network Sniffing]] a taktika egyetlen technikája, ami nem "kérdez", hanem **passzívan hallgat** — ezért nem is generál címtár- vagy parancs-válaszokat, csak a *capture eszköz elindítása* látszik (DETECT-2026-0044, Sysmon EID 1). Maga a lehallgatás a hálózati kártya szintjén zajlik, és ahhoz, hogy ez látszódjon, driver-betöltés (Sysmon EID 6) vagy NIC-módváltás telemetria kellene — egyik sem létezik ebben a repóban.

A taktika **közös FP-forrása** minőségileg más, mint a többi taktikánál, és ez a legfontosabb dolog, amit erről a taktikáról tudni kell: **itt nincs "rosszindulatú parancs".** Amit a támadó futtat, azt a rendszergazda, a leltározó szkript, a monitorozó ügynök, a login script és a helpdesk is futtatja — bájtra ugyanúgy. Következésképp allowlist-alapú szűrés (ami [TA0006 - Credential Access]-nél kivételesen jól működik) itt csak a *gépi* zajra alkalmazható (monitorozó ügynök szolgáltatásfiókja, ismert leltározó szkript útvonala); az emberi adminisztrátor tevékenysége nem szűrhető, csak bázisvonalhoz mérhető. Ezért a Discovery-szabályok reális célja nem az önálló riasztás, hanem a **kontextus-dúsítás**: egy Discovery-találat akkor ér valamit, ha egy másik taktikán is van jel ugyanarról a gépről/felhasználóról.

Amit ezen a szinten **nem** lehet látni: az API-szintű felderítést, ami nem indít folyamatot (egy beültetett implant a `NetUserEnum`/LDAP-hívást közvetlenül teszi meg — se parancssor, se új folyamat); és a tisztán passzív lehallgatást, ha a capture eszköz elindítását elszalasztottuk.

## Lefedettség ebben a repóban

Jelenleg **2 szabály** viseli ezt a taktika-tag-et, és mindkettő atipikus a taktikán belül:

**[[T1087 - Account Discovery]] `.002` (Domain Account) — DETECT-2026-0004** (`stable`, `medium`): Windows domain-fiók enumeráció detekciója a hitelesítési válaszokból, natív Security logból. Atipikus, mert nem a felderítő parancsot látja, hanem annak a *címtár-oldali lenyomatát*.

**[[T1040 - Network Sniffing]] — DETECT-2026-0044** (`stable`, `medium`): packet-capture eszközök és a Windows beépített capture-képességeinek (`pktmon`, `netsh trace`, NetEventSession) elindulása, Sysmon EID 1-ből. Atipikus, mert ez a taktika egyetlen technikája, ami nem kérdez, hanem hallgat — és mert egyszerre Credential Access-technika is, ott van a részletes tárgyalása.

A lefedettség tehát **34 technikából 2**, ami első ránézésre nagy hiánynak tűnik, de ez a taktika természetéből adódik és **nem ugyanolyan súlyos, mint mondjuk a Persistence-oldali hiány**: a Discovery-technikák többségére az egyedi szabály eleve alacsony értékű lenne (lásd fentebb: nincs rosszindulatú parancs). A reálisan legértékesebb következő lépés ezért nem 10 új parancsszabály, hanem **egy aggregáló szabály**: n különböző felderítő parancs egy rövid időablakban, gépenként — ami a meglévő Sysmon EID 1 adatforráson, `custom.splunk.raw_query`-vel megépíthető, új pipeline-előfeltétel nélkül.

Az egyedi szabályt érdemlő kivételek: [[T1482 - Domain Trust Discovery]] (`nltest /domain_trusts` egy munkaállomáson gyakorlatilag mindig gyanús), [[T1201 - Password Policy Discovery]] (`net accounts /domain`, a spraying előkészítése) és a [[T1518 - Software Discovery]] `.001` biztonsági szoftver-keresés ága.

## Saját feljegyzések

