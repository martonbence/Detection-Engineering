---
mitre_id: TA0003
mitre_type: tactic
name: Persistence
aliases:
  - TA0003
  - Persistence
url: https://attack.mitre.org/tactics/TA0003/
matrix_position: 5
technique_count: 22
de_priority: kritikus
coverage: részleges
---
# TA0003 — Persistence

## Cél

A támadó azt akarja elérni, hogy a hozzáférése **túlélje** azokat a dolgokat, amik egy illékony kódfuttatást megszüntetnének: az újraindítást, a felhasználó kilépését, a folyamat leállását, a felhasznált hitelesítő adat lejáratát vagy megváltoztatását. A perzisztencia tehát nem új képességet ad a támadónak, hanem **biztosítja a már megszerzettet**.

Ennek a támadó szempontjából az az értéke, hogy a belépési pont drága volt (exploit, phishing, ellopott hitelesítő adat), és nem akarja minden alkalommal újra megfizetni. Emiatt a perzisztencia jellemzően **közvetlenül az első kódfuttatás után** következik, és jellemzően **több helyen, párhuzamosan** épül ki — ha az egyiket megtalálják, a többi életben marad.

Detection engineering szempontból ez a taktika azért kitüntetett, mert szinte minden technikája **állapotot ír valahová**: registry-kulcsot, fájlt a lemezre, ütemezett feladatot, szolgáltatás-bejegyzést, felhasználói fiókot. Ez kétszeresen hasznos. Egyrészt a *létrehozás* pillanata detektálható eseményt generál. Másrészt — és ez a másik taktikáknál nem így van — az eredmény **utólag is megtalálható**: a perzisztencia definíció szerint ott marad, tehát akkor is felfedezhető, ha a létrehozás eseményét elszalasztottuk.

> [!quote] MITRE definíció
> The adversary is trying to maintain their foothold.

## Hely a támadási láncban

- **Előtte tipikusan:** [TA0002 - Execution] — perzisztenciát telepíteni önmagában is kódfuttatás; a támadónak először futtatnia kell valamit, hogy bármit is beírhasson  *(taktika-hivatkozás szándékosan egykapcsos: ne kösse össze a taktikákat a gráf nézetben)*
- **Utána tipikusan:** [TA0004 - Privilege Escalation] vagy [TA0007 - Discovery] — a lábnyom megszilárdítása után a támadó vagy jogosultságot próbál növelni, vagy elkezdi feltérképezni, hova jutott
- **Mit feltételez:** kódfuttatási képességet a gépen. Emelt jogosultságot **nem** minden technika: a felhasználói `HKCU\...\Run` kulcs, a felhasználó saját `cron`-bejegyzése vagy egy webroot-ba írható könyvtárba tett webshell mind sima felhasználói kontextusban is működik — csak a hatóköre kisebb (nem gépszintű, hanem felhasználó- vagy alkalmazásszintű)

## Technikák

| ID                                                       | DE prioritás | Lefedettség | Megjegyzés                                                                                                                       |
| -------------------------------------------------------- | :----------- | :---------- | :------------------------------------------------------------------------------------------------------------------------------- |
| [[T1505 - Server Software Component]]                      | magas        | részleges   | 6 altechnika; a `.003` (Web Shell) fedett 2 szabállyal (0039, 0040), a többi (IIS/SQL/Transport Agent) nincs                      |
| [[T1547 - Boot or Logon Autostart Execution]]              | kritikus     | nincs       | 14 altechnika; a klasszikus `Run` kulcs / startup folder — a legnagyobb egyedi hiány, registry-telemetriát igényel (Sysmon EID 12/13) |
| [[T1053 - Scheduled Task-Job]]                             | kritikus     | nincs       | 5 altechnika; átfed az Execution taktikával, `schtasks`/`at`/`cron`                                                               |
| [[T1543 - Create or Modify System Process]]                | kritikus     | nincs       | 5 altechnika; Windows szolgáltatás létrehozása/módosítása — gépszintű, SYSTEM-kontextusú perzisztencia                             |
| [[T1546 - Event Triggered Execution]]                      | magas        | nincs       | 18 altechnika (a legtöbb az egész mátrixban); WMI event subscription, AppInit DLL, accessibility features                          |
| [[T1078 - Valid Accounts]]                                 | kritikus     | nincs       | Átfed az Initial Access/Privilege Escalation/Lateral Movement taktikákkal; a jel tisztán kontextuális                             |
| [[T1098 - Account Manipulation]]                           | magas        | nincs       | 7 altechnika; csoporttagság-bővítés, SSH-kulcs hozzáadás, AD-attribútum módosítás                                                  |
| [[T1136 - Create Account]]                                 | magas        | nincs       | 3 altechnika; a legkézenfekvőbb perzisztencia, natív logból (4720/4732) jól látszik                                                |
| [[T1556 - Modify Authentication Process]]                  | magas        | nincs       | 9 altechnika; átfed a Credential Access taktikával — lásd [TA0006 - Credential Access]                                            |
| [[T1197 - BITS Jobs]]                                      | magas        | teljes      | 2 szabály (0005, 0006); a 0006 (`SetNotifyCmdLine`) kifejezetten a perzisztencia-ág                                                |
| [[T1574 - Hijack Execution Flow]]                          | közepes      | nincs       | 12 altechnika; DLL search order hijacking, átfed az Execution és Privilege Escalation taktikákkal                                  |
| [[T1112 - Modify Registry]]                                | közepes      | nincs       | Önálló technikaként is szerepel; registry-telemetria előfeltétele ugyanaz, mint a T1547-nél                                        |
| [[T1133 - External Remote Services]]                       | magas        | nincs       | Átfed az Initial Access taktikával — egy már meglévő VPN/RDP-hozzáférés fenntartása                                                |
| [[T1137 - Office Application Startup]]                     | közepes      | nincs       | 6 altechnika; Outlook-szabály, sablon, add-in                                                                                      |
| [[T1037 - Boot or Logon Initialization Scripts]]            | közepes      | nincs       | 5 altechnika; logon script, `rc.common`                                                                                            |
| [[T1176 - Software Extensions]]                            | közepes      | nincs       | 2 altechnika; böngésző- és IDE-kiterjesztés                                                                                        |
| [[T1205 - Traffic Signaling]]                              | alacsony     | nincs       | 2 altechnika; port knocking, socket filter — hálózati szenzort igényel                                                             |
| [[T1542 - Pre-OS Boot]]                                    | alacsony     | nincs       | 5 altechnika; bootkit/UEFI — OS-szintű logból strukturálisan láthatatlan                                                           |
| [[T1554 - Compromise Host Software Binary]]                | alacsony     | nincs       | Meglévő bináris kicserélése/trojanizálása                                                                                          |
| [[T1653 - Power Settings]]                                 | alacsony     | nincs       | Hibernálás/alvás módosítása a perzisztencia támogatására                                                                            |
| [[T1525 - Implant Internal Image]]                         | —            | nincs       | Konténer-image — hatókörön kívül                                                                                                   |
| [[T1668 - Exclusive Control]]                              | —            | nincs       | Más támadók kizárása a kompromittált rendszerről                                                                                    |
| [[T1671 - Cloud Application Integration]]                  | —            | nincs       | Cloud — hatókörön kívül                                                                                                            |

## Detekciós stratégia (taktikai szint)

A taktika detekciója **négy adatforrás-családra** oszlik, és a repo jelenleg kettőben van jelen:

- **Folyamatindítás (Sysmon EID 1).** A perzisztencia *telepítésének* eszközét látja: `schtasks /create`, `sc.exe create`, `reg add ...\Run`, `bitsadmin /SetNotifyCmdLine`. Ez az, amiben a repo erős — a két BITS-szabály (0005/0006) pontosan ezt teszi. A korlátja, hogy csak a parancssori utat fogja: ha ugyanazt a registry-kulcsot egy .NET API-hívás írja be, folyamatindítás-esemény nem keletkezik róla.
- **Registry-telemetria (Sysmon EID 12/13/14).** A perzisztencia *eredményét* látja, függetlenül attól, milyen eszköz írta be. Ez fedi le a taktika legnagyobb technikáit (T1547, T1112, T1543, T1546), és **ebben a repóban jelenleg egyáltalán nincs** — nincs `registry_event` kategóriájú logsource egyetlen szabályban sem. Ez a taktika legfontosabb strukturális rése, és pipeline-oldali előfeltétele van (a Sysmon-konfig registry-ágának bekapcsolása és a megfelelő szűrés, mert szűrés nélkül ez a legzajosabb EID az összes közül).
- **Fájlírás (Sysmon EID 11 / webszerver-oldali fájl-telemetria).** A lemezre kerülő perzisztencia: startup folderbe tett `.lnk`, webrootba írt `.php`. A [[T1505.003 - Web Shell]] elsődleges, MITRE által is megnevezett detekciós jele éppen ez — és pontosan ez az, ami itt hiányzik, ezért látja a két webshell-szabály a shellt csak a HTTP-kérésen keresztül, nem a fájlrendszeren.
- **Natív Windows Security log.** A fiók- és csoport-műveletek (4720 fiók létrehozás, 4732 csoporthoz adás, 4698 ütemezett feladat létrehozás) — a T1136/T1098 ága. Ez a repóban a `service: security` ág, ami a [TA0006 - Credential Access] brute-force szabályaival (0002/0003/0004) már létezik, tehát a T1136 detekciója nem új adatforrást, csak új szabályt igényel.

A taktikára jellemző **közös FP-forrás** szinte definíció szerint adott: minden legitim szoftvertelepítés perzisztenciát épít. Egy telepítő registry autostart kulcsot ír, szolgáltatást hoz létre, ütemezett frissítő feladatot regisztrál — **telemetriailag megkülönböztethetetlen** a támadói perzisztenciától, csak a beírt érték tartalma és a végrehajtó folyamat identitása különbözteti meg. Ez azt jelenti, hogy ezen a taktikán a "gyanús esemény" fogalma önmagában nem használható: a szabálynak vagy a *célértéket* kell megítélnie (hova mutat az autostart bejegyzés: `Temp`-be írt binárisra vagy egy aláírt program telepítési könyvtárába?), vagy a *létrehozó kontextust*. Ez érdemben nehezebb, mint [TA0002 - Execution] parancssori mintái, és ez a fő ok, amiért ez a taktika a repóban hátrébb van.

Amit ezen a szinten **nem** lehet látni: a firmware-/bootkit-szintű perzisztenciát (T1542), mert az az operációs rendszer alatt él; és a cloud-oldali perzisztenciát (OAuth-alkalmazás hozzájárulás, felhő-szerepkör), mert ahhoz cloud audit log kellene.

## Lefedettség ebben a repóban

Jelenleg **4 szabály** viseli ezt a taktika-tag-et:

**[[T1505 - Server Software Component]] `.003` (Web Shell) — 2 szabály.** DETECT-2026-0039 (feltöltés + azonnali visszahívás korrelációja, `custom.splunk.raw_query`-vel megvalósított kétesemény-párosítás) és DETECT-2026-0040 (a már elhelyezett webshell vezérlése a query stringen keresztül). Mindkettő nginx `access_combined` logból, `experimental` státuszban, `high` szinten. Fontos korlát: **egyik sem a fájlt látja, hanem a HTTP-kérést** — a MITRE saját T1505.003 analitikái a webroot-ba írt fájlt és a web szerver folyamatából induló shellt nevezik meg elsődleges jelként, és ebből a repóban egyik sem áll rendelkezésre, mert a webszerver-hoston nincs végponti telemetria. Részletek: [[T1505.003 - Web Shell]].

**[[T1197 - BITS Jobs]] — 2 szabály.** DETECT-2026-0005 (`bitsadmin` / BITS PowerShell cmdletek) és DETECT-2026-0006 (`SetNotifyCmdLine`, ami a BITS-job befejeződéséhez kapcsol parancsot — ez a tulajdonképpeni perzisztencia-mechanizmus, ezért `critical`). Mindkettő `stable`, Sysmon EID 1-ből.

A kép tehát az, hogy a taktikának **két szűk, jól kidolgozott szelete** van lefedve, a fősodra pedig teljesen üres: nincs egyetlen szabály sem a három legnagyobb súlyú technikára ([[T1547 - Boot or Logon Autostart Execution]], [[T1053 - Scheduled Task-Job]], [[T1543 - Create or Modify System Process]]). Ezek közül a T1053 és a T1543 parancssori úton (Sysmon EID 1) *ma is* detektálható lenne — a T1547 viszont registry-telemetriát kíván, ami pipeline-oldali előfeltétel. A prioritási sorrend tehát ebből adódik: először az, ami a meglévő adatforráson elkészíthető.

## Saját feljegyzések

