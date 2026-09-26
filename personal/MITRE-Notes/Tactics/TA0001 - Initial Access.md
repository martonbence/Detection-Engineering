---
mitre_id: TA0001
mitre_type: tactic
name: Initial Access
aliases:
  - TA0001
  - Initial Access
url: https://attack.mitre.org/tactics/TA0001/
matrix_position: 3
technique_count: 11
de_priority: kritikus
coverage: részleges
---
# TA0001 — Initial Access

## Cél

A támadó itt szerzi meg az **első lábnyomot** a célkörnyezetben: azt a pillanatot, amikor a tevékenysége átlép a saját infrastruktúrájáról a célpont rendszereire. Ez a taktika a pre-kompromittációs fázis (Reconnaissance, Resource Development) és a tényleges behatolás közötti határvonal — előtte a támadó csak *tud* a célpontról, utána *van benne*.

A belépési pontok két, detekciós szempontból nagyon eltérő családra oszlanak. Az egyik a **technikai kihasználás**: egy internetről elérhető szolgáltatás sérülékenységének kiaknázása (T1190), vagy a felhasználó böngészőjének megtámadása egy weboldalon keresztül (T1189). A másik a **legitim belépés visszaélésszerű használata**: ellopott hitelesítő adattal VPN-re/RDP-re bejelentkezés (T1078, T1133), vagy egy megbízott harmadik fél hozzáférésének kihasználása (T1199). Az első családnál van payload és exploit, tehát van szignatúra; a másodiknál a támadó ugyanazt teszi, mint egy valódi felhasználó, és a jel kizárólag a kontextusban van (honnan, mikor, milyen gyakran).

Detection engineering szempontból ez a taktika azért különösen értékes, mert **itt még a peremen van a támadó**: minden későbbi taktika (Execution, Persistence, Lateral Movement) költségesebb detektálni, mert addigra a tevékenység a normál belső forgalomba olvad.

> [!quote] MITRE definíció
> The adversary is trying to get into your network.

## Hely a támadási láncban

- **Előtte tipikusan:** [TA0043 - Reconnaissance] — a támadó itt találja meg azt a konkrét felületet (nyitott port, sérülékeny szolgáltatás, rejtett admin felület), amit itt kihasznál; illetve [TA0042 - Resource Development], ahol az ehhez szükséges eszközt/infrastruktúrát (exploit, phishing domain, C2 callback szerver) felépíti  *(taktika-hivatkozás szándékosan egykapcsos: ne kösse össze a taktikákat a gráf nézetben)*
- **Utána tipikusan:** [TA0002 - Execution] — a belépés önmagában csak egy lehetőség; a támadónak kódot kell futtatnia, hogy bármit is tudjon kezdeni vele. Sok technika (T1190, T1189) egyetlen lépésben adja mindkettőt, ezért a két taktika itt gyakran időben elválaszthatatlan
- **Mit feltételez:** kívülről elérhető támadási felület (publikált szolgáltatás, kifelé böngésző felhasználó, külső partner-kapcsolat), és egy **konkrét, azonosított gyengeség** ezen a felületen — legyen az egy nem patchelt CVE, egy validáció nélküli feltöltési pont, vagy egy ellopott hitelesítő adat. Jogosultság a célkörnyezetben **nem** előfeltétel: ez az a taktika, ami definíció szerint nulla hozzáférésből indul

## Technikák

| ID                                                  | DE prioritás | Lefedettség | Megjegyzés                                                                                                              |
| --------------------------------------------------- | :----------- | :---------- | :---------------------------------------------------------------------------------------------------------------------- |
| [[T1190 - Exploit Public-Facing Application]]        | kritikus     | részleges   | 3 szabály (0037 traversal, 0041 SQLi, 0043 Log4Shell) nginx access logból; **kísérlet-szintű** jel, a sikert nem látja   |
| [[T1189 - Drive-by Compromise]]                      | közepes      | részleges   | DETECT-2026-0042 (reflected XSS a kérésben); a böngésző-oldali kihasználás maga végponti telemetria, ami itt nincs      |
| [[T1566 - Phishing]]                                 | kritikus     | nincs       | 4 altechnika; e-mail gateway log kellene hozzá — ebben a pipeline-ban nincs ilyen adatforrás                             |
| [[T1078 - Valid Accounts]]                           | kritikus     | nincs       | Átfed a Persistence/Privilege Escalation/Lateral Movement taktikákkal; a jel tisztán kontextuális (4624 + anomália)      |
| [[T1133 - External Remote Services]]                 | magas        | nincs       | Kifelé publikált RDP/VPN/SSH; a labban a brute-force oldala (T1110) fedett, a *sikeres* külső belépés nem                |
| [[T1199 - Trusted Relationship]]                     | közepes      | nincs       | Beszállítói/MSP-hozzáférés kihasználása — hatókörön kívül, nincs ilyen kapcsolat a labban                                |
| [[T1195 - Supply Chain Compromise]]                  | közepes      | nincs       | 3 altechnika; build/szállítói lánc — ez inkább a repo saját CI-jének security-kérdése (Priya hatóköre), nem SIEM-szabály |
| [[T1091 - Replication Through Removable Media]]      | alacsony     | nincs       | USB-alapú terjedés; Sysmon EID 11-ből elvileg látszik, de a labban nincs removable media                                 |
| [[T1200 - Hardware Additions]]                       | alacsony     | nincs       | Fizikai eszköz behozása — nem végponti log kérdése                                                                      |
| [[T1659 - Content Injection]]                        | alacsony     | nincs       | Forgalomba injektált tartalom (ISP/AiTM pozícióból); hálózati szenzort igényel                                           |
| [[T1669 - Wi-Fi Networks]]                           | —            | nincs       | Vezeték nélküli belépés; WIPS-kérdés, ugyanaz a szerkezeti korlát, mint [[T1557 - Adversary-in-the-Middle]] .004-nél     |

## Detekciós stratégia (taktikai szint)

A taktika detekciója **három, egymást nem helyettesítő rétegben** él, és ebben a repóban jelenleg csak az első van meg:

- **Alkalmazási réteg (web szerver access log).** Minden request-hordozott kihasználási kísérlet — traversal, SQLi, XSS, JNDI-lookup, webshell-feltöltés — itt hagy nyomot, mert a támadó payloadja *része a kérésnek*, amit a szerver amúgy is naplóz. Ez a réteg olcsó, magas volumenű, és **kísérlet-szintű**: a nginx access log nem tartalmaz sem request bodyt, sem response bodyt, tehát a POST-ban szállított payload láthatatlan, és a sikeres kihasználás sem igazolható belőle, csak a próbálkozás. Ez nem hangolási hiba, hanem az adatforrás határa.
- **Végponti réteg (Sysmon a kiszolgálón).** A kihasználás *következménye*: a web szerver folyamata (nginx, w3wp.exe, httpd) shellt vagy interpretert indít, vagy fájlt ír a webroot alá. A MITRE saját T1190/T1505.003 analitikái pontosan ezt a láncot nevezik meg elsődleges jelnek — és **ez a réteg jelenleg hiányzik**, mert a web szerver ([[T1595 - Active Scanning]]-nál is ugyanez a gép) Linux, a Linux-végponti detekció pedig ebben a repóban tudatosan nincs felépítve. Gyakorlati következmény: a "kísérlet → siker" átmenetet nem látjuk, csak a kísérletet.
- **Hitelesítési réteg (natív Windows Security log).** A legitim-belépés-családhoz (T1078, T1133) egyáltalán nincs payload, amit keresni lehetne — ott a 4624/4625 esemény *kontextusa* a jel: szokatlan forrás-IP, szokatlan időpont, szokatlan gép. Ez küszöb- és bázisvonal-alapú detekció, nem szűrés, ugyanaz a szerkezeti probléma, mint [TA0006 - Credential Access] címtár-oldalán.

A taktikára jellemző **közös FP-forrás** nem a legitim alkalmazáshasználat, hanem a **saját és idegen scanner-forgalom**: egy internetre kitett hoston a traversal-, SQLi- és JNDI-payload folyamatos háttérzaj, függetlenül attól, hogy van-e egyáltalán sérülékeny alkalmazás mögötte. Ez a taktika legfontosabb triage-tanulsága: a web-oldali szabályok **aktivitás-/enrichment-jelként** értékesek (ki nyúlkál a hostra, mivel), nem önálló, azonnali incidens-triggerként — a valódi eszkalációt a válaszkód, a válasz mérete és a végponti korrobáció adja, nem a payload puszta jelenléte.

Amit ezen a szinten **nem** lehet látni: a phishing-alapú belépés (T1566) e-mail-gateway adatforrás nélkül, a POST-ban vagy JSON-bodyban szállított payload (a log_format nem rögzíti), és a DOM-alapú, kizárólag kliensoldalon lefutó XSS (a szerverhez soha nem ér el).

## Lefedettség ebben a repóban

Jelenleg **4 szabály**, mind ugyanarról az egy adatforrásról (nginx `access_combined` a `linux-victim` hoston), mind `experimental` státuszban:
[[T1190 - Exploit Public-Facing Application]] alatt **DETECT-2026-0037** (path traversal / LFI), **DETECT-2026-0041** (SQL injection) és **DETECT-2026-0043** (Log4Shell `${jndi:` lookup); [[T1189 - Drive-by Compromise]] alatt **DETECT-2026-0042** (reflected XSS). Mindegyik a kérés `uri_path` és `uri_query` mezőjét vizsgálja — a 0043 ezen túl a `useragent` és `referer` mezőt is.

A lefedettség tehát **egy rétegben mély, a többiben üres**: a request-hordozott kihasználási kísérletek négy nagy családja megvan, de a taktika két legnagyobb súlyú technikájára ([[T1566 - Phishing]], [[T1078 - Valid Accounts]]) nulla szabály van, és mindkettő adatforrás-hiány miatt, nem szabályírási kapacitás miatt: a phishinghez e-mail gateway log kell, a Valid Accounts-hoz pedig bázisvonal-alapú logon-elemzés.

A legnagyobb *strukturális* hiány viszont nem egy technika, hanem egy réteg: a **web szerver végponti telemetriája**. A jelenlegi négy szabály mind azt látja, hogy valaki *megpróbálta*; egyik sem látja, hogy sikerült-e. Ezt a rést nem lehet pattern-munkával bezárni az access logon belül — vagy a nginx `log_format` bővül (request body, további header), vagy a webszerver-hoston lesz folyamatindítás-szintű telemetria. Amíg egyik sem történik meg, a négy szabály kimenete triage-input, nem verdikt.

## Saját feljegyzések

