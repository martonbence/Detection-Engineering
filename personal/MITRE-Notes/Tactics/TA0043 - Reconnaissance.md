---
mitre_id: TA0043
mitre_type: tactic
name: Reconnaissance
url: https://attack.mitre.org/tactics/TA0043/
technique_count: 11
---
# TA0043 — Reconnaissance

> A támadó olyan információkat próbál gyűjteni, amelyek felhasználhat a jövőbeli műveleteinek megtervezéséhez.
> Ilyen információk lehetnek:
> 	- Szervezeti
> 	- Infrastruktúra
> 	- Személyzeti részletek.
>Ezek azért fontosak, mert kontextust adhatnak a támadónak, aki ezen információk birtokában könnyebben elérheti a célját. 
>Például:
> 	- Hitelesebb phishing levelet tud küldeni, ami segíthet neki az Initial Access-ben
> 	- Scan-tevékenység használata során megismerheti a publikus IP-címeket, és az azokon nyitva lévő portokat, vagy a peremvédelmi biztonsági megoldások válaszcsomagjaiból megismerheti a hálózati eszközök típusait, ami később fontos információval szolgálhat számára, amikor sérülékenység után kutat.

>Ez a MITRE ATT&CK mátrix első taktikája, mely a pre-kompromittációs fázis része. 
>A taktika két ágra bontható: **passzív** és **aktív** felderítésre:
>	- A **passzív** felderítés során a támadó nyílt forrásokból (OSINT), külső adatbázisokból, vagy a célpont publikusan elérhető felületeiről gyűjt információt anélkül, hogy közvetlen interakcióba lépne az infrastruktúrával.
>	- Az **aktív** felderítés során a támadó már közvetlen interakcióba lép a célponttal — port scan, service fingerprinting formájában.
>
>A Reconnaissance taktika célja tehát a célpont minél pontosabb megismerése.
---

## 📋 Technikák

| No. | ID                                             | Prioritás |
| --- | :--------------------------------------------- | :-------- |
| 1.  | [[T1595 - Active Scanning]]                    | 🟡 MEDIUM |
| 2.  | [[T1592 - Gather Victim Host Information]]     | 🟢 LOW    |
| 3.  | [[T1589 - Gather Victim Identity Information]] | 🟡 MEDIUM |
| 4.  | [[T1590 - Gather Victim Network Information]]  | 🟢 LOW    |
| 5.  | [[T1591 - Gather Victim Org Information]]      | 🟢 LOW    |
| 6.  | [[T1598 - Phishing for Information]]           | 🟡 MEDIUM |
| 7.  | [[T1597 - Search Closed Sources]]              | 🟢 LOW    |
| 8.  | [[T1596 - Search Open Technical Databases]]    | 🟢 LOW    |
| 9.  | [[T1593 - Search Open Websites Domains]]       | 🟢 LOW    |
| 10. | [[T1594 - Search Victim-Owned Websites]]       | 🟢 LOW    |
| 11. | [[T1685 - Search Threat Vendor Data]]          |           |

---
## 🔍 Detekciós stratégia (taktikai szint)

A Reconnaissance nagy részét **nem lehet detektálni** a saját infrastruktúrán belülről — a passzív OSINT tevékenység teljes egészében a támadó oldalán zajlik. Ami detektálható:
	- **Aktív scanning** — hálózati IDS/IPS, firewall log-ok szokatlan portok vagy IP-k felőli sweep-jei
	- **Phishing for information** — email gateway log-ok, credential harvesting oldalak elleni kattintások proxy log-ban
	- **Search Victim-Owned Websites** — web szerver access log-ok: crawlerek, szokatlan user-agent-ek, rendszeres automated lekérések

Általános detekciós jellemző: a Reconnaissance ritkán hagy magas fidelitású, egyértelmű IoC-t. Inkább aggregált anomáliák és threat intelligence feed-ek (ismert scanner IP-k) adnak értéket ezen a szinten.

---
## 📝 Személyes feljegyzések

*Ide kerülhetnek saját tapasztalatok, SOC-ban látott minták, környezet-specifikus megjegyzések.*
