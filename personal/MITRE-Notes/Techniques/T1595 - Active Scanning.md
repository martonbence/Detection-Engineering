---
mitre_id: T1595
mitre_type: technique
name: Active Scanning
url: https://attack.mitre.org/techniques/T1595/
tactic:
  - "[[TA0043 - Reconnaissance]]"
subtechnique_count: 3
platforms:
  - PRE
---
# T1595 — Active Scanning

A támadó aktív felderítő vizsgálatot végez annak érdekében, hogy információkat gyűjtsön a célpont infrastruktúrájáról. A tevékenység hálózati forgalmon keresztül zajlik, és három jól elkülöníthető altechnikára bontható:

Három főbb típusa:
- A [[T1595.001 - Scanning IP Blocks]] célja megállapítani, hogy mely IP-címek vannak aktív használatban, és az azokon futó végpontokon milyen szolgáltatások, szoftverek és verziók találhatók.
- A [[T1595.002 - Vulnerability Scanning]] tipikusan az előzőt követi — célja megállapítani, hogy a feltérképezett végpontokon futó szolgáltatások sérülékenyek-e, és azok illeszkednek-e egy ismert exploit követelményeihez.
- A [[T1595.003 - Wordlist Scanning]] az alkalmazási rétegben zajlik — célja rejtett webes tartalmak, könyvtárak, adminisztrációs felületek, illetve cloud tárolók azonosítása szólisták segítségével.

Az Active Scanning nem önmagában álló tevékenység, hanem más technikák belépési pontja. Az összegyűjtött információkat a támadó felhasználhatja további felderítéshez, célzott exploit vagy payload fejlesztéséhez, vagy közvetlen belépési kísérlethez — például egy nyitott RDP port azonnal [TA0001 - Initial Access] célpont lesz.

---
## Mihez vezet

A felderítés során összegyűjtött adatot (élő IP-k, nyitott portok, sérülékeny szolgáltatások) a támadó tipikusan a [TA0001 - Initial Access] felé viszi: célja, hogy a feltérképezett gyenge ponton — pl. egy nyitott RDP porton vagy egy sérülékeny webes szolgáltatáson — keresztül megszerezze az első belépési pontot a célkörnyezetbe.

---
##  Sub-techniques

| Sub-Technique ID                       | Detection Engineering prioritás |
| -------------------------------------- | ------------------------------- |
| [[T1595.001 - Scanning IP Blocks]]     | Alacsony                        |
| [[T1595.002 - Vulnerability Scanning]] | Alacsony                        |
| [[T1595.003 - Wordlist Scanning]]      | Alacsony                        |

---
## Mitigáció

Ez a technika nem könnyen mérsékelhető megelőző ellenőrzésekkel, mivel a vállalati védelmi és ellenőrzési intézkedéseken kívüli viselkedésen alapul.

---
## Detekciós stratégia

### Szükséges telemetria

| Adatforrás                       | Típus                | Megjegyzés                                                              | Érintett altechnika             |
| -------------------------------- | -------------------- | ----------------------------------------------------------------------- | ------------------------------- |
| Tűzfal log                       | Network Traffic      | Befelé irányuló forgalom, elutasított kapcsolatok                       | T1595.001, T1595.002            |
| IDS/IPS log                      | Network Traffic      | Signature-based scan detekció                                           | T1595.001, T1595.002, T1595.003 |
| Web szerver / Proxy log (Access) | Network Traffic      | HTTP request anomáliák                                                  | T1595.002, T1595.003            |
| NetFlow / IPFIX                  | Network Traffic Flow | Forgalmi minta elemzés                                                  | T1595.001                       |
| Cloud audit log                  | Cloud Storage        | S3 / GCP bucket hozzáférési kísérletek, nem létező bucket névfeloldások | T1595.003                       |
### Detekciós lehetőség

Az Active Scanning detektálható hálózati szinten, de a gyakorlatban rendkívül nehezen mitigálható hatékonyan, mivel ugyanezeket a tevékenységeket legitim szolgáltatások (keresőmotor crawlerek, biztonsági scannerek, monitoring eszközök) is folyamatosan végzik — ez magas zajszintet és sok false positive riasztást generál.

A három altechnika eltérő hálózati rétegben zajlik, ezért a detekció fókusza altechnikánként eltér — a részletes detekciós logika az egyes subtechnika fájlokban található. 
Általánosan elmondható azonban, hogy az Active Scanning elleni védelmet elsősorban nem SIEM oldalon kell megoldani, hanem az IPS, a tűzfal és — webes felületek esetén — a WAF megfelelő konfigurálásával. Ennek oka, hogy egyrészt ezek a minták memóriaigényes, stateful detekciót igényelnek, másrészt pedig a riasztások nem actionable típusúak, hiszen nincsen kompromittált végpont és a false positive arány is rendkívül magas.

---
## Összefoglaló táblázat

|                | [[T1595.001 - Scanning IP Blocks\|T1595.001 — Scanning IP Blocks]]                          | [[T1595.002 - Vulnerability Scanning\|T1595.002 — Vulnerability Scanning]]   | [[T1595.003 - Wordlist Scanning\|T1595.003 — Wordlist Scanning]]                         |
| -------------- | --------------------------------------------------------- | -------------------------------------- | ------------------------------------------------------- |
| **Cél**        | Használatban lévő IP-címek, és nyitott portok azonosítása | Exploitálható sérülékenységek keresése | Rejtett webes tartalmak és cloud tárolók feltérképezése |
| **Réteg**      | Hálózati                                                  | Hálózati + Alkalmazási                 | Alkalmazási                                             |
| **Eszközök**   | nmap, masscan                                             | Nessus, OpenVAS, Nuclei                | Gobuster, DirBuster, s3recon                            |
| Detekció helye | Tűzfal, IPS                                               | Tűzfal, IPS, webszerver / proxy        | WAF, webszerver / proxy, cloud audit log                |
| DE prioritás   | Alacsony                                                  | Alacsony                               | Alacsony                                                |

## Kapcsolódó jegyzetek
