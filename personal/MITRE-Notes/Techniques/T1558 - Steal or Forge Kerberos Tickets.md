---
mitre_id: T1558
mitre_type: technique
name: Steal or Forge Kerberos Tickets
aliases:
  - T1558
  - Steal or Forge Kerberos Tickets
url: https://attack.mitre.org/techniques/T1558/
tactic:
  - "[[TA0006 - Credential Access]]"
subtechnique_count: 5
platforms:
  - Windows
de_priority: kritikus
coverage: részleges
status: kész
---
# T1558 — Steal or Forge Kerberos Tickets

## Lényeg

A támadó a Kerberos hitelesítési protokoll jegyeit (TGT vagy TGS) szerzi meg, kovácsolja vagy tölti fel törésre — nem a felhasználó jelszavát próbálja kitalálni, hanem magát a protokoll bizalmi láncát használja ki. Az öt altechnika két, jól elkülöníthető csoportra bomlik: a **hash-birtokláson alapuló kovácsolás** (golden/silver ticket — a támadó már megszerzett egy kulcsfontosságú hash-t, és azzal tetszőleges jegyet gyárt), és a **legitim protokoll-válasz visszaélésszerű felhasználása** (Kerberoasting, AS-REP Roasting — a támadó egy teljesen szabályos KDC-választ kér ki, majd azt offline töri).

Ez a csoportosítás azért kritikus DE-tanulság, mert a két forma detekciós profilja gyökeresen eltér: a kovácsolás az **eszköz-futtatás pillanatában** (Mimikatz/Rubeus parancssor) hagy nyomot, míg a roasting-alapú formák maga a **kérés ténye** teljesen legitim — a támadás az azt követő, a védett környezettől független offline törésben zajlik, ami strukturálisan láthatatlan.

> [!quote] MITRE definíció
> Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket, spoof service tickets, or otherwise abuse the Kerberos protocol.

## Altechnikák

- **[[T1558.001 - Golden Ticket]]** — a domain krbtgt hash birtokában tetszőleges TGT kovácsolása; **lefedve, 1 szabály** (eszköz-jel)
- **[[T1558.002 - Silver Ticket]]** — egy konkrét szolgáltatás-fiók hash-ével TGS kovácsolása, KDC megkerülésével; **lefedve, ugyanaz az 1 szabály**, golden ticket-től megkülönböztetés nélkül
- **[[T1558.003 - Kerberoasting]]** — SPN-es fiókok TGS-ének tömeges lekérése, offline törésre; **lefedve, ugyanaz az 1 szabály** (csak eszköz-jel, natív 4769-alapú detekció hiányzik)
- .004 AS-REP Roasting — olyan fiókok elleni támadás, amiknél a Kerberos pre-authentication ki van kapcsolva; a KDC egy előzetes hitelesítés nélkül ad vissza egy törhető AS-REP választ; nincs lefedve
- .005 Ccache Files — Linux/macOS-oldali Kerberos credential cache fájlok (`/tmp/krb5cc_*`) ellopása; nincs lefedve, Windows-only pipeline

## Mitigáció

- **A krbtgt jelszó kétszeri, egymást követő elforgatása** — az egyetlen kontroll, ami a golden ticket előfeltételét ténylegesen megszünteti egy már megtörtént kompromittálás után.
- **gMSA (group Managed Service Account)** a szolgáltatás-fiókokon — automatikus, hosszú, rendszeresen rotált jelszót garantál, ami mind a silver ticket, mind a Kerberoasting offline törését számításilag kivitelezhetetlenné teszi.
- **Pre-authentication kikényszerítése minden fiókon** — az AS-REP Roasting előfeltételét szünteti meg (ez a MITRE saját ajánlott mitigációja erre az altechnikára).
- **Tiered Administration Model** csökkenti annak valószínűségét, hogy a krbtgt/szolgáltatás-fiók hash egyáltalán elérhető legyen egy alacsonyabb tier kompromittálásából, de nem akadályozza meg a kovácsolást, ha a hash már megvan.

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés | Érintett altechnika |
| ---------- | ----- | ---------- | -------------------- |
| Sysmon EID 1 (ProcessCreate) | Process | Mimikatz/Rubeus eszköz-jel — a jelenlegi egyetlen szabály erre épül | .001, .002, .003 |
| Windows Security 4768/4769 (DC) | Kerberos | a valódi, protokoll-szintű jel mindegyik altechnikára — **nincs bekötve** | .001, .003, .004 |

### Detekciós lehetőség

A repó lefedettsége **kizárólag az eszköz-futtatás jelére** épül, egyetlen, mindhárom kovácsolási/roasting-altechnikát átfedő szabállyal (DETECT-2026-0022) — ez a repó legnagyobb strukturális hiánya ezen a technikán: a Mimikatz `kerberos::golden` parancs **azonos** golden és silver ticket kovácsolásakor, tehát a két altechnika a CLI-minta szintjén nem különböztethető meg (lásd [[T1558.002 - Silver Ticket]]). A technikailag helyes, natív detekció — a DC 4768/4769 eseményeinek figyelése (szokatlanul hosszú TGT-érvényesség, RC4 titkosítási típusra szűrt TGS-kérés, sok SPN rövid időn belüli lekérdezése) — egyik altechnikánál sincs implementálva, jóllehet ez fogná meg az Impacket/egyedi-eszközös eseteket is, amiket a jelenlegi CLI-alapú szabály szisztematikusan kihagy. Az .004 AS-REP Roasting teljesen fedetlen — natívan ugyanabból a 4768-as forrásból lenne detektálható (pre-auth nélküli AS-REQ), mint a golden ticket, de erre sincs szabály.

## Kapcsolódó szabályok

| detect_id | Szabály | Altechnika | Miért szükséges |
| --------- | ------- | ---------- | ---------------- |
| [DETECT-2026-0022](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0022_Known-Credential-Dumping-Tool-Execution.yml) | Known Credential Dumping Tool Execution | .001, .002, .003 | Mimikatz `kerberos::golden`/`ptt`, Rubeus `golden`/`silver`/`kerberoast` — csak az eszköz-futtatás jele, protokoll-szintű megkülönböztetés nélkül |

**Nem fedett:** .004 AS-REP Roasting (natívan detektálható lenne, de nincs szabály), .005 Ccache Files (Linux/macOS, kívül esik a Windows-only scope-on). A natív, 4768/4769-alapú detekció mindhárom lefedett altechnikánál is hiányzik — ez a legnagyobb, valódi rés a technika egészén.

## Kapcsolódó jegyzetek

- **Rokon technikák:** [[T1003 - OS Credential Dumping]] — a krbtgt/szolgáltatás-fiók hash leggyakoribb megszerzési útja, ami a golden/silver ticket előfeltétele; [[T1110 - Brute Force]] — a natív DC Security log ugyanazon audit-policy alapon épülne, mint a hiányzó 4768/4769-alapú detekció itt
- **MITRE:** https://attack.mitre.org/techniques/T1558/

## Saját feljegyzések
