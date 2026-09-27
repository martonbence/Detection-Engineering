---
mitre_id: T1566
mitre_type: technique
name: Phishing
aliases:
  - T1566
  - Phishing
url: https://attack.mitre.org/techniques/T1566/
tactic:
  - "[[TA0001 - Initial Access]]"
subtechnique_count: 4
platforms:
  - Windows
  - Linux
  - macOS
  - Cloud (SaaS/Office 365/Google Workspace)
de_priority: kritikus
coverage: részleges
status: kész
---
# T1566 — Phishing

## Lényeg

A támadó elektronikus úton (e-mail, üzenetküldő szolgáltatás, telefon) social engineering-alapú megtévesztéssel próbál kezdeti hozzáférést vagy hitelesítő adatot szerezni. A négy altechnika a **csatorna/mechanizmus** szerint különül el: rosszindulatú melléklet, rosszindulatú link, egy harmadik fél (pl. felhő-alapú fájlmegosztó) szolgáltatásán keresztüli kézbesítés, vagy hangalapú megtévesztés (vishing).

Ez a leggyakoribb kezdeti belépési vektor, mert nem igényel technikai sérülékenységet a célrendszeren — a social engineering önmagában elég "exploit". A védelem ezért is oszlik meg jellemzően két, egymástól függetlenül működő rétegre: az e-mail gateway/sandbox szintű szűrés (a levél/melléklet *tartalmát* vizsgálja, mielőtt eljutna a felhasználóhoz) és a végponti detekció (azt nézi, mi történik, *miután* a felhasználó mégis interakcióba lépett).

> [!quote] MITRE definíció
> Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering.

## Altechnikák

- **[[T1566.001 - Spearphishing Attachment]]** — célzott e-mail rosszindulatú melléklettel (makrós Office-dokumentum, HTA, exploit-terhelt PDF); **lefedve, 1 szabály** (a payload-indítás pillanata, nem a melléklet maga)
- .002 Spearphishing Link — célzott e-mail rosszindulatú linkkel, ami hitelesítő-adat-lopó oldalra vagy drive-by download-ra visz; nincs lefedve
- .003 Spearphishing via Service — kézbesítés egy harmadik fél legitim szolgáltatásán keresztül (pl. LinkedIn üzenet, felhő-alapú fájlmegosztó megosztási link), hogy a vállalati e-mail-szűrést megkerülje; nincs lefedve
- .004 Spearphishing Voice (Vishing) — telefonos/hangalapú social engineering, gyakran help-desk megszemélyesítéssel jelszó-resetelés kicsikarására; nincs lefedve, és strukturálisan sem IT-telemetriával megfigyelhető

## Mitigáció

- **E-mail gateway szintű sandboxing/attachment detonation** — ez a rendszer *előtt* fut, teljesen külön réteg a végponti detekciótól; ebben a pipeline-ban nincs bekötve.
- **Makrók letiltása internetről érkező dokumentumokban** (Mark-of-the-Web-alapú blokkolás) — a .001 leggyakoribb formájának (VBA-makró) előfeltételét szünteti meg.
- **Felhasználói képzés** csökkenti a megnyitás/kattintás valószínűségét minden altechnikánál, de nem szünteti meg — ezért marad a végponti detekció (a payload-indítás pillanata) az utolsó védelmi vonal.
- **Vishing (.004) ellen technikai kontroll gyakorlatilag nincs** — a mitigáció itt tisztán szervezeti/folyamati (help-desk azonosítási protokoll jelszó-reset előtt).

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés | Érintett altechnika |
| ---------- | ----- | ---------- | -------------------- |
| Sysmon EID 1 (ProcessCreate) | Process | `ParentImage`/`ParentCommandLine` — a payload-indítás pillanata a melléklet megnyitása után | .001 |
| E-mail gateway / attachment-sandbox log | Application | a melléklet/link tartalmának vizsgálata — **nincs ebben a pipeline-ban** | .001, .002, .003 |
| Proxy/webes hozzáférési log | Network | a linkre kattintás utáni cél-URL — **nincs bekötve** | .002 |

### Detekciós lehetőség

A repó lefedettsége kizárólag a **.001 végrehajtási szakaszára** korlátozódik — nem magára a levélre/mellékletre, hanem az abból induló gyanús folyamatláncra (lásd [[T1566.001 - Spearphishing Attachment]]). A .002 Spearphishing Link strukturálisan hasonló probléma lenne (a linkre kattintás utáni böngésző→letöltés→futtatás lánc), de erre nincs külön szabály. A .003 és .004 ennél is távolabb esik a jelenlegi Sysmon-only telemetriától: a .003 kézbesítési csatornája (harmadik fél szolgáltatása) és a .004 hangalapú csatornája egyaránt olyan adatforrást igényelne (e-mail/collaboration-platform log, telefonrendszer-log), ami ebben a pipeline-ban nincs jelen.

## Kapcsolódó szabályok

| detect_id | Altechnika | Miért szükséges |
| --------- | ---------- | --------------- |
| [DETECT-2026-0013](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0013_PowerShell-Suspicious-Parent-Process.yml) (lásd [[T1566.001 - Spearphishing Attachment]]) | .001 | Office/script-host/LOLBin szülőfolyamatból induló PowerShell — a melléklet-megnyitás utáni payload-indítás jele |

**Nem fedett:** .002 Spearphishing Link, .003 Spearphishing via Service, .004 Spearphishing Voice.

## Kapcsolódó jegyzetek

- **Rokon technikák:** [[T1059 - Command and Scripting Interpreter]] — a .001 lefedettsége technikailag egy PowerShell-gyanús-szülőfolyamat szabály, nem egy Phishing-specifikus logika
- **MITRE:** https://attack.mitre.org/techniques/T1566/

## Saját feljegyzések
