---
mitre_id: T1071
mitre_type: technique
name: Application Layer Protocol
aliases:
  - T1071
  - Application Layer Protocol
url: https://attack.mitre.org/techniques/T1071/
tactic:
  - "[[TA0011 - Command and Control]]"
subtechnique_count: 5
platforms:
  - Windows
  - Linux
  - macOS
de_priority: közepes
coverage: nincs
status: kész
---
# T1071 — Application Layer Protocol

## Lényeg

A támadó a command-and-control (C2) kommunikációt egy elterjedt alkalmazás-rétegbeli protokollba csomagolja (HTTP/HTTPS, DNS, e-mail, fájlátviteli protokollok, publish/subscribe rendszerek), hogy a forgalma beleolvadjon a normál hálózati háttérzajba. A közös nevező az öt altechnikában a **protokoll megválasztása** — mindegyik ugyanazt a célt szolgálja (a C2-csatorna elrejtése legitim forgalom mögé), csak más portot/protokoll-mintát használ, más védelmi eszköz (proxy, DNS-szűrő, mail gateway) hatáskörébe esve.

Ez a legelterjedtebb C2-csatorna-kategória, mert minden altechnikájának a portja szinte minden hálózati szegmensen kifelé engedélyezett, és a titkosított forgalom tartalma tűzfal-szinten (TLS-inspekció nélkül) nem is vizsgálható — a védelem ezért jellemzően metaadatokra (domain-reputáció, időzítés-minta, forgalmi anomália), nem a tartalomra épül.

> [!quote] MITRE definíció
> Adversaries may communicate using application layer protocols associated with client-server model traffic to avoid detection/network filtering by blending in with existing traffic.

## Altechnikák

- **[[T1071.001 - Web Protocols]]** — HTTP/HTTPS-alapú C2-csatorna; **nincs önálló szabály, csak egyetlen named-tool kulcsszó egy általánosabb reverse-shell szabályban**
- .002 File Transfer Protocols — FTP/SFTP-alapú C2 vagy exfiltrációs csatorna
- .003 Mail Protocols — SMTP/IMAP/POP3-alapú C2, tipikusan egy kompromittált vagy támadó-kontrollált postafiókon keresztül
- .004 DNS — DNS-lekérdezésekbe/válaszokba kódolt C2-csatorna (DNS tunneling), a legkevésbé blokkolt kimenő protokoll a legtöbb hálózaton
- .005 Publish/Subscribe Protocols — üzenetsor-alapú protokollok (MQTT és hasonlók) visszaélésszerű felhasználása C2-re

## Mitigáció

- **Proxy-alapú kimenő szűrés és domain-allowlist** — csökkenti a .001/.002 hatókörét, de egy jó reputációjú, újonnan regisztrált domain továbbra is átjuthat.
- **TLS-inspekció** teszi lehetővé a HTTPS-tartalom vizsgálatát, jelentős üzemeltetési/adatvédelmi költséggel.
- **DNS-forgalom anomália-elemzése** (szokatlanul hosszú/gyakori lekérdezések, magas entrópiájú subdomain) a .004 elleni gyakorlatilag egyetlen realista védelem.
- **Hálózati viselkedés-elemzés (beacon-detekció)** — rendszeres időközönkénti, kis méretű kérések azonos célra — a leghatékonyabb, technikafüggetlen megközelítés mind az öt altechnikára, de hálózati szenzor/NDR-szintű képesség, nem végponti Sysmon-alapú szabály.
- Egyik kontroll sem alkalmazható ebben a pipeline-ban, mert a rendelkezésre álló telemetria kizárólag végponti (Sysmon), hálózati szenzor nincs bekötve.

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés | Érintett altechnika |
| ---------- | ----- | ---------- | -------------------- |
| Hálózati szenzor (proxy log / NDR), HTTP(S) metaadat | Network | a technika valódi jele — **nincs ebben a pipeline-ban** | .001 |
| DNS resolver/forwarder log | Network | tunneling-minta — **nincs bekötve** | .004 |
| Mail gateway log | Application | — **nincs bekötve** | .003 |
| Sysmon EID 1 (ProcessCreate) | Process | csak közvetett, eszköznév-alapú jel | .001 |

### Detekciós lehetőség

**Ez a technika ténylegesen nincs önálló szabállyal lefedve egyik altechnikáján sem.** A `.001 Web Protocols`-hoz kapcsolt DETECT-2026-0001 (Reverse Shell Execution via PowerShell or Netcat) elsődlegesen nyers TCP-socket reverse shelleket céloz, és a T1071.001-hez való kapcsolódása egyetlen named-tool kulcsszón (`Invoke-PoshRatHttp`) keresztül történik — ez a helyi eszköz elindítását nézi, nem a HTTP(S) protokoll-forgalmat magát, és minden más HTTP(S)-alapú C2-forma (Cobalt Strike beacon, Sliver, egyedi `Invoke-RestMethod`-loop) kívül esik a hatókörén. A technikailag helyes detekció (beacon-jelleg, domain-reputáció, JA3-ujjlenyomat, DNS-entrópia) mind az öt altechnikánál **strukturálisan kívül esik** azon, amit egyetlen Sysmon `ProcessCreate` esemény megmutathatna — ehhez hálózati szenzor kellene, ami jelenleg nincs a pipeline-ban.

## Kapcsolódó szabályok

| detect_id | Altechnika | Miért csak részleges |
| --------- | ---------- | --------------------- |
| [DETECT-2026-0001](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0001_Reverse-Shell-Execution-via-PowerShell-or-Netcat.yml) (lásd [[T1071.001 - Web Protocols]]) | .001 | Egyetlen named HTTP-RAT eszköz (`Invoke-PoshRatHttp`) elindítása — nem a HTTP(S) forgalom maga, ezért a jegyzet `coverage: nincs` marad a technika szintjén |

**Nem fedett:** .002 File Transfer Protocols, .003 Mail Protocols, .004 DNS, .005 Publish/Subscribe Protocols — és a .001-en belül minden HTTP(S)-alapú C2-forma az egyetlen named-tool kivételével.

## Kapcsolódó jegyzetek

- **Rokon technikák:** [[T1059 - Command and Scripting Interpreter]] — a jelenlegi egyetlen kapcsolódó szabály technikailag egy PowerShell-eszköznév-detekció, nem hálózati C2-elemzés
- **MITRE:** https://attack.mitre.org/techniques/T1071/

## Saját feljegyzések
