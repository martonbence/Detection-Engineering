---
mitre_id: T1557
mitre_type: technique
name: Adversary-in-the-Middle
aliases:
  - T1557
  - Adversary-in-the-Middle
  - AiTM
  - MiTM
url: https://attack.mitre.org/techniques/T1557/
tactic:
  - "[[TA0006 - Credential Access]]"
subtechnique_count: 4
platforms:
  - Windows
de_priority: magas
coverage: részleges
status: kész
---
# T1557 — Adversary-in-the-Middle

## Lényeg

A támadó a hálózati kommunikációba ékelődik be két végpont, vagy egy végpont és az infrastruktúra közé, hogy onnan lehallgassa vagy manipulálja a forgalmat. A közös nevező itt nem egy konkrét protokoll, hanem a **pozíció**: a támadó hamis hálózati-rétegbeli válaszokkal (névfeloldás, ARP, DHCP) elhiteti az áldozat gépével, hogy ő a legitim célpont, majd az így hozzá irányuló forgalmat vagy csak lehallgatja, vagy aktívan tovább is adja (relay) egy másik, valódi célpont felé.

Ez utóbbi — a **relay** — teszi ezt a technikát különösen veszélyessé a puszta lehallgatáshoz képest: a támadónak nem kell megfejtenie egy hash-t, mert a hitelesítési kísérletet élőben, a saját nevében továbbküldve **azonnal hitelesített session-t** kap egy másik gépen, az áldozat identitásával.

> [!quote] MITRE definíció
> Adversaries may attempt to position themselves between two or more networked devices using a man-in-the-middle (MiTM) technique to support follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation.

## Mihez vezet

A megszerzett NTLM hash-t vagy — sikeres relay esetén — a már hitelesített élő session-t a támadó tipikusan a [TA0008 - Lateral Movement] felé viszi: célja, hogy egyetlen hamis broadcast-válaszból kiindulva, jelszó feltörése nélkül, közvetlenül egy másik gépen jelenjen meg az áldozat identitásával.

## Altechnikák

- [[T1557.001 - LLMNR-NBT-NS Poisoning and SMB Relay|LLMNR/NBT-NS Poisoning and SMB Relay]] — a Windows névfeloldási broadcast-forgalmát célozza; ez az egyetlen altechnika, aminek van érdemi Windows-natív telemetriája
- [[T1557.002 - ARP Cache Poisoning]] — nem a névfeloldást, hanem a helyi L2 szegmens ARP-tábláját hamisítja meg; végponti oldalról gyakorlatilag láthatatlan
- [[T1557.003 - DHCP Spoofing]] — egy rogue DHCP szerver felállításával a kliens gateway/DNS beállítását téríti el; a detekció a DHCP szerver oldalán él, nem a végponton
- **T1557.004 Evil Twin** — hamis Wi-Fi access point; vezetékes, AD-központú vállalati környezetben alacsony relevanciájú, ebben a vault-ban egyelőre hatókörön kívül

## Összehasonlítás

|                    | [[T1557.001 - LLMNR-NBT-NS Poisoning and SMB Relay\|.001 LLMNR/NBT-NS + SMB Relay]] | [[T1557.002 - ARP Cache Poisoning\|.002 ARP Cache Poisoning]] | [[T1557.003 - DHCP Spoofing\|.003 DHCP Spoofing]] |
| ------------------ | ------------------------------------------------------------ | -------------------------------------------------------------- | ---------------------------------------------------- |
| **Cél**            | hamis válasz a névfeloldási broadcast/multicast kérésre, hogy a kliens a támadóhoz forduljon hitelesítésre | hamis ARP válasz, hogy az L2 forgalom a támadón menjen át        | rogue DHCP szerver, hogy az új kliens a támadót kapja gateway/DNS-ként |
| **Mit szerez meg** | NTLMv2 hash, vagy — relay esetén — egy élő, már hitelesített SMB session | lehallgatott forgalom, ebből esetlegesen hitelesítő adat          | az elfogadó kliensek teljes forgalmának átirányítását |
| **Réteg**          | alkalmazás / névfeloldás                                       | hálózati (L2)                                                    | hálózati (DHCP)                                       |
| **Eszközök**       | Responder, Inveigh, Impacket `ntlmrelayx`                     | Ettercap, Bettercap, `arpspoof`                                  | saját rogue DHCP szerver, Yersinia                     |
| **Telemetria**     | Sysmon EID 1 (eszköz indítása); hálózati szenzor az UDP 5355/137 válaszokra (nincs ebben a pipeline-ban); natívan Security 4624 Type 3 a célgépen | gyakorlatilag nincs végponti jel — switch/IDS ARP inspection log | DHCP szerver saját logja (lease-konfliktus, ismeretlen szerver) |
| **Detekció helye** | végpont (ha a támadó gépe is monitorozott) + a relay célgépe   | hálózati eszköz (switch, IDS)                                    | DHCP szerver                                          |
| **DE prioritás**   | magas                                                          | alacsony                                                          | alacsony                                              |

A táblázat legfontosabb sora ugyanaz, mint [[T1003 - OS Credential Dumping]]-nál: csak a .001-nek van érdemi **végponti** lába. A .002 és .003 detekciója nem SIEM-probléma — ott a hálózati eszközök (switch DAI/DHCP snooping) konfigurálása az elsődleges védelmi vonal, nem egy Sysmon-alapú szabály.

## Mitigáció

- **LLMNR/NBT-NS letiltása GPO-val** — a legegyszerűbb és leghatékonyabb egyetlen kontroll a .001 ellen: ha a broadcast-alapú névfeloldás ki van kapcsolva, a Responder-nek nincs mire válaszolnia
- **SMB Signing kikényszerítése** — akkor is megakadályozza a sikeres relay-t, ha a hitelesítési kísérlet megtörténik, mert az aláíratlan SMB session-t a célgép elutasítja
- **Dynamic ARP Inspection (DAI)** a switch-eken — a .002 ellen
- **DHCP Snooping** a switch-eken — a .003 ellen; csak megbízható portokról fogad el DHCP szerver-válaszokat
- **802.1X port-alapú hitelesítés** — általános védelem az összes altechnika ellen, mert megnehezíti, hogy egy idegen eszköz egyáltalán bekerüljön a szegmensbe

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás                        | Típus    | Megjegyzés                                                                 | Érintett altechnika |
| ---------------------------------- | -------- | --------------------------------------------------------------------------- | -------------------- |
| Sysmon EID 1 (ProcessCreate)       | Process  | Responder / Inveigh / `ntlmrelayx` elindulása — csak ha a támadó gépe is monitorozott | .001                 |
| Hálózati szenzor (Zeek/Suricata)   | Network  | LLMNR/NBT-NS kérés (UDP 5355/137), amire nem-autoritatív host válaszol — a mérgezés egyetlen közvetlen jele; nincs ebben a pipeline-ban | .001                 |
| Windows Security 4624 (Type 3)     | Logon    | NTLM hitelesítés anomális forrásból vagy nem egyező workstation névvel      | .001                 |
| Switch / IDS ARP inspection log   | Network  | duplikált vagy inkonzisztens MAC–IP párosítás                              | .002                 |
| DHCP szerver log                   | Network  | ismeretlen szervertől érkező lease-ajánlat, lease-konfliktus                | .003                 |

### Detekciós lehetőség

Az altechnikák három, egymástól teljesen független rétegben zajlanak (alkalmazás/névfeloldás, L2, DHCP), ezért a technika-szintű lefedettség nem oldható meg egyetlen adatforrásból — ugyanaz a szerkezeti probléma, mint [[T1003 - OS Credential Dumping]]-nál a DCSync esetén.

A .001 az egyetlen, ahol a Sysmon és a natív Windows log ténylegesen látja a tevékenységet: a támadó gépén az eszköz elindulása (ha az is monitorozott host), és — függetlenül attól, hogy a támadó gépe látszik-e — a célgépen a **4624 Type 3 NTLM logon**, ami relay esetén egy olyan forrásból jön, ahonnan a felhasználó ténylegesen nem szokott bejelentkezni. Ez utóbbi a megbízhatóbb jel, mert nem függ attól, hogy a támadó infrastruktúráját egyáltalán látja-e a monitorozás.

A .002 és .003 detekciója **nem SIEM-probléma**: az ARP-mérgezés a helyi szegmensen belül zajlik, ahol a végponti agent nem lát semmit, a rogue DHCP pedig csak a DHCP szerver saját logjában hagy nyomot. Mindkettőnél a védelem a hálózati eszközök (switch DAI, DHCP snooping) konfigurálásán múlik, ugyanúgy, ahogy a [[T1595 - Active Scanning]]-nál az aktív scanning elleni védelem is elsősorban IPS/tűzfal-oldali, nem detekciós szabály.

## Kapcsolódó szabályok

| detect_id | Szabály | Altechnika | Telemetria | Szint |
| --------- | ------- | ---------- | ---------- | ----- |
| [DETECT-2026-0034](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0034_LLMNR-NBT-NS-Poisoning-and-SMB-Relay-Tooling-Execution.yml) | LLMNR/NBT-NS Poisoning and SMB Relay Tooling Execution | .001 | Sysmon EID 1 (folyamatindítás; T1557.001-only 2026-09-10 óta) | critical |

*A .002 és .003 továbbra is fedetlen — mindkettőnek gyakorlatilag nincs végponti telemetriája (lásd az Összehasonlítás táblát), a védelmük hálózati eszköz (switch, DHCP szerver) oldali, nem SIEM-szabály kérdése.*

## Kapcsolódó jegyzetek

- **Rokon technikák:** [[T1187 - Forced Authentication]] — mindkettő a cél NTLM-hitelesítésének kikényszerítéséről szól, csak a .001 a *válaszokat* hamisítja, a T1187 magát a *kezdeményezést* csalja ki (pl. egy SMB útvonal megnyitásával); [[T1003 - OS Credential Dumping]] — alternatíva ugyanarra a célra (domain hitelesítő adat), végponti memóriaolvasás helyett hálózati pozícióból
- **MITRE:** https://attack.mitre.org/techniques/T1557/

## Saját feljegyzések

