---
mitre_id: T1040
mitre_type: technique
name: Network Sniffing
aliases:
  - T1040
  - Network Sniffing
  - Packet capture
  - Traffic capture
url: https://attack.mitre.org/techniques/T1040/
tactic:
  - "[[TA0006 - Credential Access]]"
  - "[[TA0007 - Discovery]]"
subtechnique_count: 0
platforms:
  - Windows
  - Linux
  - macOS
  - Network Devices
  - IaaS
de_priority: közepes
coverage: részleges
rules:
  - DETECT-2026-0044
---
# T1040 — Network Sniffing

## Lényeg

A támadó a gép hálózati interfészén **passzívan olvassa a forgalmat**, hogy abból információt nyerjen: hitelesítő adatot, session-tokent, belső hosztneveket, protokoll-verziókat, a hálózat topológiáját. Nem küld semmit, nem módosít semmit — csak hallgat.

Ez a technika azért szerepel **egyszerre két taktikában**, és ezt érdemes rögzíteni, mert ez a lényege: ugyanaz a művelet két különböző nyereséget ad. [TA0006 - Credential Access] oldalon a cél a hitelesítő anyag (cleartext jelszó egy titkosítás nélküli protokollból, NTLMv2 challenge-response, Kerberos ticket); [TA0007 - Discovery] oldalon a cél maga a környezet megismerése — ki beszél kivel, milyen szolgáltatások élnek, hol van a domain controller. A támadó ugyanazzal a `pktmon start` paranccsal mindkettőt megkapja.

A technika gyakorlati korlátja és egyben a legfontosabb tudnivalója: **kapcsolt (switchelt) hálózaton a sniffing önmagában kevés.** A switch csak azt a forgalmat küldi egy portra, ami annak a portnak szól — plusz a broadcast/multicast forgalmat. A támadó tehát a saját gépének forgalmát és a szegmens broadcast-jait látja, semmi többet. Ezért a sniffing a valóságban szinte mindig **egy pozíció-technikával párban** jelenik meg: [[T1557 - Adversary-in-the-Middle]]-vel, ami *odairányítja* hozzá a forgalmat, vagy port mirroring/SPAN konfigurálásával a hálózati eszközön.

> [!quote] MITRE definíció
> Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network.

## Mihez vezet

A lehallgatott hitelesítő anyagot a támadó tipikusan a [TA0008 - Lateral Movement] felé viszi: célja, hogy a hálózaton elfogott jelszóval vagy hash-sel egy másik gépen jelentkezzen be — legitim felhasználóként, exploit nélkül. A Discovery-oldali eredmény (topológia, élő szolgáltatások, ki hitelesít hova) ugyanoda vezet, csak közvetve: a *célpontválasztást* alapozza meg ugyanahhoz a lépéshez.

## Altechnikák

Ennek a technikának az ATT&CK szerint **nincs altechnikája**. A végrehajtási módok viszont detekciós szempontból élesen elválnak (harmadik féltől származó sniffer capture driverrel vs. a Windows saját, beépített capture-képességei vs. raw socket), ezért ez a jegyzet a szokásos "Altechnikák"/"Összehasonlítás" szekciók helyett a "Hogyan csinálják a gyakorlatban" szakaszban tárgyalja őket módszerenként — ugyanazzal a szerkezettel, mint [[T1190 - Exploit Public-Facing Application]] és [[T1189 - Drive-by Compromise]].

## Hogyan csinálják a gyakorlatban

Egygépes technika: minden a monitorozott végponton történik, nincs második szereplő. Ami viszont mindegyik alábbi módszerre közösen igaz: **helyi rendszergazdai jog kell hozzá** — akár a capture driver telepítéséhez/megnyitásához, akár a raw socket létrehozásához. Ez fontos előfeltétel, mert azt jelenti, hogy a sniffing sosem az első lépés a láncban.

### Harmadik féltől származó sniffer capture driverrel

A Wireshark-család (`Wireshark.exe` GUI, `tshark.exe` CLI, `dumpcap.exe` a tényleges capture-motor) és a `WinDump.exe` mind ugyanazon az alapon nyugszik: a **Npcap** (korábban WinPcap) kernel-módú capture driveren. A driver az, ami a hálózati kártyáról promiszkuus módban ki tudja olvasni a kereteket — a felhasználói módú eszköz ezt csak vezérli.

```
"C:\Program Files\Wireshark\tshark.exe" -i 1 -c 5
```

A logban ez `Image` végződésként (`\tshark.exe`) és `OriginalFileName`-ként (`tshark.exe`) is látszik — az utóbbi átnevezés-ellenálló, mert a PE verzió-erőforrásából jön, nem a fájlnévből.

### Raw socket sniffer, driver nélkül

A `RawCap.exe` (Netresec) azért érdemel külön említést, mert **nem igényel semmilyen telepítést**: nyers socketen keresztül olvassa a forgalmat, tehát nincs driver-betöltés, nincs telepítő, egyetlen kis futtatható állomány, ami pendrive-ról is elindul. Ez a "hordozható, nyomtalan" tulajdonság egyben azt is jelenti, hogy legitim vállalati használata gyakorlatilag nincs — a Wireshark-kal szemben, amit a hálózati mérnökök tényleg futtatnak.

### A Windows saját, beépített capture-képességei

Ez a detekciós szempontból legfontosabb ág, mert **nem kell hozzá semmit felmásolni a gépre**. Kettő van:

A `netsh trace` a Windows beépített forgalom-nyomkövetése, ami `capture=yes` mellett tényleges csomagrögzítést végez ETL formátumba:

```
netsh trace start capture=yes tracefile=%temp%\trace.etl maxsize=10
```

A `pktmon` (Packet Monitor) a Microsoft saját, in-box hálózati diagnosztikai eszköze — a Microsoft dokumentációja szerint a `pktmon.exe` paranccsal érhető el gyárilag (a `C:\Windows\System32\` alatt), és a képességei között szerepel a több ponton történő csomag-elkapás, a futásidejű szűrés, és a pcapng-export (vagyis a rögzített anyag közvetlenül Wiresharkban elemezhető):

```
pktmon start --etw -f %TEMP%\capture.etl
pktmon filter add -p 445
pktmon stop
pktmon format pktmon.etl
```

A `pktmon filter add -p 445` sor az, ami a szándékot leginkább elárulja: a támadó nem hálózati hibát keres, hanem célzottan az SMB-forgalmat szűri ki.

Ugyanezt az alatta lévő NDIS capture providert PowerShellből is lehet vezérelni, telepítés és külön bináris nélkül:

```powershell
New-NetEventSession -Name Capture007 -LocalFilePath "$ENV:Temp\sniff.etl"
Add-NetEventPacketCaptureProvider -SessionName Capture007 -TruncationLength 100
Start-NetEventSession -Name Capture007
```

**Mi váltja ki a gyakorlatban:** ez az a technika, ahol a jóindulatú kiváltó ok nem marginális, hanem domináns. Egy hálózati mérnök vagy helpdesk-munkatárs, aki VPN- vagy kapcsolódási hibát vizsgál, pontosan ugyanezeket futtatja — a `pktmon`-t maga a Microsoft dokumentálja diagnosztikai eszközként, a Wiresharkot pedig a szakma alapszerszámaként. Ez az egyetlen ok, amiért a technika detekciója nem lehet `critical` szintű: a telemetria a legitim és a rosszindulatú használat között **bájtra azonos**, a különbség kizárólag a kontextusban van (ki futtatta, milyen gépen, volt-e hozzá jegy).

## Mitigáció

A MITRE négy mitigációja itt **feltűnően más szerepet játszik, mint a repo többi technikájánál**: egyik sem a capture-t akadályozza meg, hanem mindegyik annak az *értékét* csökkenti. Ez közvetlenül meghatározza, mit jelent egy találat:

- **Forgalom titkosítása (M1041).** Ez az egyetlen kontroll, ami a technika Credential Access-oldali nyereségét valóban megszünteti: titkosított csatornán a lehallgatás nem ad cleartext jelszót. **De a Discovery-oldali nyereséget nem szünteti meg** — a forgalom metaadata (ki beszél kivel, milyen porton, mennyit) titkosítás mellett is látható. Vagyis a szabály teljesen titkosított környezetben is releváns marad, csak a súlya csökken.
- **Többfaktoros hitelesítés (M1032).** Ugyanez a logika egy szinttel tovább: ha a lehallgatott hitelesítő adat önmagában nem elég a bejelentkezéshez, a capture nyeresége elértéktelenedik. Szintén nem a technikát állítja meg, hanem a következő lépést.
- **Hálózati szegmentáció (M1030).** A MITRE megfogalmazása itt explicit: *"Deny direct access of broadcasts and multicast sniffing, and prevent attacks such as Name Resolution Poisoning and SMB Relay."* Ez a legfontosabb mitigációs sor ezen a jegyzeten, mert megmutatja a technika valódi szerkezeti korlátját: kapcsolt hálózaton a sniffing a broadcast/multicast forgalomra és a saját gép forgalmára szorítkozik — ezért kell a támadónak [[T1557.001 - LLMNR-NBT-NS Poisoning and SMB Relay]]-szerű pozíció-technika ahhoz, hogy legyen mit lehallgatni. Egy jól szegmentált, LLMNR/NBT-NS-mentes hálózatban egy `pktmon` futás sokkal kevesebbet ér — de a futás maga ugyanúgy megtörténik és ugyanúgy naplózódik.
- **Nincs olyan kontroll, ami a capture *elindítását* megakadályozná** — a `pktmon` és a `netsh` a Windows saját része, nem lehet "eltávolítani". Alkalmazás-kontrollal (AppLocker/WDAC) a harmadik féltől származó sniffereket ki lehet zárni, a beépítetteket gyakorlatilag nem. **Ez indokolja, hogy miért kell egyáltalán detekciós szabály erre a technikára:** a megelőzés itt nem alternatíva, csak a hatás-csökkentés.

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés |
| ---------- | ----- | ---------- |
| Sysmon EID 1 (ProcessCreate) | Process | `Image`, `OriginalFileName`, `CommandLine` — a capture eszköz vagy a beépített utility elindulása. **A repo egyetlen adatforrása erre a technikára** (DETECT-2026-0044) |
| Sysmon EID 6 (DriverLoad) | Driver | A Npcap/WinPcap driver (`npcap.sys`, `npf.sys`) betöltése — ez a Wireshark-család *előfeltétele*, és átnevezés-független jel. **Ebben a repóban nincs egyetlen `driver_load` kategóriájú logsource sem**, tehát ez nevesített lefedettségi hiány, nem elnézés |
| NIC promiszkuus-mód váltás | Host / Network config | A MITRE saját analitikája (AN0875) ezt nevezi meg jelként. Nincs olyan telemetria ebben a pipeline-ban, ami ezt hordozná |
| Hálózati eszköz konfigurációs log | Network | Port mirroring / SPAN session létrehozása a switchen — a *nagy hatókörű* sniffing tulajdonképpeni engedélyezése. Nincs betöltve |
| Cloud audit log | Cloud | Traffic mirror / vTAP session létrehozása (AWS VPC Traffic Mirroring, Azure vTAP). Hatókörön kívül |

### Detekciós logika

A kiindulópont: **a lehallgatást magát nem lehet látni.** A promiszkuus olvasás passzív művelet, nem generál folyamat-, fájl- vagy registry-eseményt. Amit detektálni lehet, az kizárólag az **eszköz elindítása** — tehát a technika előkészítése, nem a végrehajtása. Ez a szabály legfontosabb szerkezeti korlátja, és nem hangolással javítható.

- **Négy, egymástól független ág, mert négy különböző mechanizmus.** (1) A harmadik féltől származó snifferek `Image`/`OriginalFileName` páron — az `OriginalFileName` azért kell, mert egy átnevezett `tshark.exe` az `Image`-en elbújik. (2) A `pktmon` ugyanígy, párban. (3) A `netsh trace` **nem elég a bináris nevéből**: a `netsh.exe` teljesen hétköznapi eszköz, ezért itt a parancssornak *együtt* kell tartalmaznia a `trace`, `start` és `capture=yes` részt — ez a `capture=yes` az, ami a puszta nyomkövetést tényleges csomagrögzítéstől elválasztja. (4) A PowerShell NetEventSession-ág parancssori cmdlet-nevekre illeszt, mert itt nincs saját bináris, amit azonosítani lehetne.
- **Miért `medium` és nem `critical`.** A négy ág FP-profilja nem egyforma, de a szabály szintjét a legzajosabb ág határozza meg: a `pktmon`-t és a Wiresharkot valóban futtatják hálózati hibakeresés közben. Ezért a helyes triage-szabály nem a szabály szintjéből, hanem az *eszköz identitásából* következik: egy `RawCap.exe`-találat érdemben gyanúsabb, mint egy `Wireshark.exe`-találat, mert a RawCap-nek nincs legitim vállalati használata — ugyanabban a szabályban, ugyanazon a szinten.
- **Amit tudatosan nem fed le ez a megközelítés:** a capture driver telepítését (EID 6 kellene), a NIC promiszkuus-módba állítását, és a nem-folyamat-alapú capture-t. Az utóbbi a legfontosabb rés: ha a támadó nem elindít egy eszközt, hanem a saját implantjében nyit raw socketet, folyamatindítás-esemény nem keletkezik róla. Ugyanez a szerkezeti probléma, mint [TA0002 - Execution]-nél a T1106 (Native API) esetén.

### False positive források

- **Hálózati mérnök és helpdesk hibakeresése — ez a domináns FP-forrás,** és nem periferikus: `netsh trace`, `pktmon`, Wireshark/`tshark` mind dokumentált diagnosztikai eszköz, a `pktmon`-t a Microsoft maga ajánlja hálózati problémákhoz. Nem szűrhető detekciós időben, mert egy legitim futás telemetriája azonos a rosszindulatúval; a triage-nek a változáskezelési/jegyrendszer felé kell keresztellenőriznie.
- **Eszköz-szintű súlyozás a szabályon belül.** A `RawCap` (hordozható, telepítést nem igénylő sniffer) gyakorlatilag nem fordul elő legitim adminisztratív használatban — egy ilyen találatot érdemesebb gyanúsnak venni, mint a többi ágat.
- **A PowerShell NetEventSession-ág** valódi szkriptelt diagnosztikai használattal is rendelkezik, csak gyakorlatilag ritkábban, mint a GUI/CLI eszközök.
- **Amit *nem* kell FP-ként kezelni:** a `capture=yes` nélküli `netsh trace` futásokat — a szabály ezeket nem is fogja meg, épp azért, mert azok nyomkövetés, nem csomagrögzítés.

## Kapcsolódó szabályok

| detect_id | Szabály | Telemetria | Szint | Miért szükséges |
| --------- | ------- | ---------- | ----- | --------------- |
| [DETECT-2026-0044](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0044_Network-Sniffing-Tool-and-Windows-Native-Packet-Capture-Execution.yml) | Network Sniffing Tool and Windows Native Packet Capture Execution | Sysmon EID 1 (folyamatindítás): `Image`, `OriginalFileName`, `CommandLine` | medium | A Windows gyárilag tartalmaz teljes értékű csomagrögzítő képességet (`pktmon`, `netsh trace capture=yes`, NetEventSession), ezért helyi rendszergazdai joggal a támadónak semmit nem kell felmásolnia a gépre ahhoz, hogy a hálózati forgalmat olvassa — nincs telepítés, nincs új bináris, nincs driver, amit egy alkalmazás-kontroll megfoghatna. Ezzel titkosítás nélküli protokollokból hitelesítő adatot, a broadcast-forgalomból pedig a szegmens topológiáját nyerheti ki. |

Ez a szabály `stable` státuszú, és **a repo egyetlen szabálya erre a technikára**. A technika lefedettsége azért csak "részleges", mert a szabály a capture *elindítását* látja, nem a lehallgatást: a driver-betöltés (Sysmon EID 6) és a promiszkuus-mód-váltás telemetriája hiányzik, és ezek pótolnák azt az ágat, ahol a támadó nem egy ismert eszközt indít el. Előzmény: a technika korábban a `TA0006` jegyzetben egy azóta törölt szabályra (DETECT-2026-0035) hivatkozott; ténylegesen ez a 2026-09-26-i szabály az első, ami erre a technikára elkészült.

## Kapcsolódó jegyzetek

- **Rokon technikák:** [[T1557 - Adversary-in-the-Middle]] — a szükséges *pozíció*-technika: kapcsolt hálózaton a sniffing önmagában alig látja a forgalmat, az AiTM az, ami odairányítja; a kettő a gyakorlatban szinte mindig együtt jelenik meg, és a `.001` eszközei (Responder/Inveigh) egyszerre poisonolnak és rögzítenek. [[T1003 - OS Credential Dumping]] — alternatíva ugyanarra a célra (hitelesítő adat), végponti memória-/fájlolvasással a hálózati pozíció helyett; ha van rendszergazdai jog (és a sniffinghez is kell), a dumping jellemzően közvetlenebb út. [[T1595 - Active Scanning]] — a Discovery-oldali kontraszt: ott a támadó *kérdez* és ezzel forgalmat generál, itt csak hallgat, és ezért hálózati oldalon láthatatlan
- **MITRE:** https://attack.mitre.org/techniques/T1040/

## Saját feljegyzések

