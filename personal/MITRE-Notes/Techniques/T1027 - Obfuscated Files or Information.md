---
mitre_id: T1027
mitre_type: technique
name: Obfuscated Files or Information
aliases:
  - T1027
  - Obfuscated Files or Information
url: https://attack.mitre.org/techniques/T1027/
tactic:
  - "[[TA0005 - Stealth]]"
subtechnique_count: 18
platforms:
  - Windows
  - Linux
  - macOS
de_priority: magas
coverage: részleges
status: kész
---
# T1027 — Obfuscated Files or Information

> [!note] Tactic-átnevezés
> Ez a technika a repó saját, cache-ből származó ATT&CK-taxonómiájában a **Stealth** (TA0005) tactic alá tartozik — ez ugyanaz a TA0005 azonosító, amit upstream még "Defense Evasion" néven ismer, csak átnevezve. Lásd `scripts/validate/check_mitre_tags.py` és a `mitre-attack-mapping` skill: `attack.stealth` érvényes tag ebben a repóban.

## Lényeg

A támadó kódolással, tömörítéssel, karakter-behelyettesítéssel vagy szintaktikai trükkökkel elrejti egy fájl vagy parancs valódi tartalmát/szándékát a statikus, kulcsszó- vagy szignatúra-alapú detekció elől — miközben a végrehajtási rétegen (interpreter, loader) a tartalom pontosan ugyanazt csinálja, mintha nyílt szöveggel/formában lenne jelen. A technika 18 altechnikája nagyon eltérő rétegeket fed le: van, ami a *parancssorra* (Command Obfuscation), van, ami a *fájl bájtjaira* (Binary Padding, Steganography), és van, ami a *futásidejű kódfelbontásra* (Dynamic API Resolution, Polymorphic Code) épül.

Ez a legolcsóbb és leggyakoribb evázió-forma, mert nem igényel új exploitot vagy binárist — az interpreter/loader *már meglévő*, legitim képességeit (Base64-dekódolás, string-konkatenáció, tömörítés) fordítja a statikus szabályok megkerülésére.

> [!quote] MITRE definíció
> Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its content on the system or in transit.

## Altechnikák

- **[[T1027.010 - Command Obfuscation]]** — parancssori szintű kódolás/tömörítés + azonnali kiértékelés; **lefedve, 3 szabály** (PowerShell-specifikus)
- .001 Binary Padding — a fájl méretének mesterséges növelése, hogy AV-motor méret-küszöböt/hash-egyezést kerüljön
- .002 Software Packing — futásidejű csomagoló/unpacker (UPX és egyedi packerek), ami a valódi kódot csak memóriában bontja ki
- .003 Steganography — payload elrejtése egy ártalmatlannak tűnő médiafájlban (kép, audio)
- .004 Compile After Delivery — forráskód/köztes reprezentáció szállítása, célgépen fordítva, hogy a lemezen soha ne legyen jelen kész bináris
- .005 Indicator Removal from Tools — az eszköz saját, ismert szignatúráinak eltávolítása újrafordítás előtt
- .006 HTML Smuggling — payload beágyazása egy HTML-fájl JavaScriptjébe, kliensoldalon összeállítva, elkerülve a hálózati proxy tartalom-szűrését
- .007 Dynamic API Resolution — Win32 API-hívások futásidejű feloldása (nem statikus import-táblából), hogy a statikus elemzés ne lássa a hívott függvényeket
- .008 Stripped Payloads — szimbólum-/metaadat-eltávolítás a bináris elemzésének megnehezítésére
- .009 Embedded Payloads — a tényleges payload egy másik, ártalmatlannak tűnő fájlformátumba ágyazva (pl. kép fájlvégéhez fűzve)
- .011 Fileless Storage — payload tárolása lemez helyett registry-ben/WMI-ben/memóriában
- .012 LNK Icon Smuggling — payload elrejtése egy `.lnk` fájl ikon-erőforrásában
- .013 Encrypted/Encoded File — a teljes fájl titkosítva/kódolva, futásidőben visszafejtve
- .014 Polymorphic Code — önmódosító kód, ami minden futtatáskor más bájtmintát ad, szignatúra-egyezés ellen
- .015 Compression — önálló tömörítés, kódolás nélkül
- .016 Junk Code Insertion — értelmetlen, funkció nélküli kódrészletek beszúrása a minta megzavarására
- .017 SVG Smuggling — payload beágyazása egy SVG-fájl szkript-képes elemeibe
- .018 Invisible Unicode — láthatatlan/homoglif Unicode-karakterek a szöveges egyezés megzavarására

## Mitigáció

- A MITRE ehhez a technikához nem sorol egységes, minden altechnikára ható megelőző kontrollt — az obfuszkáció az interpreter/fájlformátum legitim képességeit használja.
- **AMSI** a legerősebb, ténylegesen alkalmazható védelem a PowerShell-oldali altechnikákra (.010, részben .013), mert a *deobfuszkált* tartalmat vizsgálja végrehajtás előtt — ez az egyetlen kontroll, ami a kódolás rétegétől függetlenül működik, amíg maga az AMSI nincs megkerülve (lásd [[T1685.001 - Disable or Modify Windows Event Log]]).
- **Statikus + dinamikus (sandbox-alapú) elemzés kombinációja** csökkenti a csomagolás/steganográfia/polimorf kód hatását, mert a futásidejű viselkedést nézi, nem a fájl bájtmintáját.

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés | Érintett altechnika |
| ---------- | ----- | ---------- | -------------------- |
| Sysmon EID 1 (ProcessCreate) | Process | `CommandLine` — az egyetlen jelenleg lefedett altechnika (.010) erre épül | .010 |
| Fájl-alapú AV/EDR statikus scan | File | csomagolt/steganografált/polimorf bináris felismerése — nincs ebben a pipeline-ban | .001–.003, .008, .013, .014 |

### Detekciós lehetőség

A repó lefedettsége kizárólag a **parancssori** altechnikára (.010 Command Obfuscation) korlátozódik, és azon belül is csak a PowerShell-specifikus formákra (lásd [[T1027.010 - Command Obfuscation]] "Nem fedett" szakaszát: `cmd.exe`-alapú obfuszkáció és a Linux/macOS oldal kívül esik). A többi 17 altechnika — ami jellemzően fájl-alapú (csomagolás, steganográfia, polimorf kód) — strukturálisan kívül esik azon, amit egy Sysmon `ProcessCreate`-alapú pipeline egyáltalán megmutathatna; ehhez statikus/dinamikus fájl-elemzés (AV/EDR-szintű scan) kellene, ami nincs bekötve.

## Kapcsolódó szabályok

| detect_id | Altechnika | Miért szükséges |
| --------- | ---------- | --------------- |
| DETECT-2026-0007, 0009, 0011 (lásd [[T1027.010 - Command Obfuscation]]) | .010 | `-EncodedCommand`, inline Base64-dekódolás, tömörített payload — mind `IEX`-szel párosítva |

**Nem fedett:** .001–.009, .011–.018 — a technika 17 másik, jellemzően fájl-szintű altechnikája.

## Kapcsolódó jegyzetek

- **Rokon technikák:** [[T1059 - Command and Scripting Interpreter]] — a Command Obfuscation szinte mindig egy T1059.001 PowerShell-munkameneten belül jelenik meg; [[T1685 - Disable or Modify Tools]] — az AMSI-bypass ugyanabban a láncban, mert az obfuszkáció önmagában nem kerüli meg az AMSI-t
- **MITRE:** https://attack.mitre.org/techniques/T1027/

## Saját feljegyzések
