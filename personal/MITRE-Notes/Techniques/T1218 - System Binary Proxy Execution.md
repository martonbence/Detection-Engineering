---
mitre_id: T1218
mitre_type: technique
name: System Binary Proxy Execution
aliases:
  - T1218
  - System Binary Proxy Execution
url: https://attack.mitre.org/techniques/T1218/
tactic:
  - "[[TA0005 - Stealth]]"
subtechnique_count: 14
platforms:
  - Windows
de_priority: kritikus
coverage: részleges
status: kész
---
# T1218 — System Binary Proxy Execution

## Lényeg

A támadó egy natív, Microsoft által aláírt Windows-binárist (LOLBin) használ arra, hogy egy megbízhatónak minősített, gyakran allowlistelt program képében futtasson tetszőleges kódot. A 14 altechnika mindegyike egy konkrét, jól ismert bináris (rundll32, mshta, regsvr32, msiexec, cmstp stb.) visszaélésszerű felhasználását fedi — a közös nevező, hogy a bináris maga sosem gyanús (aláírt, rendszerkomponens), csak a *paraméterezése* (melyik DLL-t, HTA-t, szkriptet tölti be) árulja el a rosszindulatú szándékot.

Ez teszi a technikát az alkalmazás-allowlisting (AppLocker/WDAC) egyik leggyakoribb megkerülési útjává: az allowlist a binárisra épül, nem arra, hogy *mit* hívat vele a támadó.

> [!quote] MITRE definíció
> Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries.

## Altechnikák

- **[[T1218.011 - Rundll32]]** — DLL-export proxyzása (`rundll32.exe payload.dll,Export`); **lefedve, 1 szabály** (kizárólag a `comsvcs.dll` MiniDump LSASS-dump forgatókönyv)
- .001 Compiled HTML File (`.chm`) — kompilált HTML súgófájlba ágyazott szkript futtatása `hh.exe`-vel
- .002 Control Panel (`.cpl`) — rosszindulatú Control Panel item betöltése
- .003 CMSTP — a Microsoft Connection Manager Profile Installer visszaélésszerű felhasználása UAC-bypasshoz és szkript-futtatáshoz
- .004 InstallUtil — .NET `InstallUtil.exe`, ami tetszőleges assembly-t futtathat telepítési logika ürügyén
- .005 Mshta — HTA-fájlok natív futtatása, gyakori [[T1566.001 - Spearphishing Attachment]]-folytatás
- .007 Msiexec — `.msi` csomagba ágyazott rosszindulatú telepítő-logika futtatása
- .008 Odbcconf — ODBC-driver konfigurációs eszköz visszaélésszerű DLL-betöltésre
- .009 Regsvcs/Regasm — .NET COM-regisztrációs eszközök visszaélésszerű assembly-futtatásra
- .010 Regsvr32 — a klasszikus "Squiblydoo" minta, távoli szkript regisztrálása COM-objektumként
- .012 Verclsid — CLSID-ellenőrző bináris visszaélésszerű felhasználása
- .013 Mavinject — folyamat-injektálás egy natív, aláírt Windows-eszközzel
- .014 MMC — Microsoft Management Console snap-in-ek visszaélésszerű betöltése
- .015 Electron Applications — Electron-alapú alkalmazások (natívan aláírt, elterjedt desktop-keretrendszer) beépített szkript-futtatási módjának kihasználása

## Mitigáció

- **AppLocker/WDAC szabály, ami az egyes LOLBin-eket konkrét, allowlistelt paraméterekre/DLL-ekre korlátozza** — ez veszi célba a proxy-jelleget magát, nem egy konkrét payloadot; enélkül a bináris aláírt volta önmagában semmit nem árul el a mögötte futó kódról.
- **LSA Protection (RunAsPPL)** a .011-nél a konkrét `comsvcs.dll` MiniDump-forgatókönyv előfeltételét szünteti meg, de nem a technika egészéét.
- **Attack Surface Reduction szabályok (Defender ASR)** több konkrét altechnikára (pl. Office-eredetű `mshta`/`regsvr32`-hívás blokkolása) célzott, kész mitigációt adnak — ezek nincsenek dokumentálva ebben a repóban, mint bekötött kontroll.

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés | Érintett altechnika |
| ---------- | ----- | ---------- | -------------------- |
| Sysmon EID 1 (ProcessCreate) | Process | `Image`/`OriginalFileName` + `CommandLine` — a jelenlegi szabály és minden potenciális jövőbeli LOLBin-szabály erre épülne | .011 |

### Detekciós lehetőség

A repó lefedettsége egyetlen, nagyon szűk forgatókönyvre korlátozódik: a `comsvcs.dll` MiniDump exportjának LSASS-dumpra használt hívása (lásd [[T1218.011 - Rundll32]] "Nem fedett" szakaszát az ordinálalapú `#24`-megkerülésről). A `rundll32.exe` bármely *más* DLL+export kombinációja, és a technika másik 13 altechnikája (mshta, regsvr32, cmstp, msiexec stb.) **teljesen fedetlen** — ezek mindegyike ugyanazon az adatforráson (Sysmon EID 1, `Image`+`CommandLine`) épülhetne, tehát strukturális akadály nincs, csak a szabályok hiányoznak. A `.005 Mshta` lenne a legnagyobb gyakorlati következő lépés, mert közvetlenül összefügg a már lefedett [[T1566.001 - Spearphishing Attachment]] láncával.

## Kapcsolódó szabályok

| detect_id | Altechnika | Miért szükséges |
| --------- | ---------- | --------------- |
| [DETECT-2026-0020](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0020_LSASS-Dump-via-comsvcs-MiniDump.yml) (lásd [[T1218.011 - Rundll32]]) | .011 | `comsvcs.dll` MiniDump exportjának névvel történő meghívása LSASS PID-re |

**Nem fedett:** .001–.010, .012–.015 — a technika 13 másik altechnikája, plusz a `rundll32.exe` minden más DLL+export kombinációja a .011-en belül.

## Kapcsolódó jegyzetek

- **Rokon technikák:** [[T1003.001 - LSASS Memory]] — a jelenleg lefedett rundll32-forgatókönyv célja és technikai háttere; [[T1566 - Phishing]] — a `.005 Mshta` a leggyakoribb végrehajtási lánc-folytatás egy rosszindulatú melléklet után
- **MITRE:** https://attack.mitre.org/techniques/T1218/

## Saját feljegyzések
