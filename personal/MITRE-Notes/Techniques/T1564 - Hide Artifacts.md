---
mitre_id: T1564
mitre_type: technique
name: Hide Artifacts
aliases:
  - T1564
  - Hide Artifacts
url: https://attack.mitre.org/techniques/T1564/
tactic:
  - "[[TA0005 - Stealth]]"
subtechnique_count: 14
platforms:
  - Windows
  - Linux
  - macOS
de_priority: közepes
coverage: részleges
status: kész
---
# T1564 — Hide Artifacts

## Lényeg

A támadó a tevékenységéhez tartozó valamilyen artifactot (fájl, felhasználó, ablak, folyamat, e-mail szabály) úgy hoz létre vagy módosít, hogy az a normál felhasználói/adminisztrátori felületen ne legyen látható — nem *törli* a nyomot, hanem elrejti azt a szokásos megfigyelési útból. A 14 altechnika nagyon különböző rétegeket fed: fájlrendszer-szintű rejtés (rejtett fájlok/attribútumok), folyamat-szintű rejtés (rejtett ablak, virtuális instance), fiók-szintű rejtés (rejtett felhasználó), és alkalmazás-szintű rejtés (e-mail szabály, VBA stomping).

A közös motívum: a rejtés önmagában ritkán elég erős jel — legtöbbször *más*, egyidejűleg jelenlévő gyanús mintával együtt válik érdemi detekciós ponttá (pl. rejtett ablak + kódolt parancs), mert minden altechnikának van bőséges legitim, jóindulatú használati módja is.

> [!quote] MITRE definíció
> Adversaries may attempt to make an artifact or behavior related to their activity difficult to detect in order to evade defenses. This encompasses many different techniques to hide artifacts including manipulating file metadata, hiding entire file systems, or specific portions of files or information.

## Altechnikák

- **[[T1564.003 - Hidden Window]]** — folyamat indítása látható ablak nélkül (`-WindowStyle Hidden`); **lefedve, 1 szabály** (flag-kombináció küszöbölés)
- .001 Hidden Files and Directories — fájl/könyvtár rejtett attribútummal vagy pont-prefixszel (Unix `.dotfile`); nincs lefedve
- .002 Hidden Users — operációs rendszer szintjén rejtett/elrejtett felhasználói fiók létrehozása; nincs lefedve
- .004 NTFS File Attributes — payload elrejtése egy NTFS Alternate Data Stream-ben; nincs lefedve
- .005 Hidden File System — teljes rejtett fájlrendszer/partíció létrehozása; nincs lefedve
- .006 Run Virtual Instance — a rosszindulatú tevékenység egy virtuális gépen/konténeren belül fut, a hoszt EDR-je elől elrejtve
- .007 VBA Stomping — egy Office-makró p-code (fordított) formája marad meg, a látható VBA-forráskód ártalmatlanra cserélve
- .008 Email Hiding Rules — postafiók-szabály, ami a bejövő figyelmeztető/válasz e-maileket automatikusan törli/archiválja (jellemzően BEC-lánc része)
- .009 Resource Forking — payload elrejtése egy macOS resource fork attribútumban
- .010 Process Argument Spoofing — a folyamat parancssori argumentumainak futásidejű meghamisítása a monitoring-eszközök felé
- .011 Ignore Process Interrupts — a folyamat úgy indul, hogy figyelmen kívül hagyja a megszakítási jeleket (pl. terminál bezárása), rejtve tartva magát
- .012 File/Path Exclusions — a biztonsági eszköz saját kizárási listájának (allowlist) visszaélésszerű bővítése
- .013 Bind Mounts — Linux bind mount trükk, ami egy fájlrendszer-útvonalat egy másikra képez le, elrejtve az eredeti tartalmat
- .014 Extended Attributes — payload elrejtése fájlrendszer-szintű kiterjesztett attribútumban (xattr)

## Mitigáció

- A MITRE ehhez a technikához nem sorol egységes, minden altechnikára ható kontrollt — az operációs rendszer/alkalmazás legitim funkcióit használja.
- **Application allowlisting (AppLocker/WDAC)** közvetve segít a .003/.007-nél: ha csak aláírt, ismert tartalom futhat, a rejtett ablakú/stompolt makrós tartalom köre szűkül.
- **Rendszeres audit a fájlrendszer rejtett attribútumaira, ADS-ekre és a felhasználói fiókok listájára** (.001, .002, .004) csökkenti a felfedezetlen idő hosszát, de nem előzi meg a létrehozást.
- A gyakorlatban ez a technika tisztán **detekció-fókuszú** a legtöbb altechnikánál — a védelem súlypontja a rejtés *kombinációján* van más gyanús jellel, nem magának a funkciónak a letiltásán.

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés | Érintett altechnika |
| ---------- | ----- | ---------- | -------------------- |
| Sysmon EID 1 (ProcessCreate) | Process | `CommandLine` — a jelenlegi egyetlen szabály erre épül | .003 |
| Sysmon EID 15 (FileCreateStreamHash) | File | ADS-létrehozás — nincs bekötve | .004 |
| Windows Security 4720/4722 (fiók létrehozás/engedélyezés) | Account | rejtett/gyanús attribútumú fiók létrehozása — nincs bekötve | .002 |
| Exchange/O365 szabály-audit log | Application | postafiók-szabály létrehozása — nincs ebben a pipeline-ban | .008 |

### Detekciós lehetőség

A repó lefedettsége egyetlen altechnikára (.003 Hidden Window) korlátozódik, és ott is tudatosan **kombinációs küszöbre** épül, nem önálló flagre (lásd [[T1564.003 - Hidden Window]]) — ez a legreálisabb megközelítés, mert egyetlen rejtett-ablak flag túl gyakori legitim automatizálásban. A többi 13 altechnika teljesen fedetlen; ezek közül a .001 (Hidden Files/Directories) és a .004 (NTFS ADS) lennének a legkönnyebben hozzáférhető következő lépések Sysmon EID 11/15 alapon, míg a .002, .008 natív Windows Security/alkalmazás-audit adatforrást igényelne, ami jelenleg nincs bekötve.

## Kapcsolódó szabályok

| detect_id | Altechnika | Miért szükséges |
| --------- | ---------- | --------------- |
| [DETECT-2026-0014](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0014_PowerShell-Stealth-Execution-Flags.yml) (lásd [[T1564.003 - Hidden Window]]) | .003 | ≥2 elrejtő flag-csoport kombinációja a `CommandLine`-ban |

**Nem fedett:** .001, .002, .004–.014 — a technika 13 másik altechnikája.

## Kapcsolódó jegyzetek

- **Rokon technikák:** [[T1059 - Command and Scripting Interpreter]] — a Hidden Window szinte mindig egy T1059.001 PowerShell-munkameneten belül jelenik meg, más gyanús mintával (kódolás, letöltés) kombinálva
- **MITRE:** https://attack.mitre.org/techniques/T1564/

## Saját feljegyzések
