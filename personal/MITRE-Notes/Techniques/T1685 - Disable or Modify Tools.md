---
mitre_id: T1685
mitre_type: technique
name: Disable or Modify Tools
aliases:
  - T1685
  - Disable or Modify Tools
url: https://attack.mitre.org/techniques/T1685/
tactic:
  - "[[TA0112 - Defense Impairment]]"
subtechnique_count: 6
platforms:
  - Windows
  - Linux
  - macOS
  - Cloud
de_priority: magas
coverage: részleges
status: kész
---
# T1685 — Disable or Modify Tools

> [!note] Ez egy renumbering-eredmény, nem egy megszokott technika
> `T1685` a repó saját, 2026-09-26-án frissített ATT&CK-cache-ében **önálló tactic** (**Defense Impairment**, azonosítója a jelenlegi ismeretek szerint **TA0112** — ezt élő ATT&CK-oldal-lekérdezésből kaptam, de a repó saját forrásában (`scripts/validate/check_mitre_tags.py`) nincs numerikus TA-azonosító hozzá rögzítve, csak a név; érdemes ezt egy következő cache-frissítéskor megerősíteni). Ez **nem ugyanaz**, mint a többi Stealth-altechnika (T1027, T1564, T1218) tactic-ja — a régi, egységes "Defense Evasion" tactic itt ténylegesen **két külön tactic-ra vált szét**: a általános elrejtés/evázió maradt Stealth (TA0005) néven, a *védelmi mechanizmusok célzott hatástalanítása* pedig átkerült egy új, dedikált tactic-ba. Ez a `docs/credential-access-buildout.md`-ban már korábban is jelzett "T1562→T1685" renumbering folytatása — a régi T1562 Impair Defenses és T1070 Indicator Removal egyes altechnikái olvadtak össze ebben az új technikában.

## Lényeg

A támadó közvetlenül manipulálja azokat a védelmi/naplózási mechanizmusokat, amik egyébként a tevékenységét rögzítenék vagy megakadályoznák — a Windows Event Log szolgáltatást, egy biztonsági eszköz felhasználói felületét/riasztását, egy cloud-naplózási funkciót, vagy a Linux `auditd`-t. A közös nevező nem egy konkrét mechanizmus, hanem a **szándék**: a védelem *tudatos* hatástalanítása, még mielőtt vagy miközben a tényleges rosszindulatú tevékenység lezajlana.

Ez a technika két, egymással ellentétes időbeli irányban valósulhat meg: vagy **megelőzi** az esemény keletkezését (.001, .002, .004 — a naplózás/eszköz letiltása előre), vagy **eltünteti** a már keletkezett bejegyzést utólag (.005, .006 — törlés). A kettő anti-forensics szempontból nem egyenértékű: egy hirtelen üres napló azonnal gyanút kelt, míg a megelőző letiltás simán belesimul abba, hogy "erről sosem is keletkezett bejegyzés".

> [!quote] MITRE definíció
> Adversaries may disable or modify tools used for detection or logging in order to limit what forensic evidence is collected during an operation.

## Altechnikák

- **[[T1685.001 - Disable or Modify Windows Event Log]]** — a Windows eseménynapló-mechanizmus (vagy egy alkalmazás, pl. PowerShell saját naplózásának) megelőző letiltása; **lefedve, 1 szabály** (DETECT-2026-0016)
- **[[T1685.005 - Clear Windows Event Logs]]** — már keletkezett bejegyzések utólagos törlése (`wevtutil cl`, `Clear-EventLog`); **nincs lefedve** — a korábban ide tagelt DETECT-2026-0016 tagja 2026-09-27-én eltávolításra került, miután megerősítést nyert, hogy a szabály valójában az .001-et fedi
- .002 Disable or Modify Cloud Log — cloud-natív naplózási funkció (pl. CloudTrail) kikapcsolása/manipulálása; nincs lefedve, nincs cloud-telemetria ebben a pipeline-ban
- .003 Modify or Spoof Tool UI — egy biztonsági eszköz felhasználói felületének/riasztásának meghamisítása, hogy a defender valós státuszt lásson, miközben a valóság más; nincs lefedve
- .004 Disable or Modify Linux Audit System Log — a Linux `auditd` letiltása/manipulálása; nincs lefedve (a repó Linux-endpoint rules-ait 2026-09-20-án eltávolították)
- .006 Clear Linux or Mac System Logs — Unix-oldali naplótörlés; nincs lefedve

## Mitigáció

- **Jogosultság-korlátozás** a naplózási/biztonsági konfigurációra (csak SYSTEM/domain admin írhatja) — nem szünteti meg az előfeltételt admin-szintű kompromittálásnál, de emeli a küszöböt.
- **Naplók valós idejű, távoli továbbítása** (Windows Event Forwarding, vagy — mint ebben a pipeline-ban — Splunk Universal Forwarder) az egyetlen kontroll, ami *mindkét irányban* (megelőzés és törlés) hatásos: ha az esemény a manipuláció pillanatában már elhagyta a hosztot, a helyi beavatkozás a bizonyítékot csak lokálisan tünteti el.
- Egyik kontroll sem akadályozza meg magát a kísérletet admin-jogosultsággal — a védelem súlypontja a *detekción* és a *log-forwarding időzítésén* van, nem a megelőzésen.

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés | Érintett altechnika |
| ---------- | ----- | ---------- | -------------------- |
| Sysmon EID 1 (ProcessCreate) | Process | `CommandLine` — a jelenlegi két szabály erre épül | .001 |
| Windows Security 1102 / System 104 | Log | a törlés natív, közvetlen jele — **nincs feldolgozva** | .005 |
| Cloud audit log (CloudTrail stb.) | Cloud | — nincs ebben a pipeline-ban | .002 |
| Linux `auditd` saját logja | Log | — nincs ebben a pipeline-ban | .004 |

### Detekciós lehetőség

**Tagelési pontatlanság, javítva 2026-09-27-én, Bjorn megerősítésével:** két szabály fedte korábban helytelenül ezt a technikát. A DETECT-2026-0016 (Logging Disable) `t1685.005`-re (Clear Windows Event Logs) volt tagelve, miközben tartalmilag a `ScriptBlockLogging`/`ModuleLogging` policy-kulcsok *jövőbeli* naplózást megelőző manipulálására illeszkedik, nem a *már meglévő* bejegyzések törlésére — a `.005` tag eltávolításra került, megmaradt a helyes `.001`. A tényleges `wevtutil cl`/`Clear-EventLog` minta (.005 valódi jele) **továbbra sincs lefedve egyik szabályban sem** — lásd [[T1685.005 - Clear Windows Event Logs]] "Detekciós logika" szakaszát.

A DETECT-2026-0012 (AMSI Bypass) `t1685.001`-tagelését is felülvizsgálta Bjorn — a felmerült `.003 Modify or Spoof Tool UI` alternatívát kifejezetten megvizsgálta és **elvetette**: a `.003` MITRE-definíciója egy biztonsági eszköz *felhasználói felületének/riasztásának* meghamisítása (pl. hamis "minden rendben" dashboard), nem egy scan-függvény memóriában történő patchelése — ez nem ugyanaz, mint az AMSI-bypass. Mivel az AMSI-patchelés MITRE saját procedure-példái (Turla, SILENTTRINITY, Donut) is a **szülő T1685 technika alatt**, nem semelyik altechnika alatt szerepelnek, a végleges tag a bare **`attack.t1685`** lett (subtechnika-jelölés nélkül) — ez a repó saját, más szabályoknál is használt konvenciójával (`attack.t1040`, `attack.t1105`, `attack.t1190`) egyezik. Emiatt a DETECT-2026-0012 **nem** ennek az altechnikának (.001) a lefedettsége — lásd a lenti táblázatot.

## Kapcsolódó szabályok

| detect_id | Szabály | Tag | Miért vitatható |
| --------- | ------- | --- | --------------- |
| [DETECT-2026-0012](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0012_PowerShell-AMSI-Bypass.yml) | PowerShell AMSI Bypass | `attack.t1685` (bare, javítva 2026-09-27, volt: `.001`) | Egyik altechnikába sem illik pontosan — a technika szintjén marad |
| [DETECT-2026-0016](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0016_PowerShell-Logging-Disable.yml) | PowerShell Script Block or Module Logging Disable | `attack.t1685.001` (javítva 2026-09-27, `.005` eltávolítva) | Helyes — megelőző letiltás |

**Nem fedett ténylegesen:** .002 Disable or Modify Cloud Log, .003 Modify or Spoof Tool UI (a jelenlegi AMSI-szabály sem ide illik, lásd fent), .004 Disable or Modify Linux Audit System Log, .006 Clear Linux or Mac System Logs, és a valódi .005 minta (`wevtutil cl`/`Clear-EventLog`).

## Kapcsolódó jegyzetek

- **Rokon technikák:** [[T1027 - Obfuscated Files or Information]] — az AMSI-bypass gyakran ugyanabban a munkamenetben jelenik meg, mint a Command Obfuscation minták; [[T1059 - Command and Scripting Interpreter]] — mindkét jelenlegi szabály PowerShell `CommandLine`-ra épül
- **MITRE:** https://attack.mitre.org/techniques/T1685/

## Saját feljegyzések
