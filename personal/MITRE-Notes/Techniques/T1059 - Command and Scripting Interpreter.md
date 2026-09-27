---
mitre_id: T1059
mitre_type: technique
name: Command and Scripting Interpreter
aliases:
  - T1059
  - Command and Scripting Interpreter
url: https://attack.mitre.org/techniques/T1059/
tactic:
  - "[[TA0002 - Execution]]"
subtechnique_count: 13
platforms:
  - Windows
  - Linux
  - macOS
  - Network Devices
de_priority: kritikus
coverage: részleges
status: kész
---
# T1059 — Command and Scripting Interpreter

## Lényeg

A támadó egy már natívan telepített, aláírt szkript- vagy parancsértelmezőt (PowerShell, `cmd.exe`, bash, Python, JavaScript, egy hálózati eszköz saját CLI-je stb.) használ tetszőleges kód futtatására. A közös nevező nem egy konkrét platform, hanem a **motívum**: az interpreter már eleve jelen és megbízhatónak minősített minden célrendszeren, ezért a támadónak nem kell idegen binárist bevinnie — az operációs rendszer beépített képességeit fordítja a saját céljára.

Ez az egyik legszélesebb, leggyakrabban kihasznált execution-technika a teljes ATT&CK mátrixban, mert szinte minden post-exploitation keretrendszer (Cobalt Strike, Empire, Metasploit) végső soron egy ilyen interpretert hív meg a payload futtatásához — a különbség altechnikánként csak abban van, *melyik* nyelvet/motort célozza.

> [!quote] MITRE definíció
> Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms.

## Altechnikák

- **[[T1059.001 - PowerShell]]** — a legnépszerűbb Windows-forma, teljes .NET-hozzáféréssel; **lefedve, 12 szabály**
- **[[T1059.004 - Unix Shell]]** — bash/sh-alapú végrehajtás Linux/macOS/ESXi/hálózati eszközökön; **lefedve, 1 szabály** (webshell query stringen keresztüli közvetett jel, nem natív auditd)
- .002 AppleScript — macOS-natív szkriptnyelv, jellemzően perzisztencia/social-engineering láncokban (fals dialógusablakok); a repóban nincs macOS-lefedettség
- .003 Windows Command Shell (`cmd.exe`) — a PowerShell-nél egyszerűbb, régebbi parancsértelmező; gyakran LOLBin-láncok köztes lépése
- .005 Visual Basic (VBS/VBA) — Office-makrók és HTA-fájlok natív nyelve, tipikusan [[T1566.001 - Spearphishing Attachment]] folytatása
- .006 Python — egyre gyakoribb offenzív tooling nyelv (Impacket, egyedi C2-implantok), különösen Linux-oldalon
- .007 JavaScript — böngésző- és `wscript`/`cscript`-alapú végrehajtás, HTA-kkal is összefügg
- .008 Network Device CLI — hálózati eszközök (router/switch) saját parancssori felülete, konfiguráció-manipulációhoz
- .009 Cloud API — felhő-szolgáltatások saját parancssori/API-felülete (AWS CLI, Az CLI), cloud-natív környezetben
- .010 AutoHotKey & AutoIT, .011 Lua, .012 Hypervisor CLI, .013 Container CLI/API — újabb, szűkebb hatókörű altechnikák; egyik sincs lefedve ebben a repóban

## Mitigáció

- **Constrained Language Mode / AppLocker+WDAC** — a PowerShell-t (és részben a többi interpretert) aláírt szkriptekre vagy allowlistre korlátozza; a legjobban dokumentált kontroll a .001-re.
- **Interpreter-specifikus logging** (PowerShell Script Block Logging 4104, bash `auditd`/history-forward) — ahol nincs bekötve, ott a technika gyakorlatilag csak a folyamatindítási parancssoron keresztül látható, nem a tényleges szkript-tartalmon.
- Egyik kontroll sem szünteti meg az előfeltételt (az interpreter jelenlétét) — minden platformon natívan ott van, és eltávolítása az esetek túlnyomó részében a normál üzemeltetést törné.

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés | Érintett altechnika |
| ---------- | ----- | ---------- | -------------------- |
| Sysmon EID 1 (ProcessCreate) | Process | `CommandLine`/`Image`/`ParentImage` — minden jelenlegi szabály erre épül | .001, .004 |
| WEL 4104 (Script Block Logging) | Script | deobfuszkált PowerShell-tartalom — nincs bekötve | .001 |
| Linux `auditd` / EDR process telemetria | Process | natív Unix Shell-jel — nincs bekötve, csak közvetett webshell-jel van | .004 |

### Detekciós lehetőség

A repó lefedettsége erősen **PowerShell-központú**: a 12 szabályból álló [[T1059.001 - PowerShell]] réteg a technika messze legérettebb szegmense. A [[T1059.004 - Unix Shell]] lefedettség ehhez képest szűk és közvetett — nem natív Linux-telemetriára épül, hanem a webshell-lánc query stringjén átszűrődő parancsmintára (lásd a nginx web-detection track). A többi hét altechnika (AppleScript, Windows Command Shell, Visual Basic, Python, JavaScript, Network Device CLI, Cloud API) és az újabb, szűkebb formák (AutoHotKey/AutoIT, Lua, Hypervisor CLI, Container CLI/API) **teljesen fedetlenek** — ezek közül a Windows Command Shell (.003) a legnagyobb gyakorlati hiány, mert `cmd.exe`-n keresztül is fut sok LOLBin-lánc, amit a jelenlegi PowerShell-fókuszú selection-ök nem látnak.

## Kapcsolódó szabályok

| detect_id | Altechnika | Miért szükséges |
| --------- | ---------- | --------------- |
| DETECT-2026-0001, 0007–0016, 0018 (12 szabály, lásd [[T1059.001 - PowerShell]]) | .001 | Réteges PowerShell-detekció — kódolás, download cradle, reflection, stealth flagek, logging-letiltás stb. |
| DETECT-2026-0040 (lásd [[T1059.004 - Unix Shell]]) | .004 | Webshell-lánc query stringjén átszűrődő shell-parancsminta |

**Nem fedett:** .002 AppleScript, .003 Windows Command Shell, .005 Visual Basic, .006 Python, .007 JavaScript, .008 Network Device CLI, .009 Cloud API, .010–.013 (AutoHotKey/AutoIT, Lua, Hypervisor CLI, Container CLI/API).

## Kapcsolódó jegyzetek

- **Rokon technikák:** [[T1027 - Obfuscated Files or Information]] — a Command Obfuscation altechnikája (.010) gyakran ugyanabban a PowerShell-munkamenetben jelenik meg, mint a T1059.001 minták
- **MITRE:** https://attack.mitre.org/techniques/T1059/

## Saját feljegyzések
