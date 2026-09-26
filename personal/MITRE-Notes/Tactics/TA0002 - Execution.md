---
mitre_id: TA0002
mitre_type: tactic
name: Execution
aliases:
  - TA0002
  - Execution
url: https://attack.mitre.org/tactics/TA0002/
matrix_position: 4
technique_count: 20
de_priority: kritikus
coverage: részleges
---
# TA0002 — Execution

## Cél

A támadó **saját kódot futtat** a célkörnyezet egy gépén. Ez a taktika önmagában sosem a végcél — a futtatott kód mindig valami mást szolgál: felderítést, hitelesítőadat-lopást, perzisztencia-telepítést, C2-csatorna kiépítését. Ezért az Execution szinte minden támadási láncban szerepel, és jellemzően nem egyszer, hanem sokszor.

Detection engineering szempontból ez a taktika **kitüntetett helyzetben van**, két ok miatt. Egyrészt ez a legjobban megfigyelhető taktika az egész mátrixban: a folyamatindítás (Sysmon EID 1, Windows 4688) a legrészletesebb, legkönnyebben hozzáférhető végponti telemetria, és minden kódfuttatás keletkeztet ilyen eseményt. Másrészt a támadó itt kényszerül a legtöbb *megfigyelhető döntésre*: milyen interpretert használ, milyen paraméterekkel, milyen szülőfolyamatból — és ezek a döntések ujjlenyomatként viselkednek.

A taktika nehézsége viszont nem a láthatóság, hanem a **legitimitás**: a támadó ugyanazokat az interpretereket használja (PowerShell, `cmd.exe`, `bash`, WMI), amiket a rendszergazdák és a telepítőcsomagok is. Itt tehát nem az a kérdés, hogy *látjuk-e* — hanem hogy meg tudjuk-e különböztetni.

> [!quote] MITRE definíció
> The adversary is trying to run malicious code.

## Hely a támadási láncban

- **Előtte tipikusan:** [TA0001 - Initial Access] — kódfuttatáshoz először be kell jutni; sok Initial Access technika (exploit, makrós dokumentum) egyetlen lépésben adja mindkettőt  *(taktika-hivatkozás szándékosan egykapcsos: ne kösse össze a taktikákat a gráf nézetben)*
- **Utána tipikusan:** [TA0003 - Persistence] — az első kódfuttatás jellemzően illékony (egy folyamat, ami véget ér); a támadó első dolga, hogy ezt tartóssá tegye. Utána [TA0007 - Discovery] és [TA0006 - Credential Access] következik
- **Mit feltételez:** **nem feltételez emelt jogosultságot** — egy sima felhasználói kontextusban futó PowerShell is Execution. Amit feltételez: egy már meglévő belépési pont (letöltött és megnyitott melléklet, kihasznált szolgáltatás, ellopott hitelesítő adattal nyitott session), és egy elérhető interpreter vagy futtatási mechanizmus a gépen

## Technikák

| ID                                                       | DE prioritás | Lefedettség | Megjegyzés                                                                                                                       |
| -------------------------------------------------------- | :----------- | :---------- | :------------------------------------------------------------------------------------------------------------------------------- |
| [[T1059 - Command and Scripting Interpreter]]              | kritikus     | részleges   | 13 altechnika; a repo súlypontja — 12 szabály a `.001` (PowerShell) alatt, 1 a `.004` (Unix Shell) alatt                          |
| [[T1053 - Scheduled Task-Job]]                             | kritikus     | nincs       | 5 altechnika; átfed a Persistence taktikával, `schtasks`/`at`/`cron`; a legnagyobb egyedi hiány ezen a taktikán                   |
| [[T1047 - Windows Management Instrumentation]]             | magas        | nincs       | `wmic.exe` / `Invoke-WmiMethod`; távoli kódfuttatás gyakori eszköze, Sysmon EID 1-ből jól látszik                                  |
| [[T1197 - BITS Jobs]]                                      | magas        | teljes      | 2 szabály (0005 `bitsadmin`/PowerShell, 0006 `SetNotifyCmdLine`); átfed a Persistence és Stealth taktikákkal                      |
| [[T1204 - User Execution]]                                 | magas        | nincs       | 5 altechnika; a felhasználó nyitja meg a payloadot — a jel a szülőfolyamat (Office, böngésző, archívumkezelő), lásd 0013          |
| [[T1203 - Exploitation for Client Execution]]              | magas        | nincs       | Kliensoldali exploit (Office, böngésző); nincs megbízható szignatúra, a gyermekfolyamat-anomália az egyetlen jel                  |
| [[T1569 - System Services]]                                | közepes      | nincs       | 3 altechnika; `sc.exe create`, PsExec — átfed a Lateral Movement taktikával                                                        |
| [[T1574 - Hijack Execution Flow]]                          | közepes      | nincs       | 12 altechnika (DLL search order, path interception); átfed a Persistence és Privilege Escalation taktikákkal                       |
| [[T1559 - Inter-Process Communication]]                    | közepes      | nincs       | 3 altechnika; COM/DDE-alapú futtatás                                                                                              |
| [[T1106 - Native API]]                                     | közepes      | nincs       | Közvetlen syscall/API-hívás az interpreter megkerülésével — folyamatindítás-logból strukturálisan láthatatlan                     |
| [[T1127 - Trusted Developer Utilities Proxy Execution]]    | közepes      | nincs       | 3 altechnika; MSBuild/`dotnet`/`msxsl` — LOLBAS-terület, átfed a Stealth taktikával                                               |
| [[T1129 - Shared Modules]]                                 | alacsony     | nincs       | DLL betöltése; EID 7 (ImageLoad) kellene hozzá, extrém volumen                                                                    |
| [[T1072 - Software Deployment Tools]]                      | alacsony     | nincs       | SCCM/Intune visszaélés — a labban nincs ilyen eszköz                                                                              |
| [[T1674 - Input Injection]]                                | alacsony     | nincs       | Szintetikus billentyű-/egérbevitel (pl. USB Rubber Ducky)                                                                          |
| [[T1609 - Container Administration Command]]               | —            | nincs       | Konténer — hatókörön kívül                                                                                                        |
| [[T1610 - Deploy Container]]                               | —            | nincs       | Konténer — hatókörön kívül                                                                                                        |
| [[T1648 - Serverless Execution]]                           | —            | nincs       | Cloud — hatókörön kívül                                                                                                            |
| [[T1651 - Cloud Administration Command]]                   | —            | nincs       | Cloud — hatókörön kívül                                                                                                            |
| [[T1675 - ESXi Administration Command]]                    | —            | nincs       | Hipervizor — hatókörön kívül                                                                                                      |
| [[T1677 - Poisoned Pipeline Execution]]                    | —            | nincs       | CI/CD pipeline — ebben a repóban ez a saját GitHub Actions security-kérdése, nem detekciós szabály                                 |

## Detekciós stratégia (taktikai szint)

Ez a taktika a repo detekciós gerince, és **egyetlen adatforráson nyugszik**: a Sysmon EID 1 (ProcessCreate) eseményen. A jelet három mező hordozza, és érdemes tudni, melyik mit ér:

- **`CommandLine`** — a legerősebb és egyben a legsérülékenyebb. Itt látszik, *mit* futtattak: a kódoló flag (`-EncodedCommand`), a letöltő cradle (`Net.WebClient`), az AMSI-bypass string, a webshell parancsa. A gyengesége az obfuszkáció: base64, string-konkatenáció, backtick-beszúrás, változó-behelyettesítés — mindegyik ugyanazt a viselkedést más karakterekkel írja le. Ezért a repo PowerShell-családja nem egyetlen nagy szabály, hanem **12 külön, egy-egy konkrét visszaélési mintára hangolt szabály** (0007–0018): ez ad triage-elhető, indokolható riasztást, szemben egy kulcsszólistával, ami mindent egybefog.
- **`Image` / `OriginalFileName`** — a *mit indítottak el* kérdés. Az `OriginalFileName` (a PE verzió-erőforrásából) azért fontos, mert átnevezés-ellenálló: egy `svchost.exe`-nek nevezett `powershell.exe` az `Image`-en elbújik, az `OriginalFileName`-en nem. A repo szabályai ezt következetesen párban használják.
- **`ParentImage` / `ParentCommandLine`** — a *kontextus*, és gyakran ez az egyetlen dolog, ami a rosszindulatút a legitimtől elválasztja. Egy `powershell.exe` önmagában semmi; egy `powershell.exe` `winword.exe` szülővel (DETECT-2026-0013) már riasztás. Ugyanez a logika adja a webszerver-oldali T1505.003 detekció végponti lábát is: `nginx` vagy `w3wp.exe`, ami shellt indít.

A taktika **közös FP-forrása** jól körülhatárolható és ezért jól szűrhető: szoftvertelepítők és -frissítők, konfigurációmenedzsment (GPO startup scriptek, SCCM), monitorozó és backup ügynökök, valamint a rendszergazdák saját szkriptjei. Ezek mind **névvel azonosítható, visszatérő entitások** — ugyanaz a helyzet, mint [TA0006 - Credential Access]-nél, és ellentétben [TA0001 - Initial Access] anonim scanner-zajával. Az allowlist itt tehát működő eszköz, nem kapituláció.

Amit ezen a szinten **nem** lehet látni: a folyamatindítás nélküli kódfuttatást — beinjektált shellcode egy már futó folyamatban, közvetlen syscall (T1106), .NET assembly reflektív betöltése (ezt a 0015 csak a betöltő PowerShell-hívásból látja, nem a betöltött kódból). Ehhez EDR-szintű memória-telemetria kellene, ami nem folyamatindítás-log kérdése. Továbbá a Linux-oldali kódfuttatás: a `.004` (Unix Shell) végponti detekciója ebben a repóban tudatosan nincs felépítve, ezért az egyetlen `.004`-es szabály nem is végponti, hanem web-access-log alapú.

## Lefedettség ebben a repóban

Jelenleg **15 szabály**, ami ezt a taktika-tag-et viseli — a repo legnagyobb egybefüggő szabálycsoportja:

**[[T1059 - Command and Scripting Interpreter]] `.001` (PowerShell) — 12 szabály.** DETECT-2026-0001 (reverse shell), 0007 (kódolt parancs), 0008 (download cradle), 0009 (inline base64 dekódolás+futtatás), 0010 (execution policy bypass), 0011 (tömörített payload), 0012 (AMSI bypass), 0013 (gyanús szülőfolyamat), 0014 (stealth flag-kombináció), 0015 (reflektív assembly-betöltés), 0016 (script block logging kikapcsolása), 0018 (ismert rosszindulatú cmdletek). Ez a csoport a taktika `.001` altechnikáját gyakorlatilag teljesen lefedi a folyamatindítás-log szintjén.

**[[T1197 - BITS Jobs]] — 2 szabály.** DETECT-2026-0005 és 0006; mindkettő egyszerre Execution, Persistence és Stealth.

**[[T1059 - Command and Scripting Interpreter]] `.004` (Unix Shell) — 1 szabály.** DETECT-2026-0040, és ez a repo egyetlen nem-Windows kódfuttatás-detekciója. Fontos érteni, hogy **miért nem végponti**: nem `bash` folyamatindítást lát, hanem egy nginx access-log kérést, aminek a query stringjében Unix-parancs látszik — vagyis a webshell *interfészét*, nem a lefutást. Részletek: [[T1059.004 - Unix Shell]].

Az aránytalanság szándékos és a lab-környezetből következik: a monitorozott végpontok Windows-osak, Sysmon-nal, és a PowerShell a domináns támadási felület rajtuk. A legnagyobb **egyedi** hiány ezen a taktikán a [[T1053 - Scheduled Task-Job]] és a [[T1047 - Windows Management Instrumentation]] — mindkettő ugyanabból az adatforrásból (Sysmon EID 1) detektálható, amire már 15 szabály épül, tehát nincs pipeline-oldali előfeltételük: ez tisztán szabályírási hátralék, nem strukturális rés.

## Saját feljegyzések

