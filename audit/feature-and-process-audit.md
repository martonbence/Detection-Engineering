# Repo audit — funkciók, dokumentáció, folyamat

**Ez a fájl egy második, önálló register.** Nem folytatása a lezárt
`audit/remediation-plan.md`-nek (54/54, 9,0/10, lezárva 2026-08-15) — az
történelmi rekord, változatlanul marad. Amit az a kör *nem* nézett meg —
funkcióhiányok, dokumentáció-teljesség, és maga a fejlesztési folyamat —,
az itt kezdődik elölről.

- Az audit alapja: `dev @ d17ff7e`, statikus átvizsgálás + futtatott ellenőrzések, 2026-08-18
- Nincs publikált register-oldal ehhez a körhöz (az `audit/register.html` a régi audité, nem ezé)
- Nincs menetrend — a tempó ad-hoc, tételenként

> **Státusz: v1.0, lezárt első kiadás (2026-08-18).** Két független átvizsgálás
> összefésült eredménye: Kwame auditja (verifikáció-alapú) és Yara stratégiai
> briefje (ideáció-alapú), amelyek egymás kimenetének ismerete nélkül készültek.
> Ahol a két forrás ugyanarra a hiányra mutatott, egy tétel lett belőle; ahol
> Yara állítása ellenőrzésen elbukott vagy pontosításra szorult, a tétel a
> **verifikált** változatot rögzíti, és a Napló nevesíti az eltérést.

## Munkamenet

1. Egy tétel elvégzése után itt `[ ]` → `[x]`, és egy sor a Naplóba a végére.
2. Folyamatban lévő tételnél a sor végére `⟶ folyamatban`.
3. Minden tétel végén `→ <név>`: az a szakember, akihez a végrehajtás tartozik
   (`CLAUDE.md` roster). Kwame ezt a fájlt vezeti, a mögöttes felületeket nem szerkeszti.
4. Elutasítás is lezárás: `[x]` + a Naplóban az indoklás. Egy tétel akkor is kikerül a
   nyitott halmazból, ha végiggondolva nem éri meg — ez a régi register bevált gyakorlata.

## Pontszám

Kiindulás: **7,0 / 10**. Kész súly: **0 / 84**. *(Ez a v1.0 kiindulási
alapállapot, szándékosan befagyasztva — nem élő számláló, egyetlen lezárás
sem növeli, ellentétben a lezárt `remediation-plan.md` azonos formátumú
sorával. Részletek: Napló, 2026-08-21.)*

Dimenziók — most → hova vinné a register teljesítése:

| Dimenzió | Most | Cél | Miért ennyi ma |
|---|---|---|---|
| Koncepció | 9 | 9 | A zárt hurok (deploy → valódi támadás → mérés → verdikt) továbbra is a repo legerősebb tulajdonsága. Nem ezen múlik semmi. |
| Dokumentáció | 5 | 9 | Terjedelmes és jól megírt, de a legterheltebb állításai elavultak: a prod bizalmi határát máig a megszűnt drift gate-tel magyarázza, a negyedik workflow-ról egy szó sincs, 13 script nincs leírva. |
| Robusztusság | 7 | 9 | A CI-kapuk erősek, de a repo legnagyobb egybefüggő kódfelülete (front-end, 7 500 sor) semmilyen automatizált ellenőrzés alatt nincs, és a teszt-suite a fejlesztő saját gépén bukik. |
| Hitelesség | 6 | 9 | A publikált szám ma 4% pass rate — nem azért, mert romlott valami, hanem mert a szándékosan kikapcsolt tesztelés és két teszt-fixtúra ugyanabba a nevezőbe kerül, mint a valódi mérés. A számok matematikáját nulla teszt fedi. |
| Karbantarthatóság | 6 | 8 | 1 263 sor inline shell a dev workflow-ban, 1 812 soros generátor egyetlen 277 soros központi függvénnyel, hat különböző commit-visszaírási út. |
| Biztonság | 8 | 9 | Attesztáció-alapú prod-kapu, SHA-pinelt actionök, fork-PR nem ér el self-hosted runnert, pip-audit fut. A rés inkább dokumentációs: a leírt kontroll nem az, ami fut. |
| Fejlesztői folyamat (Claude-munkamodell) | 6 | 9 | A roster átgondolt, de van gazdátlan felület (`CLAUDE.md`, `TEAM.md`, `.claude/**`), egy gyakorlatilag halott hook, nincs permission- és MCP-konfiguráció a repóban, és az ügynökfájlokban elavult tények élnek. |

A register meterének súlyozása: kritikus ×3, robusztusság ×2, funkció ×1,5,
Claude-munkamodell ×1,5, dokumentáció ×1.
A teljes súly **84** = 6×3 + 8×2 + 13×1,5 + 11×1,5 + 14×1.
Projektált pontszám = `7,0 + 2,5 × (kész súly / 84)`.

*(A súly 70-ről 79-re nőtt a Yara-brief beolvasztásakor: hét új tétel a
funkció-, dokumentáció- és folyamat-kategóriákban. A kiindulási pontszám nem
mozdult — az új tételek mélyítik a képet, de nem változtatnak a diagnózison.)*

## Javasolt sorrend

**1.1** → **1.2** → **1.4** → **1.5** + **3.9** → **1.6** → **5.1** → **5.3** → **2.12** → **4.3** → **4.2** → **3.1**

Az első öt tétel mind ugyanarról szól: *amit a projekt magáról állít, az ma nem
egyezik azzal, ami fut.* Ez a legolcsóbban javítható és a legdrágábban hagyható
kategória — egy külső olvasó (vagy egy fél év múlva visszatérő fejlesztő) a
dokumentációt hiszi el, nem a kódot. Az **1.1** azért az első, mert nem egyszerű
elavulás: a README és három architektúra-dokumentum egy *biztonsági kontrollt* ír
le (`git diff --exit-code` drift gate), ami már nem létezik, és nem említi azt,
ami a helyére lépett (Sigstore build-provenance attesztáció) — vagyis a repo
alulértékeli a saját, ténylegesen erősebb védelmét, miközben egy nem létezőre
hivatkozik.

Az **1.6** azért kerül még a folyamat-tételek elé, mert az egyetlen olyan tétel,
ami a többi javítását is olcsóbbá teszi: amíg a pass rate / evidence-aritmetikát
nulla teszt fedi, minden ezt érintő változtatás (1.4, 1.5, 3.1) csak kézi
összehasonlítással ellenőrizhető.

Az **1.5** és a **3.9** szándékosan egy lépés: az egyik a metrika *számítását*
javítja, a másik a *kontextusát* adja meg ott, ahol a szám olvasható. Külön-külön
mindkettő féloldalas — együtt attól szűnik meg a „4%" félreolvashatósága, hogy
egyszerre igaz a szám és látszik, mikor mértek utoljára élesben.

Az **5.1** és **5.3** azért kerül előre a folyamat-kategóriából, mert ezek
termelik a többi tétel egy részét: gazdátlan `.claude/**` és `TEAM.md` mellett
minden ügynökfájl-elavulás (5.5) újratermelődik, permission-konfiguráció nélkül
pedig minden rutinfutás kézi jóváhagyást kér.

A **2.12** azért ugrik ilyen előre a dokumentációs kategóriából, mert nem
elavulás, hanem **élő hiba**: egy ügynökfájl kötelező érvénnyel hivatkozik egy
skillre, ami nem létezik — vagyis minden front-end diagram-munka egy nem
teljesíthető utasítással indul.

---

## 1 · Kritikus — ami félrevezet vagy elveszik (6) · ×3

- [ ] **1.1** A prod bizalmi határának leírása egy megszűnt kontrollt ír le, a valódit nem említi · `README.md:116`, `docs/architecture/pipeline_overview.md:109,383`, `scripts_reference.md:87-93,260,276`, `data_flow.md:59`, `.github/dependabot.yml:5-8` · A régi register **3.2 stage C** (lezárva 2026-08-09) törölte a prod-oldali újrakonverziót és a `git diff --exit-code -- rules/splunk` drift gate-et; a helyére a `.bundle-provenance.json` pointer + `gh attestation verify` lépett (`ci_prod_workflow.yml:149-230`). A dokumentáció mind az öt helyen a régi mechanizmust írja le mint aktív kaput, és az „attestation" / „provenance" szó **nulla alkalommal** szerepel a README-ben és a `docs/architecture/` egyetlen fájljában sem. Ez nemcsak elavult: a `pipeline_overview.md:383` job-táblája két olyan lépést nevez meg (`Regenerate SPL + meta sidecars from Sigma source`, `Fail if regenerated SPL drifted…`), amelyek a fájlban nem léteznek. Ellenpont, ami mutatja, hogy megoldható: a `.github/requirements.txt` fejléc-kommentje **pontosan** leírja az új állapotot — a kód kommentjei előrébb járnak, mint a dokumentáció → **Chloe**
- [ ] **1.2** Négy workflow van, minden dokumentum hármat ismer · `.github/workflows/ci_prod_audit.yml` (356 sor, 2 job: `audit_prod`, `record_inventory`) · A `ci_prod_audit` a régi register **4.7 phase 2** terméke — az egyetlen mechanizmus, ami megkérdezi, hogy a prod Splunk még az-e, aminek hisszük. Előfordulása: `README.md` **0**, mind az öt `docs/architecture/*.md` **0**, `CLAUDE.md` **0** (Jamal sora „the 3 GitHub Actions workflows"-t mond), `.claude/agents/Jamal - DevOps Engineer.md` **0** (háromsoros workflow-tábla). A README „CI orchestration — three workflows" szakaszcíme és a repo-layout tábla is hármat sorol. Mellékhatás: a prod-audit létezéséről csak az tud, aki a `.github/workflows/` könyvtárat listázza → **Chloe** (docs), **Gaz** (`CLAUDE.md` roster-sor)
- [ ] **1.3** A README dev-job táblája kihagy egy jobot, a prod-leírás egy jobbal kevesebbet mond · `README.md:106-114,140`, `docs/architecture/pipeline_overview.md:363-374` · A `ci_dev_workflow.yml` ma **9** jobból áll; az `update_dashboard` (`:2240`, „Update Dashboard & Docs", saját `environment: dev`, saját commit-visszaírás) egyik táblában sem szerepel. A README a `ci_prod_workflow.yml`-t „single job (`deploy_to_prod`)"-ként írja le (`:140`), holott két jobja van (`announce_lab_offline` + `deploy_to_prod`) — a `pipeline_overview.md` ezt már helyesen tudja, tehát a két dokumentum egymásnak is ellentmond → **Chloe**
- [x] **1.4** A publikált statisztika két teszt-fixtúrát valódi szabályként számol · `rules/sigma/DETECT-2026-0003_Test3.yml` (`status: test`, `level: critical`, leírás: „Test Sigma rule for demonstration purposes."), `rules/sigma/DETECT-2026-0032_Pipeline-Test-Rule-…yml` (`status: test`, „Disposable pipeline test rule") · Mindkettő beleszámít a `total_rules`-ba (28), a MITRE-lefedettségbe (`attack.t1059.001`, `attack.t1057`), a README badge-eibe és a pass rate nevezőjébe. A `generate_stats.py` nem ismeri a `status` mezőt szűrőként. Két út van: a generátor zárja ki (vagy külön jelölje) a `status: test` szabályokat, vagy a két fixtúra kerüljön ki a könyvtárból. A döntés nem Kwaméé — de az állapot ma az, hogy egy „demonstration purposes" szabály `critical` szinten szerepel a nyilvános lefedettségi mátrixban → **Sienna** (generátor) vagy **Yuki/Bjorn** (szabály-kivezetés), **Gaz** dönt · **Elutasítva, lásd Napló 2026-08-20**
- [x] **1.5** A szándékosan ki nem tesztelt szabály úgy néz ki, mint a mérhetetlen — és lehúzza a pass rate-et · `outputs/results/*/result.json` (27 db `NOT_VERIFIED`, ok: „Testing is disabled for this rule (custom.testing.enabled: false)"), `scripts/docs/generate_stats.py:863-1140` · Az `ef39dce` commit tudatosan kikapcsolta a tesztelést 27 szabályon; ettől `verified_current = 28`, `verified_pass_current = 1`, és a **publikált pass rate 4%** (`outputs/reports/stats.json`). A `NOT_VERIFIED` a nevezőben marad, tehát a „nem is akartuk mérni" és a „mérni akartuk, nem sikerült" ugyanabba a számba folyik. A README maga fogalmazza meg a helyes elvet („Both mean *we don't know*, not *it's broken*") — a metrika viszont ma büntetésként viselkedik. Javaslat: külön evidence-vödör (`Testing disabled` / hatókörön kívül), ami a `never_tested`-hez hasonlóan kiesik a nevezőből, plusz a badge-sor mellé egy „scoped for testing" arány → **Sienna**, a `pass_fail_eval.py` oldalán **Jamal**
- [x] **1.6** A publikált számok matematikáját nulla teszt fedi · `tests/` (555 teszt, ebből a `generate_stats`-ot **egy** modul importálja: `tests/test_deployment_panel.py`, és az kizárólag a deployment-panelt vizsgálja) · Nincs egyetlen assertion sem a `pass_rate` / `verified_current` / `verified_stale` / `verified_superseded` / `verified_expired` / `REVIEW_INTERVAL_DAYS` viselkedésére (`grep` a `tests/`-ben: 0 találat). A README ~2 000 szót szentel annak, hogy ezek a számok pontosan mit jelentenek — ez a repo központi hitelességi állítása —, és a mögötte lévő `generate_stats()` egy 277 soros függvény (`:863-1140`), amit semmi nem véd egy csendes regressziótól. Minimum: a hat layer-2 kulcs és a 180 napos küszöb határesetei szintetikus verdikt-fixtúrákkal → **Sienna** (a modul az övé), tesztkonvenciók **Jamal**

## 2 · Dokumentációs hiányok és elavulás (14) · ×1

- [ ] **2.1** A „per-file map" 13 scriptet nem ír le a 30-ból · `docs/architecture/scripts_reference.md` · Hiányzik a teljes `scripts/lib/` a `rule_naming.py` kivételével (`env.py`, `meta_sidecar.py`, `rule_version.py`, `rules.py`, `splunk_client.py`, `splunk_ns.py`, `summary.py`, `verdict_history.py`), továbbá `check_detect_id_uniqueness.py`, `check_spl_syntax.py`, `check_version_bump.py`, `deployment_inventory.py`, `new_rule.py`. Ebből három **hard CI-kapu** (`check_detect_id_uniqueness`, `check_version_bump`, `check_spl_syntax`), egy pedig az a script, amivel a `sigma-rule-authoring` skill szerint minden új szabály indul (`new_rule.py`). Chloe saját ügynökfájlja ezt a dokumentumot nevezi meg úgy, mint „the first thing to drift" — igaza lett → **Chloe**
- [ ] **2.2** A `LAB_ONLINE` kapcsoló nincs a README-ben · `README.md` (0 előfordulás) vs. `ci_dev_workflow.yml` (14), `ci_prod_workflow.yml` (6), `pipeline_overview.md` (5) · Ez az a repository-variable, ami eldönti, hogy a pipeline lab-függő fele egyáltalán fut-e. Aki csak a README-t olvassa, nem tudja megmagyarázni, miért zöld egy futás, ami semmit nem mért → **Chloe**
- [ ] **2.3** A `pipeline_overview.md` ügynök-listája 7 ügynököt sorol a 11-ből · `docs/architecture/pipeline_overview.md:438-448` · Hiányzik a `detection-engineer` (Yuki), a `threat-intel` (Masha), az `audit-compliance` (Kwame) és a Gaz-referencia. A lista csak slugokat használ, a `TEAM.md`-re (a névvel ellátott, hivatalos roster) nem hivatkozik, pedig az a fájl azóta létrejött. A szakasz saját maga kéri, hogy „re-read that directory if this list looks stale" — elavult → **Chloe**
- [ ] **2.4** A `repo-terkep.hu.md` számai elavultak · `docs/architecture/repo-terkep.hu.md:80,97,111` · „`ci_dev_workflow.yml` — 1 695 sor, 8 job" (valójában **2 572 sor, 9 job**), „`ci_prod_workflow.yml` — 232 sor" (valójában **341**), „`ci_code_checks.yml` — 559 sor" (valójában **571**). A `:106` és `:130` sorok ráadásul a drift gate-et magyarázzák mint élő indoklást (lásd 1.1) → **Chloe**
- [ ] **2.5** 19 helyen kézzel bedrótozott „27 szabály" / „12 of 27" / „92%" · `README.md:48,50,52,56,57,59`, `docs/architecture/*.md` · A könyvtár ma **28** szabály, a mai adatokon 1 PASS / 27 NOT_VERIFIED / 4%. A próza számai a `<!-- STATS_START -->` blokkon *kívül* élnek, tehát a generátor sosem frissíti őket. Két megoldás közül kell választani: vagy a próza ne idézzen élő számot (csak fogalmat magyarázzon, példát „pl."-lel jelölve), vagy a generátor kapjon több behelyettesíthető markert. A jelenlegi állapot a rosszabbik: konkrét, hitelesnek *látszó* és hamis → **Chloe**, generált markerek esetén **Sienna**
- [ ] **2.6** Nincs „hogyan futtasd le helyben" dokumentum · sem `README.md`, sem `docs/architecture/` · Nincs leírva, mit kell telepíteni ahhoz, hogy a `pytest`, a `ruff`, a `validate_sigma.py` vagy a `generate_stats.py` helyben fusson; a `.github/requirements*.txt` fejléce kifejezetten azt mondja, hogy „nothing here is needed to work on the rules locally" — ami a tesztekre nem igaz. Lásd a 4.3-at: a suite ma bukik a fejlesztő saját gépén, és nincs hova utánanézni → **Chloe**, a tényleges függőséglista **Jamal**
- [ ] **2.7** A Wiki továbbra sem létezik · `README.md:177,182`, `.claude/agents/Chloe - Technical Writer.md` · A README őszintén jelzi, hogy nincs — ez rendben van —, de a „planned newcomer-facing walkthrough" tartósan terv marad, miközben a `docs/architecture/` négy fájlja együtt 1 400+ sor mély referencia, kezdő belépési pont nélkül. Döntést igényel: vagy engedélyezés + első oldal (**Kai**, majd **Chloe**), vagy a Wiki-hivatkozások kivezetése a README-ből, hogy ne ígérjen nem létező felületet → **Gaz** dönt
- [x] **2.8** `TEAM.md`: 11/11 „Avatar: pending", holott két avatár létezik · `TEAM.md:5,63,80,96,…` vs. `.claude/agents/avatars/Bjorn.jpg`, `Yuki.png` · Ráadásul a `team-avatars` skill (`.claude/skills/team-avatars/SKILL.md:84-89`) `<firstname-lowercase>.png` elnevezést és `![Bjorn](...)` bekötést ír elő — a két meglévő fájl nagy kezdőbetűs, az egyik `.jpg`, és egyik sincs bekötve. A `Yuki.png` 1,1 MB, a repo legnagyobb követett fájlja. **Kwame és Yara egymástól függetlenül ugyanezt találta meg** — a két átvizsgálás egyetlen teljes átfedése, ami önmagában is jelzés arról, mennyire látható ez a rés → **gazdátlan, lásd 5.1**
- [ ] **2.9** Nincs per-szabály dokumentáció, és a hozzá tartozó hivatkozás holt · `README.md:175` (issue #20), `.claude/agents/Bjorn - Detection Quality Engineer.md` frontmatter (a `rule_documentations/` könyvtárra hivatkozik, ami már nincs a repóban — az ügynökfájl maga jelzi ezt, de a mondat így is félrevezető) · A README szerint a metaadat-forrás kérdése megoldódott (minden a `rules/sigma/*.yml`-ben van), tehát az automatizálásnak nincs technikai akadálya. Ma egyetlen szabályról sincs önálló, olvasható lap sem a repóban, sem a rule browserben → **Gaz** priorizál, **Sienna** (generátor) vagy **Jamal** (CI-lépés)
- [x] **2.10** Feloldatlan register-hivatkozás a kódban: `[dashboard-decoupling]` · `.github/workflows/ci_dev_workflow.yml:1131,1601,2116,2295,2578` (öt komment, nem három — a szám a v1.0 kiadás óta nőtt) · A lezárt `audit/remediation-plan.md`-ben **nulla** előfordulása van; a repo minden más ilyen kommentje valódi számozott tételre mutat (38 azonosító). A mögöttes döntés (`cb99a97`) valós és jó volt, csak sosem lett regisztrálva. **Utólag felvéve és lezárva mint 4.8** (ld. ott a teljes tartalom) — ez a tétel saját maga kínálta (a) opció. A (b) opció (a kódkommentek szövege a placeholder helyett `4.8`-ra hivatkozzon) **nem történt meg**: a register-könyvelés kész, a kommentcsere Jamal külön hatásköre (`ci_dev_workflow.yml` tartalma), Kwame nem szerkesztheti → **Jamal** (5 komment `[dashboard-decoupling]` → `4.8`)
- [x] **2.11** A `dependabot.yml` indoklása a 3.2 előtti világot írja le · `.github/dependabot.yml:5-8` · „The pins exist because prod re-runs the converter over the same Sigma source dev already converted…" — a prod ezt már nem teszi (a `.github/requirements-deploy.txt` fejléce ezt helyesen le is írja). A pineknek ma is van értelme (a dev saját reprodukálhatósága), csak nem ez az. Konfigurációs komment, de a repo szerkesztési kultúrájában ezek dokumentumértékűek → **Jamal** · **Javítva, lásd Napló 2026-08-22.**
- [x] **2.12** Élő hivatkozás egy nem létező skillre · `.claude/agents/Sienna - Frontend Engineer.md:48`: „when adding or redesigning any chart, graph, stat tile, or dashboard element, **invoke the `dataviz` skill first** … before writing chart code" · A `.claude/skills/` alatt három skill van: `mitre-attack-mapping`, `sigma-rule-authoring`, `team-avatars`. `dataviz` **nincs**. Ez nem elavulás, hanem működő hiba: kötelező érvényű utasítás egy nem teljesíthető lépésre, ami minden front-end diagram-munka elejére be van építve. Két út: megírni a skillt (a repo diagram-konvenciói ma a `page.css` 4 036 sorában és a `page.js` chart-kódjában élnek, tehát lenne mit rögzíteni), vagy törölni a sort. Yara találata, `grep`-pel megerősítve → **Gaz** dönt (skill-gazda kijelölése az 5.1-gyel együtt), tartalom **Sienna**
- [ ] **2.13** Nincs architektúra-dokumentum magáról a `.claude/` ökoszisztémáról · `docs/architecture/` négy mély referenciát ad a pipeline-ról, a csapatmodellről egyet sem · A `CLAUDE.md` előíró (ki mit birtokol, hogyan megy a delegálás), a `TEAM.md` roster — egyik sem „hogyan folyik a munka a gyakorlatban" referencia valódi példákkal. Egy `docs/architecture/agent_workflow.md` (Yuki→Bjorn átadás, egy Kwame-féle drift-elkapás, egy Gaz-féle feladatszétvágás, mindegyik valós esettel) egyszerre lenne onboarding-anyag és annak a dokumentálása, ami ebben a repóban ténylegesen újszerű. Yara javaslata; a jelen audit 5. szakasza pont azt bizonyítja, hogy van mit leírni → **Chloe**
- [ ] **2.14** Nincs `CONTRIBUTING.md` · ellenőrizve: a fájl nem létezik · A régi register **2.11**-e a CODEOWNERS-t és a PR-sablont utasította el mint „checklist-ballaszt" egy egyszemélyes repóban — ez a döntés áll. A `CONTRIBUTING.md` viszont más kérdésre válaszol: nem kapu, hanem egy helyen összeszedett szerzői folyamat (szabály-scaffold → validálás → review → promotion), ami ma öt dokumentum és három skill között van szétszórva. Alacsony prioritás az egyszemélyes valóság miatt, de olcsó, és a 2.6 (lokális futtatás) természetes otthona lenne. Yara javaslata → **Chloe**

## 3 · Funkció- és képességhiányok (13) · ×1,5

- [x] **3.1** Az elévülés mechanizmusa megvan, a visszamérésé nincs · nincs `schedule:` trigger egyetlen workflow-ban sem (`grep cron` → 0 találat; a `ci_prod_audit.yml:19` tudatosan indokolja a magáét) · A `REVIEW_INTERVAL_DAYS = 180` gondoskodik róla, hogy egy verdikt lejárjon, és a README büszkén állítja, hogy „a pipeline that stopped running would drive the pass rate to zero within 180 days" — de semmi nem méri újra automatikusan. A „Needs Re-run" halmaz csak nőhet, amíg valaki kézzel nem indít `workflow_dispatch`-et. A `select_unverified.py` + a dispatch `unverified` scope pontosan ehhez készült; hiányzik a heti/havi ütemezés `LAB_ONLINE`-tudatos kapuval (ami már létezik, és pont ezt a helyzetet kezeli offline lab esetén) → **Jamal**
- [x] **3.2** A prod-audit csak kézzel indul · `.github/workflows/ci_prod_audit.yml:19-22` · A „nincs schedule" indoklás (offline lab) helytálló volt, de a `LAB_ONLINE` gate azóta pont ezt a helyzetet kezeli máshol. Egy ütemezett futás `LAB_ONLINE != 'false'` feltétellel offline labnál is csak kihagyja magát — cserébe a „prod még az, aminek hisszük?" kérdés nem attól függ, hogy valakinek eszébe jut-e megkérdezni. Ugyanaz a minta, mint a 3.1, ezért érdemes egyszerre → **Jamal** · **Elutasítva, lásd Napló 2026-08-21**
- [x] **3.3** Egyetlen backend, és a második létezését csak szintetikus teszt bizonyítja · `config/backends.yml`, `tests/test_backend_config.py:106-148` · A régi register 3.7 kivette a backend-döntést a kódból adatba — a fájl saját kommentje szerint „a new backend is a new block below, and the converter's code path is unchanged". Ezt ma **semmi valódi futás nem támasztja alá**: a `config/backends.yml`-ben egyetlen `splunk` blokk van, a „több backend is működik" állítást pedig kizárólag a tesztfájlban felépített, kitalált `esql` / `elastic` konfiguráció támasztja alá — ami a *betöltőt* teszteli, nem a konverziót. Yara ugyanide jutott, és egy konkrét eszközt javasolt hozzá: egy kis CLI, ami kap egy backend-konfigurációt + mintaszabályokat, és megmondja, mi fordul le és mi nem. Ez egyszerre lenne a 3.7 falszifikálása és egy jövőbeli „adjunk hozzá Elasticet" kör önellenőrző eszköze → **Gaz** dönt hatókört, **Jamal** hajtja végre (a `scripts/convert/` mellé) · **Elutasítva, lásd Napló 2026-08-23**
- [x] **3.4** A verdikt csak azt méri, hogy „tüzelt-e" — a zajszintről nincs adat · `scripts/verify/pass_fail_eval.py` (`1 ≤ events ≤ 10`) · A README maga nevezi meg a korlátot („A PASS still only proves the search fired once, on one synthetic execution"). A lezárt register **4.1**-e (csendes ablak mérése) jó okkal lett elutasítva: a laborban nincs háttérforgalom. De a maradék rés más alakban is megfogható: pl. a saved search futásidejének / `scanCount`-jának rögzítése a verify során, ami a szabály *költségét* méri, nem az FP-arányát, és háttérforgalom nélkül is értelmes szám → **Yara** (formálás) → **Jamal** · **Elutasítva, lásd Napló 2026-08-23**
- [x] **3.5** A rule browser egyetlen 674 KB-os fájl, mindent előre betöltve · `docs/index.html` (674 590 bájt), forrás: `page.js` 2 878 sor / 128 KB, `page.css` 4 036 sor / 98 KB · 28 szabálynál ez működik; a növekedés viszont lineáris, mert a teljes szabálytest, a MITRE-mátrix, két history-idősor és a deployment-panel is beágyazottan utazik. Nincs mérés arról, hol a fájdalomküszöb — egy Lighthouse-futás (a `chrome-devtools` MCP-eszközök Sienna készletében megvannak) megmondaná, hogy ez ma probléma-e vagy csak később az → **Sienna**
- [x] **3.6** Nincs értesítés a pipeline eredményéről a GitHub felületén kívül · A PASS/FAIL verdikt ma a job exit-kódjában, a step summaryben és a promotion PR meglétében jelenik meg. Aki nem nézi az Actions fület, semmiről nem tud — arról sem, hogy 27 szabály hetek óta `NOT_VERIFIED` (1.5). Legolcsóbb forma: GitHub Issue automatikus nyitása/frissítése a lejárt+superseded halmazról, vagy bármilyen tartós felület a step summary helyett → **Jamal** (CI), **Kai** (ha issue/platform-oldali)
- [x] **3.7** A lefedettségi cél nincs adatként jelen · `outputs/reports/stats.json`: `mitre_covered_techniques: 12`, `mitre_total_techniques: 222`, `mitre_coverage_pct: 5,4` · A dashboard megmutatja, mi van; nem mutatja, mi lenne a cél, és milyen ütemben haladunk felé. A `coverage_history.json` és a `rule_growth_history.json` már gyűjti az idősort — hiányzik a szándék (célhalmaz, prioritás, „következő 5 technika") rögzítése adatként, amihez a trend mérhető. Ez az a pont, ahol Yara és Masha kimenete tényleges repo-artefaktummá válhatna → **Yara** (tartalom), **Sienna** (megjelenítés) · **Elutasítva, lásd Napló 2026-08-22**
- [x] **3.8** A szabálykönyvtár két taktika-családra szűkül, hét taktikán nulla szabály · gépi számlálás a 28 szabály `attack.*` tactic-tagjein: `execution` 14, `credential_access` 13, `stealth` 8, `persistence` 2, `defense_impairment` 2, `command_and_control` 1, `initial_access` 1, `discovery` 1 · A felső ATT&CK enterprise-taxonómiához mérve **hét taktikán nulla szabály van**: Reconnaissance, Resource Development, Privilege Escalation, Lateral Movement, Collection, Exfiltration, Impact. Teljes technika-lefedettség 12/222 (5,4%). Ez nem hiba — tudatos mélységi fókusz lehet —, de sehol nincs kimondva, hogy az, és a hét üres taktika kész felvételi lista a következő körhöz. Yara javaslata a sorrendre, amivel egyetértek: a **Privilege Escalation** és a **Lateral Movement** az a kettő, amihez a meglévő victim + DC labor-hostokon reálisan van valódi Atomic-teszt — vagyis ezekre nemcsak szabály írható, hanem a repo lényegét adó *élő verifikáció* is elvégezhető rajtuk. (Pontosítás Yara briefjéhez: a repo saját taktika-szótára nem azonos az upstream ATT&CK-kal — `stealth` és `defense_impairment` itt valós taktika, lásd a `mitre-attack-mapping` skillt —, tehát nyolc taktikán *van* szabály, nem kettőn; a koncentráció állítása viszont változatlanul áll.) → **Masha** (külső megalapozás) → **Yara** (priorizálás) → **Yuki** (megvalósítás), dokumentálva **Chloe** · **Elutasítva/hatókörön kívül, lásd Napló 2026-08-22** — a Privilegium-eszkaláció/Lateral Movement priorizálás mint háttér-tény változatlanul áll, ha a felhasználó egyszer maga felveszi, de a tétel nem register-követett feladat többé
- [x] **3.9** A publikált szám mellett nincs ott, hogy mikor mértek utoljára élesben · `README.md` badge-sor, `docs/index.html` Verification-gyűrű · Ma a `stats.json` (generálva 2026-08-17) 4% pass rate-et és 27/28 `NOT_VERIFIED`-et mutat, három nappal azután, hogy a régi register naplója egy valódi `LAB_ONLINE=true` futást rögzített 26 szabály éles history-jával. Aki csak a badge-et látja, romlásnak olvassa. Hiányzik egy „utolsó éles verifikáció: `<dátum>`, N/M szabály" jelzés közvetlenül a Pass Rate badge és a gyűrű mellett, plusz a rule browserben egy önkiszolgáló szűrő/jelvény a „újramérésre vár" halmazra, ami megkülönbözteti a *szerkesztés miatt felülírt* és az *elévült* esetet (az adat mindkettőre megvan a `stats.json`-ben). Yara ezt priorizálta a legmagasabbra a briefjében, és egyetértek a *javaslattal* — a diagnózisával nem (lásd a Naplót és az 1.5-öt: a mai 4% nem elévülésből jön, `verified_stale = 0`) → **Sienna**
- [x] **3.10** Nincs anonimizálás a publikusan letölthető diagnosztikai artifactban · `ci_dev_workflow.yml:1882` (`matched-events-sigma-<run_id>`, 14 napos retention, publikus repón bárki által letölthető) · A régi register **2.16**-a ezt a kockázatot megvizsgálta, és tudatosan a **rövidebb retenciót** választotta (90 → 14 nap) a mezőszűrés helyett — az indoklás jó volt (a nyers esemény maga a hibakeresési érték) —, de a tétel szövege maga nevezi meg, mi maradt kitéve: **a labor névtana** (gépnevek, domain, szolgáltatásfiókok). Egy verify és artifact-feltöltés közé illesztett eszköz, ami a labor-azonosítókat stabil, entitásonként konzisztens álnevekre cseréli (megőrizve az események közti korrelációt, tehát a debug-értéket is), pontosan azt a maradékot zárná le, amit a 2.16 nyitva hagyott. Yara javaslata, a register szövegével megerősítve. Önálló eszköz, nincs mai gazdája — a CI-ba **Jamal** kötné be → **Gaz** dönt gazdát
- [x] **3.11** Nincs eszköz egy találatszám-eltérés kivizsgálására · verifikálva a `outputs/results/DETECT-2026-0019/history.jsonl`-ből: ugyanaz a szabály négy futás alatt **FAIL (11 esemény) → NOT_VERIFIED (1) → FAIL (0) → NOT_VERIFIED (kikapcsolva)** három nap alatt, közben a `rule_version` 1.6-ról 1.7-re mozdult · A régi register **2.7**-e a globális `--max-pass 10` ablakot vizsgálta, és elutasítással zárult: a felső korlát rossz eszköz, mert az *attack-ablak* számából elvből nem derül ki, hogy a szabály túl tág-e vagy a technika generál tényleg annyi eseményt. Ez a következtetés áll — de a gyakorlati rés megmaradt: ha egy szám 11 lesz 10 helyett, ma **semmi nem mondja meg, melyik esemény volt a plusz egy**. Egy script, ami betölti egy szabály illeszkedett eseményeit és megmutatja, mely mező(k) mentén válik szét a halmaz, a mai „ismert flakiness"-t vizsgálhatóvá tenné. Yara javaslata; a register 2.7-hez fűzött indoklása pontosítva (nem „not-a-bug flakiness"-ként lett lezárva, hanem a felső korlát elvi elutasításaként) → **Jamal** (a `scripts/verify/` kiterjesztéseként), vagy önálló eszköz, ha külön akarjuk tartani a CI-tól
- [x] **3.12** Négy valódi, egymástól független, eddig nem követett accessibility-hiba, amit a 3.5 Lighthouse-mérése hozott felszínre · `scripts/docs/assets/page.template.html`, `page.css`, `page.js` · Mind a négy audit-tétel bukott (mobil + desktop preset), és egyik sem a szabályszámmal növekvő teher (nem a 3.5 hatóköre) — ma javítható, önálló hiba: **(1) `button-name`** — a drawer bezáró gombja (`button.drawer-close`, `onclick="closeDrawer()"`, `page.template.html:587`) ikon-only, `aria-label` nélkül; a minta ismert és helyesen alkalmazott máshol ugyanabban a fájlban (`.info-close`, `:61`, `aria-label="Close"`), csak erre a gombra nem lett átvezetve. **(2) `color-contrast`** — 4 elem bukik WCAG-kontraszton: `#strip-total` („28 rules" szöveg), a „MITRE Navigator" és „Dashboards" fül-gombok, és `#result-count` („28 / 28" szöveg). **(3) `landmark-one-main`** — nincs `<main>` landmark a dokumentumban sehol (`grep '<main' page.template.html` → 0 találat). **(4) `target-size`** (desktop nézet) — a szabálytáblázat MITRE taktika-pill jelvényei (`a.badge.badge-mitre`, `page.js:1583`, CSS `page.css:1134`) kb. 73×17–85×17 px méretűek, a WCAG 24×24 px érintési minimum alatt, szűken egymás mellett csomagolva. **Elhatárolás:** ez **nem** azonos a régi `remediation-plan.md` „amit ez az audit nem fedett" szakaszában rögzített, sosem újraellenőrzött sormagasság-hibával (badge-listás sorok `vertical-align: middle` miatti üres tere, `DETECT-2026-0022`-nél ~183px sor — az a hiba a *sor* magasságáról szól, ez a tétel a *jelvény* kattintható méretéről; szomszédos felület, a régi tétel máig nyitott/nem újraellenőrzött, ebben a körben sem lett vizsgálva) → **Sienna**
- [x] **3.13** A 3.12 javítása után új, korábban nem dokumentált `color-contrast` bukások jelentek meg más elemeken · `scripts/docs/assets/page.css`: `.filter-group-label`, `.filter-uniq`, `.filter-supergroup-title`, `.filters-generated`, `.kbd-hint`, és néhány verdikt-jelvény (`badge-category` / `badge-service` a szabálytáblázatban) · Sienna a 3.12 javítása után futtatott Lighthouse-újramérésben ezt az elemhalmazt 4,19–4,47:1 tartományban jelentette (WCAG AA 4,5:1 alatt) — **ez a fenti hatókörön kívül eső, mellékesen felfedezett hiba, amit a 3.12 szándékosan nem javított**, hogy ne táguljon menet közben a tétel hatóköre; ugyanaz a mintázat, mint ami a 3.5-ből a 3.12-t termelte. Kwame saját, a `docs/index.html` friss regenerálásán futtatott Lighthouse-mérése (desktop preset, ugyanaz a `color-contrast` audit) megerősíti, hogy a hiba valós és pontosan ezt a hat elemtípust érinti, de **tágabb tartományt mér, mint Sienna jelentése**: `.filter-group-label` / `.filter-uniq` / `.filter-supergroup-title` **3,52:1** (`#6e7681` / `#1c2128`), `.filters-generated` **3,76:1** (`#6e7681` / `#161b22`), `.kbd-hint` **4,11:1** (`#6e7681` / `#0d1117`), a verdikt-jelvények **4,19–4,47:1** (`#f85149` / `#332227` és `#38272c`, `#2ea44f` / `#1e302c`) — vagyis a jelvények tartománya egyezik Sienna számával, a `#6e7681` szövegszín (feltehetően egy `text3`-hoz hasonló, tompított token) viszont a háttértől függően ennél lényegesen rosszabb is lehet. A pontos kontraszt-arányokat és a jelenlegi színtoken-kontextust (melyik CSS-változó adja a `#6e7681`-et, milyen háttereken) a javítás előtt élőben érdemes újranézni, ne csak a fenti mérésekre hagyatkozva → **Sienna**

## 4 · Robusztusság és karbantarthatóság (8) · ×2

- [ ] **4.1** 1 827 sor inline shell a workflow-kban, ebből 1 263 a dev workflow-ban · `ci_dev_workflow.yml` 2 572 sor (1 005 komment, 1 263 inline `run:` shell), `ci_code_checks.yml` 252, `ci_prod_audit.yml` 175, `ci_prod_workflow.yml` 137 · Ez a repo legnagyobb tesztelhetetlen kódfelülete: unit-teszt nem éri el, csak a shellcheck látja (actionlinten keresztül) — az pedig szintaxist ellenőriz, nem viselkedést. A pipeline logikájának jelentős része itt él (verify-ablak számítása, commit-visszaírás retryvel, bundle-kezelés, provenance-ellenőrzés). Nem az egész kiszervezése a cél, hanem a leghosszabb, legtöbb elágazást tartalmazó blokkoké `scripts/ci/*.sh` vagy Python alá, ahol a pytest is látja őket. (Helyi megjegyzés: az actionlint Windowson beragad nagy `run:` blokkokon — a méret már ma is fáj.) → **Jamal**
- [x] **4.2** 7 500 sor front-end, nulla automatizált ellenőrzés · `scripts/docs/assets/page.js` (2 878), `page.css` (4 036), `page.template.html` (586) · A `ci_code_checks.yml` négy checkerje Pythont (ruff+pytest), PowerShellt (parser+PSScriptAnalyzer), workflow-YAML-t (actionlint+shellcheck) és függőséget (pip-audit) fed — JS/CSS/HTML-t **egyiket sem**. `grep eslint|stylelint|prettier|npm` a workflow-kban: 0 találat. Arányában: 3 400 sor Pythont 555 teszt véd, 7 500 sor front-endet semmi. Belépő szint: `eslint` minimál szabálykészlettel + HTML-validáció a generált oldalon, önálló jobként (hogy egy JS-hiba ne maszkolja a ruffot, a repo bevált mintája szerint) → **Sienna** (tartalom) + **Jamal** (job)
- [x] **4.3** A teszt-suite bukik a fejlesztő saját gépén · `python -m pytest` → **3 failed, 552 passed**, mindhárom a `tests/test_meta_only.py`-ban, hibaüzenet: `'No time zone found with key Europe/Budapest'` · Ok: a `scripts/convert/sigma_to_spl.py:334` `ZoneInfo("Europe/Budapest")`-et használ, Windows alatt viszont nincs rendszerszintű tzdata, és a `.github/requirements-dev.txt` (pytest, ruff) nem tartalmazza a `tzdata` csomagot. CI-ban (ubuntu) zöld, helyben piros — ez a legrosszabb fajta eltérés, mert a fejlesztőt arra tanítja, hogy a piros suite normális. Javítás: `tzdata` a dev-requirementsbe (és/vagy a sidecar időbélyegének UTC-re váltása) → **Jamal**
- [ ] **4.4** Hat különböző commit-visszaírási út, futásonként 3-4 gépi commit · `ci_dev_workflow.yml` (jelenleg 3 commit: összevont prune+SPL / verify results / dashboard — ld. Napló 2026-08-22), `ci_code_checks.yml` (1), `ci_prod_audit.yml` (1) · 894 commitból **256** (29%) `[skip ci]` gépi commit; a `docs/index.html`-t 185, az `outputs/`-ot 221 commit érinti. Következmény a napi munkára: a felhasználó minden helyi commit előtt rebase-elni kényszerül, mert a CI mindig elé ír (ez már rögzített projekt-tapasztalat). A történet ettől olvashatatlan is: egy valódi változtatás körül 3-4 zajcommit ül. Irány: egy futás = legfeljebb egy visszaírás (az `update_dashboard` amúgy is külön jobban fut, oda összevonható), vagy a generált artefaktumok kivezetése a branchről (Pages-artifact + release-asset), ami a 3.5-tel is összeér → **Jamal** ⟶ részlegesen lezárva (a biztonságos fele kész, a maradék nagyobb léptékű átalakítást igényel és nem közeli munka, ld. Napló 2026-08-22)
- [x] **4.5** A generátor központi függvénye 277 soros, és egyetlen tesztmodul importálja · `scripts/docs/generate_stats.py:863-1140` (`generate_stats()`), a fájl összesen 1 812 sor · A régi register **3.4 phase 1** kiszedte az inline HTML/CSS/JS literált (6 000 → 1 812 sor); a phase 2, a számítási mag szétbontása nem történt meg. Ez a függvény állítja elő egyszerre az összes publikált számot, a MITRE-lefedettséget, a README-blokkot és a history-idősorokat. Az 1.6 (tesztek) ennek a szétbontásával lesz olcsó, nem előtte → **Sienna**
- [x] **4.6** Három hard CI-kapu körül nincs teszt · `scripts/validate/validate_sigma.py` (a séma-kapu, amin minden szabály átmegy), `scripts/validate/check_detect_id_uniqueness.py`, `scripts/new_rule.py` · A `tests/` egyik modulja sem importálja őket (a `check_version_bump`, `check_test_routing`, `check_mitre_tags`, `check_spl_syntax` viszont mind fedve van, jól). A `new_rule.py` külön súlyos: a `sigma-rule-authoring` skill *minden* új szabályt ezzel indíttat, tehát a scaffold hibája minden jövőbeli szabályba beépül; a skill állítása („every placeholder already satisfies the schema, `validate_sigma.py` passes on the untouched skeleton") ma nincs teszttel bizonyítva, pedig pontosan egy ilyen `scaffold → validate` round-trip teszt írná le → **Jamal**
- [x] **4.7** Nincs UI-regressziós ellenőrzés, pedig az ügynök-szerződés előírja a manuálisat · `.claude/agents/Sienna - Frontend Engineer.md` („Verifies their own changes with Playwright before calling them done") · A Playwright-ellenőrzés így minden alkalommal kézi, egyszeri és nyomtalan: nincs elmentett snapshot, nincs CI-ban futó smoke-teszt, ami észrevenné, hogy egy `@@MARKER@@` kicseréletlenül maradt, egy doughnut nem renderelődik, vagy a Navigator-nézet elszáll. Egy egyszerű headless smoke (az oldal betölt, nincs console error, megvan a várt N szabálysor és a két gyűrű) a `ci_code_checks.yml`-ben megfogná a leggyakoribb regressziót → **Sienna** + **Jamal**
- [x] **4.8** A dashboard/Pages publikálás a Splunk-függő láncra volt kötve, csendben eldobva `LAB_ONLINE=false` esetén — utólag felvett, már lezárt tétel · `.github/workflows/ci_dev_workflow.yml` (a jelenlegi `update_dashboard`/`deploy_pages` job-pár, 5 kódkomment `[dashboard-decoupling]` néven hivatkozik erre a döntésre — ld. **2.10**) · A korábbi felépítésben a stats/README/`docs/index.html`-generálás a `splunk_verify` job része volt, a `deploy_pages` pedig `splunk_verify` sikeres eredményét várta; `LAB_ONLINE=false` (vagy bármilyen felsőbb hiba, ami kihagyja `deploy_to_splunk`-ot) esetén ez az egész lánc — `deploy_to_splunk` → `splunk_verify` → `deploy_pages` — kimaradt, tehát egy új/módosított szabály SPL-je bekerült a repóba, de a rule browseren **soha nem jelent meg**, még „Not Verified"-ként sem, amíg valaki kézzel újra nem futtatta a pipeline-t labor-visszaálláskor. **Megoldva `cb99a97`-ben (2026-08-14, „fix(ci): decouple dashboard/Pages publish from Splunk-dependent chain")**: a `generate_stats.py` hívás és a README/`docs/index.html` commit kikerült egy önálló `update_dashboard` jobba (`needs: [prepare_validate_convert, splunk_verify]`, `always()`), ami `LAB_ONLINE` állapottól és `splunk_verify` tényleges kimenetelétől (siker/skip/hiba) függetlenül lefut; a `deploy_pages` mostantól erre mutat a korábbi `splunk_verify`-függés helyett. Új/módosított szabály ma azonnal publikálódik, becsületes „Not Verified" / „Not deployed" státusszal, labor-állapottól függetlenül. A munka megtörtént és jó, csak sosem lett regisztrálva ebben vagy a lezárt registerben → **Jamal** (eredeti megvalósítás, `cb99a97`)

## 5 · A Claude-munkamodell mint fejlesztési folyamat (11) · ×1,5

Ez a szakasz azt vizsgálja, hogy a `CLAUDE.md`-ben leírt tizenegyfős
delegálási modell a gyakorlatban hozza-e, amit ígér. Rövid válasz: a
*szerepfelosztás* jó és látszik is a repón (a specialistánként szűk hatókör
tényleg jobb, reviewálhatóbb kimenetet adott), a *körülötte lévő gépezet*
viszont hiányos — a konfiguráció nagy része nincs a repóban, egy hook halott,
és a legfontosabb közös fájlokat senki nem birtokolja.

- [x] **5.1** A csapat saját operatív fájljai gazdátlanok · `CLAUDE.md`, `TEAM.md`, `.claude/agents/*.md`, `.claude/skills/*` · A roster-tábla minden sora egy-egy felületet nevez meg; egyik sem tartalmazza ezt a négyet. Chloe kifejezetten „README.md prose, `docs/architecture/*.md`, the GitHub Wiki"-t birtokol — a `TEAM.md`-t nem. Ennek közvetlen, mérhető következménye a 2.8 (két avatár létezik, a `TEAM.md` mind a tizenegyet „pending"-nek mondja) és az 5.5 (elavult tények az ügynökfájlokban). Javaslat: a `CLAUDE.md` kapjon egy explicit sort arról, ki tartja karban a roster-fájlokat — akár Chloe hatóköre bővül a `TEAM.md`-vel, akár Gaz tartja meg magának, csak legyen kimondva → **Gaz**
- [x] **5.2** A docs-drift hook olyan eseményre tüzel, amit a projekt konvenciója kizár · `.claude/settings.json:5-19`, `.claude/hooks/docs-drift-check.sh:22-26` · A hook a Bash-hívás payloadjában a `git commit` szövegre szűr, majd ellenőrzi, hogy tényleg landolt-e friss commit. Csakhogy a projekt álló szabálya az, hogy **a commitokat a felhasználó csinálja, nem az ügynök** — így az ügynök Bash-hívásaiban gyakorlatilag sosem szerepel `git commit`, és a hook a gyakorlatban soha nem fut le. A kód maga jó minőségű (determinisztikus, LLM-mentes, saját teszt-scripttel `.claude/hooks/test-docs-drift-check.sh`), csak rossz eseményhez van kötve. Helyesebb trigger: `PostToolUse` `Edit|Write` matcher a `scripts/**` és `.github/workflows/**` útvonalakra, vagy `Stop` hook, ami a munkamenet végén összegzi az érintett fájlokat → **Jamal** (a hook script), **Gaz** (a konvenció eldöntése)
- [x] **5.3** Nincs `permissions` blokk a `.claude/settings.json`-ben · `.claude/settings.json` (mindössze `attribution` + `hooks`) · Két külön veszteség. (a) *Hatékonyság*: nincs allow-lista a rutinparancsokra (`python -m pytest`, `ruff check`, `git status`, `git log`, `python scripts/validate/*.py`), tehát minden ügynök minden ellenőrző futása kézi jóváhagyást kér — pont az a művelet, amit a legtöbbször kell megismételni. (b) *Biztonság/konvenció*: a „Bence commitol, az ügynök nem" szabály ma csak emlékezetben és prózában él; egy `deny` bejegyzés (`Bash(git commit:*)`, `Bash(git push:*)`) gépiesen kikényszerítené. A repo egyébként pontosan ezt a filozófiát követi mindenhol máshol: ami szabály, az legyen kapu, ne emlékeztető → **Gaz**
- [x] **5.4** Nincs `.mcp.json` a repóban, három ügynök viszont MCP-eszközökre épül · `.claude/agents/Kai - Platform Engineer.md` (~40 `mcp__github__*` eszköz), `Priya - Application Security Engineer.md` (`mcp__semgrep__*`), `Sienna - Frontend Engineer.md` (`mcp__playwright__*`, `mcp__chrome-devtools__*`) · Ezek a szerverek felhasználói szinten vannak konfigurálva, nem a repóban (`find . -name .mcp.json` → nincs találat). Következmény: egy friss klónban (más gép, más felhasználó, vagy CI-környezet) ez a három ügynök csendben elveszti az eszközkészlete nagy részét — nem hibaüzenettel, hanem úgy, hogy a képességei egyszerűen nincsenek ott. Egy projektszintű `.mcp.json` (a titkokat környezeti változóból olvasva) tenné a csapatot hordozhatóvá; ahol ez nem megy (pl. felhasználóhoz kötött auth), ott legalább dokumentálva kellene lennie, mit kell egyszer beállítani → **Gaz** dönt, **Kai** hajtja végre
- [x] **5.5** Elavult tények az ügynökfájlokban — és senki nem nézi őket rendszeresen · `.claude/agents/Kwame - Compliance Analyst.md` („last known count: 54 items, 43 done" — a register azóta 54/54 és lezárt), `Jamal - DevOps Engineer.md` (háromsoros workflow-tábla, a negyedik workflow hiányzik; a `ci_prod_workflow.yml` sora „Re-converts, drift-gates, deploys" — mindkettő megszűnt, lásd 1.1), `Bjorn - …md` (a megszűnt `rule_documentations/` könyvtár), `Priya - …md` (pontos telepítési útvonalak és MCP-elérhetőség, saját „confirm current state yourself, environments drift" kitétellel) · Ezek nem kozmetikai hibák: az ügynökfájl az első dolog, amit a diszpécselt specialista elolvas, tehát minden ilyen mondat egy hamis kiindulópont minden jövőbeli futásban. Kwame sajátja külön ironikus: a register-auditáló ügynök leírása maga elavult a registerhez képest. **Yara ugyanide jutott, egy fokkal általánosabban**, és a hiányzó *mechanizmust* nevezte meg: a `remediation-plan.md`-t Kwame állandó jelleggel ellenőrzi a valósággal szemben, az ügynökdefiníciókat viszont **semmi és senki** — nincs az a szerep, ami ezekre nézve játszaná Kwame szerepét. A tétel ezért kettős: (a) a mai konkrét elavulások javítása, (b) egy visszatérő „ügynökfájl-spot-check" beépítése valamelyik meglévő audit-körbe, hogy ne kelljen újra egy teljes átvizsgálás ahhoz, hogy kiderüljön → **gazdátlan, lásd 5.1**; a visszatérő ellenőrzés természetes helye **Kwame** köre
- [x] **5.6** Megosztott, gyorsan avuló tudás perszóna-fájlokba égetve, nem skillbe · `.claude/skills/` ma három skillt tartalmaz: `sigma-rule-authoring`, `mitre-attack-mapping`, `team-avatars` · Mindhárom a szabály-szerzés / kozmetika körül forog. A commit-történet szerint viszont a munka zöme a pipeline-on (Jamal) és a rule browseren (Sienna) folyik, és ezeknek a konvenciói ma kizárólag 1 005 sornyi workflow-kommentben és az ügynökfájlok prózájában élnek — vagyis minden diszpécselés újra levezeti őket. **Yara adta hozzá a döntési szabályt, ami ezt élessé teszi:** ha egy perszóna-fájl saját szövege azt mondja, hogy „ezt ellenőrizd, mielőtt megbíznál benne" (szó szerint ez áll Priya környezet-bekezdésében), az pont az a pont-idejű, avuló tudás, amit a skill-mechanizmus izolálni hivatott — perszóna-fájlba égetve minden jövőbeli szerkesztésbe belemásolódik az elavulás. Konkrétan hiányzó skillek: (a) **`pipeline-ci-gotchas`** — Jamal fájlja (`:29-30`) két olyan csapdát dokumentál, amelyek saját bevallása szerint már okoztak valódi hibát (a `changes` step üres szabálylistája → minden downstream job kimarad, a run mégis zöld; és a `--diff-filter=AMRC`, ami a törléseket kizárja) — ez a tudás ma **láthatatlan** Priya (CI-konfigurációt auditál) és Kwame (pipeline-állításokat verifikál) számára, hacsak külön újra fel nem fedezik; (b) **rule-browser generátor-konvenciók** (a `docs/index.html` build-artefaktum, `@@MARKER@@` behelyettesítés, asset-inline-olás, normalizált diff-összehasonlítás) — ide tartozik a 2.12-ben hiányzónak talált `dataviz` is; (c) **audit-register konvenciók** (ennek a fájlnak a formátuma, súlyozás, naplóbejegyzés). Yara egy megjegyzése ide tartozik ellensúlyként: a `team-avatars` a három meglévő közül az egyetlen, ami nem szabály-helyességet kapuz — ha a skill-készlet karbantartása később teherré válik, ez az, amit a legkönnyebb visszaolvasztani egy egyszeri beszélgetésbe → **Gaz** dönt, tartalom a felület gazdájától
- [x] **5.7** A `team-avatars` skill kimenete félkész és nincs bekötve · `.claude/skills/team-avatars/SKILL.md` · A skill precízen definiálja a stílus-lockot és a fájl helyét, de a tizenegy fős rosterből két avatár készült el, azok is a skill saját elnevezési szabályát megsértve, és egyik sincs bekötve a `TEAM.md`-be (lásd 2.8). Ez a legtisztább példa arra, amit az 5.1 leír: van skill, van kimenet, nincs gazda, aki végigvinné → **Gaz** dönt (befejezni vagy tudatosan lezárni „két avatár elég" indoklással)
- [x] **5.8** Nincs `.claude/commands/` — a visszatérő műveletek nincsenek parancsba zárva · A repóban ma nulla slash-parancs van. Legalább négy művelet ismétlődik felismerhetően: register-állapot ellenőrzése, dashboard/statisztika helyi újragenerálása + normalizált diff, teljes lokális kapu-futtatás (ruff + pytest + validate + check_mitre_tags), és új szabály scaffoldolása a review-átadásig. Mindegyik ma prózából kerül újra összerakásra minden alkalommal → **Gaz**
- [x] **5.9** Kwame eszközkészletében nincs `Write` · `.claude/agents/Kwame - Compliance Analyst.md` frontmatter: `tools: Read, Grep, Glob, Bash, Edit` · A szerepdefiníció szerint Kwame „reports accurate progress" és vezeti a registert — de új auditdokumentumot létrehozni nem tud, csak meglévőt szerkeszteni. Ez a dokumentum is `printf`-fel létrehozott helyőrző-fájl + `Edit` kerülőúton készült. Vagy a `Write` kerüljön be az eszközök közé, vagy legyen kimondva, hogy Kwame kizárólag meglévő registert könyvel, és új auditfájlt más hoz létre → **Gaz**
- [x] **5.10** A modellválasztási szabály nem mérhető és nem visszakövethető · `CLAUDE.md` 7. pont · A szabály jó (komplexitás-alapú eszkaláció dispatchenként, nem szerepenként), de semmilyen nyoma nem marad annak, melyik diszpécselés futott melyik modellen, tehát utólag nem lehet megmondani, hogy a szabály segít-e vagy sem. **Kwame és Yara egymástól függetlenül ugyanezt emelte ki**, és Yara pontosítása helytálló: ez futásidejű döntés, nem repo-artefaktum, tehát nem is lehet fájlban kikényszeríteni — amit viszont lehet, az a *nyom*. Legolcsóbb forma: a specialisták zárójelentése nevezze meg a modellt egy sorban, és a nagyobb körök (mint ez az audit) rögzítsék a Naplóban. Ez pontosan a repo saját „bizonyíték az állítás helyett" kultúrája, csak a folyamatra alkalmazva → **Gaz**
- [x] **5.11** A méret- és feltételfüggő elhalasztott döntéseknek nincs követett listája · a régi register négy tételt zárt le a *jelenlegi lépték* miatt: **3.8** (alkönyvtár-bontás), **4.1** (noise budget), **4.4** (Splunk ES / RBA), **4.11** (tömeges újramérés) · Mindegyik indoklása valós kiváltó feltételt tartalmaz, de az sűrű prózába temetve — senki nem figyeli, mikor lépjük át. Yara javaslata egy „lépték-függő döntések" tábla (tétel / mai mutató / küszöb / mi változik), ami Kwame következő körén gépiesen ellenőrizhető. Jó ötlet, **de a négy példa közül kettő pontosításra szorul**, és ez a pontosítás a tábla lényege: a **4.11** küszöbe valós és idézhető (a felhasználó a tömeges újramérést kifejezetten azzal utasította el, hogy „500+ szabálynál nem skálázna"); a **3.8**-é viszont **nem** — a register szó szerint rögzíti, hogy a „27 szabály még kezelhető, 150-nél nem" állítás rákérdezésre kiderülten *sosem volt alátámasztva*, tehát a 150-es szám nem küszöb, hanem visszavont feltevés, és a táblába is így kell bekerülnie, különben egy elvetett számot élesztünk újra. A **4.1** és a **4.4** pedig nem lépték-, hanem **feltételfüggő**: az egyik akkor nyílik újra, ha a labor Splunkja valódi háttérforgalmat kap, a másik akkor, ha telepítenek ES-t vagy megjelenik egy második üzemeltető. A tábla tehát „lépték- és feltételfüggő döntések" legyen, három oszloppal: mi a kiváltó, mérhető-e ma, és hol áll → **Kwame** (könyvelés), **Yara** (keretezés)

## 6 · Amit ez az audit nem fedett

Nem munkatételek, hanem a lefedettség őszinte korlátai. Bármelyik külön kör lehet.

- **A 28 szabály detekciós logikájának tartalmi minősége.** Csak a metaadat-teljesség lett
  gépiesen ellenőrizve (referenciák, falsepositives, `version`, leírás-hossz — ezek rendben
  vannak, egy fixtúra kivételével). FP-kockázat, átfedések, ATT&CK-tag helyesség → **Bjorn**.
- **A rule browser futó viselkedése.** A front-end csak forrásszinten lett nézve; nem futott
  Playwright, nincs accessibility-, perf- vagy Lighthouse-mérés. A 3.5 és a 4.7 ezt a rést
  nevezi meg, de maga a mérés még hátravan → **Sienna**.
- **Az élő CI-futások logjai és a flakiness-minták.** Minden megállapítás a repo statikus
  állapotán és helyben futtatott ellenőrzéseken alapul (`pytest`, `git log`, fájlszintű
  mérések). A run history-t ez az audit nem nyitotta meg.
- **A Splunk tényleges állapota (dev és prod).** A `LAB_ONLINE`-függő rész nem volt elérhető,
  tehát minden telepítés- és verifikáció-oldali megállapítás repo-oldali következtetés.
  Külön: a `ci_prod_audit.yml` sosem futott ebben az auditban.
- **Mélységi biztonsági szkennelés.** Nem futott semgrep, sem pip-audit ebben a körben; a
  biztonsági dimenzió pontszáma a konfiguráció olvasásán alapul (SHA-pinelt actionök,
  self-hosted runner fork-védelme, titkok kezelése), nem szkennelésen → **Priya**.
- **Külső CTI-megalapozás a 3.8-hoz.** Melyik üres taktikát érdemes valóban előrevenni, az
  külső fenyegetettségi adaton múlik, nem belső hiánylistán — ez a kör csak azt állapította
  meg, hol van a lyuk, nem azt, melyik ér a legtöbbet → **Masha**.
- **A perszóna-fájlok környezeti állításai (5.5b).** Azt ellenőriztem, hogy *melyik* állítás
  avult el a repo tényeihez képest; azt **nem**, hogy Priya fájljának telepítési útvonalai
  (semgrep, pip-audit, PDF-eszközök hiánya) ma igazak-e a felhasználó gépén — az a repóból
  nem eldönthető.

## 7 · Amit ne rontsunk el

- **A kód kommentkultúrája.** A workflow- és scriptkommentek konkrét run ID-kkal, elutasított
  alternatívákkal és empirikus bizonyítékokkal indokolják a döntéseket. Az 1.1 tétel épp azért
  fájdalmas, mert a `.github/requirements.txt` és a `requirements-deploy.txt` fejléce
  **pontosan** leírja az új prod-modellt — a kód tudja, csak a dokumentáció nem. A javítás
  iránya tehát a kommentekből a docs felé, nem fordítva.
- **A `NOT_VERIFIED` megkülönböztetése a `FAIL`-től.** A progress-marker mechanizmus és az
  `error_kind` osztályozás a repo egyik legérettebb része. Az 1.5 nem ezt akarja visszavonni,
  hanem továbbvinni ugyanazt a gondolatot egy negyedik esetre („nem is akartuk mérni").
- **A tesztek mennyisége és minősége a Python-oldalon.** 555 teszt, faked Splunkkal, valódi
  határeset-lefedettséggel. A 4.6 és az 1.6 rések ebben a keretben pótolhatók, nem helyette.
- **A specialistánként szűk hatókör.** Az 5. szakasz kritikái a modell *körüli* gépezetről
  szólnak, nem magáról a felosztásról — az láthatóan működik, és a `CLAUDE.md` 3. pontjának
  indoklása („narrower scope has produced better, more reviewable results here") a commitokon
  is látszik.
- **Az elutasítás mint érvényes lezárás.** A régi register négy tételt zárt le elutasítással,
  mérésre hivatkozva. Ez a kultúra tartsa magát ebben a körben is: nem minden tétel javítandó.
  Az 5.11 épp ezt védi: az elutasított tétel akkor ér valamit, ha a *feltétele* is rögzítve
  van — de attól még elutasított marad, amíg a feltétel nem teljesül.
- **Maga a register mint műfaj.** A `remediation-plan.md` bevált mintája (tételenkénti
  bizonyíték, súlyozott mérő, napló, elutasítás-mint-lezárás) az az artefaktum, ami ezt a
  repót együtt tartja — Yara külön kiemelte pozitív mintaként, és ez a dokumentum is azért
  ebben a formában készült. Új döntés-kategóriákra érdemes ugyanezt alkalmazni, nem újat
  kitalálni.

---

## 8 · Lépték- és feltételfüggő döntések — élő figyelőlista

Nem munkatételek. A lezárt `remediation-plan.md` négy tételt zárt le arra
hivatkozva, hogy a mai lépték vagy a mai környezeti feltétel nem indokolja a
megvalósítást — nem azért, mert az ötlet rossz, hanem mert *ma* nincs mihez
mérni vagy mekkora skálán érdemes. Ez a tábla az, amit **5.11** kért: azt
tartja számon, mikor kellene ezeket újranyitni, hogy ne kelljen a döntést
minden körben a sűrű register-prózából újra kibányászni. Yara állította
össze, `remediation-plan.md`-t közvetlenül olvasva, nem parafrázisból;
Kwame ellenőrizte a forrásidézeteket a mai bookkeelésnél. **Kwame feladata
ezt minden jövőbeli register-körben újranézni** — a 4.1/4.4a sorok nem
git-ből deríthetők, ott a felhasználót kell direktben megkérdezni, nem
grep-elni.

| Tétel | Kiváltó (a lezárt register saját szövege szerint) | Mérhető-e ma valós számmal/megfigyeléssel? | Mai státusz |
|---|---|---|---|
| **4.11** — tömeges újramérés / promóciós gate | Felhasználói kijelentés: „nem skálázna 500+ szabálynál" (`remediation-plan.md:186`) | Igen — kemény szám, közvetlenül számolható a `rules/sigma/`-ból | Messze a küszöbtől. Ma 28 szabály, a legutóbbi lezáráskor 27 volt. ~18x tartalék a kimondott küszöbig. |
| **3.8** — flat szabálykönyvtár | **Nincs.** A „27 kezelhető / 150 nem" szám rákérdezésre kiderülten sosem lett alátámasztva — visszavont feltevés, nem elfogadott küszöb (`remediation-plan.md:171`, Napló `:1134`) | N/A — nincs mihez mérni | Nincs nyitott kiváltó. A repo ma is flat (ellenőrizve: nincs alkönyvtár a `rules/sigma/` alatt). Ez a sor kifejezetten azért van itt, hogy senki ne élessze fel a „150"-et küszöbként — a 3.8 újranyitásának egyetlen valódi útja, ha a felhasználó explicit könyvtár-alapú kategorizálást kér, ami preferencia-váltás, nem lépték-esemény. |
| **4.1** — noise/false-positive budget | A labor Splunkja valódi, szervezetlen háttérforgalmat kezd kapni attack-teszt ablakokon kívül (`remediation-plan.md:176`) | Nem — nincs számszerű küszöb, egy bináris üzemeltetési tény, ami a repo fájljaiból nem vezethető le | Változatlan a 2026-08-15-i lezárás óta, a repóból nem ellenőrizhető. Ugyanaz a drift-osztály, mint a `LAB_ONLINE` (projektmemória: beragadt `true`-n, nincs automatizmus, ami pontosan tartaná) — ez a sor nem grep-elhető, minden körben direkt kérdés a felhasználónak. |
| **4.4a** — Splunk ES / RBA mezők a deploy payloadban | Splunk Enterprise Security ténylegesen települ a laborban (`remediation-plan.md:179`) | Részben — a repo-oldali proxy grep-elhető (`notable`/`risk_object`/`risk_score` hivatkozás, ma nulla találat), de a valódi tény (van-e ES telepítve) a repón kívül dől el | Nem triggerelt a legutóbbi ellenőrzéskor, ugyanaz a külső-tény fenntartás, mint 4.1-nél. |
| **4.4b** — riasztás-throttling / drilldown mezők | SOC vagy több-üzemeltetős kontextus jelenik meg (`remediation-plan.md:179`) | Nem — kvalitatív, nincs figyelendő szám | Nem triggerelt. A repo ma is egyszemélyes. |

**Miért 4.4a/4.4b két külön sor, nem egy:** a lezárt register `remediation-plan.md:179`-ben a **4.4** két, minőségileg független dolgot bundlézott — az ES/RBA fél attól függ, hogy valaha települ-e Splunk ES, a throttling/drilldown fél attól, hogy valaha megjelenik-e SOC vagy több üzemeltető. A kettő egymástól függetlenül nyílhat újra (ES telepítése önmagában nem hoz SOC-ot, és fordítva), tehát egy közös sor elmosná, melyik feltétel teljesült. **Pontosítás, amit Yara saját maga vett észre és javított a dispatch-brief-jében, mielőtt ez a tábla elkészült:** a termék neve **Splunk Enterprise Security (Splunk ES)**, nem Elastic Security — más gyártó, más termék; a `remediation-plan.md:179` szövege explicit ezt mondja.



- **2026-08-18** — Audit elvégezve (`dev @ d17ff7e`), 42 tétel rögzítve öt kategóriában,
  teljes súly 70, kiindulási pontszám 7,0/10. Semmi nincs még javítva. A kör Gaz felkérésére
  készült, a felhasználó (Bence) első körös kérésére: funkciók, fejlesztési lehetőségek,
  dokumentációs hiányok, és külön kérésre a Claude-munkamodell hatékonysága.
  Módszer: statikus átvizsgálás + futtatott ellenőrzések (teljes `pytest`-futás, `stats.json`
  és a 28 `result.json` beolvasása, szabály-metaadatok gépi átfésülése, workflow-k
  sor/komment/inline-shell szerinti mérése, dokumentum-lefedettség grepelése script- és
  jobnevekre). A három legsúlyosabb megállapítás mind ugyanabból a családból jött:
  a dokumentáció a 3.2-es register-tétel *előtti* prod-modellt írja le (1.1), a negyedik
  workflow egyetlen dokumentumban sem szerepel (1.2), és a publikált számokat semmilyen teszt
  nem védi (1.6). A Claude-oldali szakasz legélesebb egyedi találata az 5.2: a docs-drift hook
  a `git commit` eseményre tüzel, amit a projekt saját konvenciója (a commitokat a felhasználó
  csinálja) gyakorlatilag kizár — a hook jó kód, halott triggerrel.
  **Modell:** ez a kör Opus 5-ön futott (lásd 5.10).

- **2026-08-18 (revízió, ugyanaznap)** — Yara stratégiai briefjének beolvasztása. A két
  átvizsgálás egymás kimenetének ismerete nélkül készült, ami használható kontrollt adott:
  **két teljes átfedés** volt (a `TEAM.md` avatár-drift → 2.8, és a modellválasztási szabály
  visszakövethetetlensége → 5.10), plusz **három részleges** (a skill-hiány kérdése → 5.6, a
  backend-absztrakció bizonyítatlansága → 3.3, a lefedettségi koncentráció → 3.8). Ezek
  egyesítve lettek, nem duplikálva. Hét új tétel került be: **2.12** (`dataviz` skill-hivatkozás
  a semmibe), **2.13** (`agent_workflow.md`), **2.14** (`CONTRIBUTING.md`), **3.9** („utolsó
  éles verifikáció" kontextus), **3.10** (artifact-anonimizáló), **3.11** (találatszám-triázs
  eszköz), **5.11** (lépték- és feltételfüggő döntések táblája). A teljes súly 70 → **79**,
  a tételszám 42 → **49**; a kiindulási pontszám **7,0** maradt.

  **Yara három állítása ellenőrzésen módosult, ezért a tételek a verifikált változatot rögzítik:**
  (1) A brief legmagasabbra priorizált tétele a mai 4%-os pass rate-et „szinte biztosan" a
  dokumentált elévülési mechanikának (LAB_ONLINE, `version:`-bump) tulajdonítja — ez **téves**:
  a `stats.json` szerint `verified_stale`, `verified_superseded` és `verified_expired` mind
  **0**, egyetlen verdikt sem évült el. A tényleges ok az `ef39dce` commit, ami 27 szabályon
  kikapcsolta a tesztelést, és a keletkező `NOT_VERIFIED` bennmarad a pass rate nevezőjében
  (1.5). A *javaslata* (utolsó-éles-mérés jelzés) ettől függetlenül jó, ezért 3.9-ként bekerült.
  (2) A brief a 3.8-as register-tétel „~150 szabály" küszöbét élő figyelendő értékként kezeli;
  a register szövege viszont épp azt rögzíti, hogy ez az állítás rákérdezésre kiderülten sosem
  volt alátámasztva — küszöb helyett *visszavont feltevés*, és az 5.11 így is írja le.
  (3) A brief a 2.16-os artifact-kockázatot és a 2.7-es találatszám-kérdést pontatlanul
  keretezi (a 2.7 nem „ismert flakiness"-ként lett lezárva, hanem a felső korlát elvi
  elutasításaként) — a mögöttes hiány viszont mindkét esetben valós, sőt a 3.11-et a
  `DETECT-2026-0019` `history.jsonl`-je meg is erősíti: FAIL(11) → NOT_VERIFIED(1) → FAIL(0)
  → kikapcsolva, három nap alatt. Ellenőrizve és megerősítve lett viszont mind a `dataviz`
  hivatkozás (`grep`: nulla skill ilyen néven), a `CONTRIBUTING.md` hiánya, a Jamal-fájl két
  CI-csapdája (`:29-30`), a 2.16 által nyitva hagyott labor-névtan, és a backend-tesztek
  szintetikus volta (`tests/test_backend_config.py:106-148`).

  **A dokumentum ezzel v1.0, lezárt kiadás.** A következő módosítás már tétel-végrehajtás
  könyvelése legyen, ne szerkezeti átdolgozás.

- **2026-08-20** — **1.4 elutasítva.** A két érintett fixtúra (`DETECT-2026-0003_Test3.yml`,
  `DETECT-2026-0032_Pipeline-Test-Rule-…yml`) mindkettő szándékosan és tartósan
  `status: test` — nem fejlesztés alatt álló, hamarosan éles szabály, hanem önmagát
  annak valló pipeline-önteszt fixtúra (`DETECT-2026-0032` leírása szó szerint: „Not
  intended as production detection coverage"). A felhasználó (Bence) megerősítette,
  hogy idővel törli mindkettőt. Ellenőrizve: egyik fájlra sem támaszkodik valódi pytest
  (a `tests/test_resolve_rule_selection.py` egy azonos ID-jú, de független szintetikus
  fixtúrát használ) — a `check_version_bump.py:30` kommentje viszont névvel hivatkozik
  a `DETECT-2026-0003_Test3`-ra mint a `raw_query`-bypass egyetlen dokumentált példájára;
  ez a törléskor elavul, frissítést igényel majd (nem ennek a tételnek a hatóköre). A
  `generate_stats.py` `status`-szűrésének strukturális hiánya (a mögöttes ok, ami bármely
  jövőbeli `status: test` szabályra is vonatkozna) tudatosan **nyitva marad** — a
  felhasználó nem kért rá védőhálót, csak a két konkrét fájl eltűnését. Nincs végrehajtó.

- **2026-08-20 — 1.5 megvalósítva (Sienna, opus).** `generate_stats.py`: `load_verdicts()`
  most átemeli a `pass_fail_eval.py` által már ma is írt `result.json`-beli `disabled` mezőt;
  két új számláló (`verified_testing_disabled`, `verified_testing_disabled_current`); a
  denominátor a `_current` változattal csökken. **Tervtől eltérés, indokolt:** a teljes
  `verified_testing_disabled` (27) közvetlen kivonása a nevezőből visszahozta volna a
  hibát más alakban — egy `disabled` verdikt a `REVIEW_INTERVAL_DAYS` lejárta után *stale*-lé
  is válik, tehát dupla levonás negatív nevezőt adott volna pár hét múlva. A `_current`
  változat csak azokat vonja le, amik még nem évültek el stale-ként — Sienna szintetikus
  200-napos backdate-teszttel ellenőrizte, hogy nincs dupla számolás.
  Valós adaton: `verified_current` 28→1, `pass_rate_pct` 4%→100%, `verification_current_pct`
  100%→4% (a lefedettség és a helyesség két külön tengelye helyet cserélt, ahogy kell — a
  27 szabály hatókört költ, nem helyességet). Egyetlen meglévő badge-kulcs sem változott
  (shields.io-kompatibilitás megtartva). A rule browserben új "Out of testing scope" evidence-
  szegmens (`⊘` jelölés, kontraszt-validált narancs `#db6d28`, ΔE 15.3-17.5 a `dataviz` skill
  validátora szerint), README-blokk a badge-sor alatt. JS/Python-egyezés Node-dal
  ellenőrizve (`{current: 1, scoped: 27}` mindkét oldalon).
  **Nem történt meg:** böngészős (Playwright) vizuális ellenőrzés — nem volt rá felhatalmazás
  a dispatchben; a `pipeline_overview.md:276` és `data_flow.md:93` a régi (most hiányos)
  `verified_current` képletet dokumentálja — Chloe hatásköre, a felhasználó kérésére most
  nem nyúltunk hozzá (dokumentáció-fókusz később, a nagy audit körül).

- **2026-08-20 — 4.3 megvalósítva (Jamal).** `.github/requirements-dev.txt`: `tzdata==2026.3`
  felvéve, a fájl meglévő `==` pin-stílusát követve, kommenttel indokolva (Windows-nak nincs
  OS-szintű IANA tzdata a `zoneinfo` mögött, a Linux CI-runnerekkel ellentétben). A
  `sigma_to_spl.py:334` `ZoneInfo("Europe/Budapest")` hívása változatlan. Ellenőrzés: izolált
  venv-ben telepítve, `zoneinfo.reset_tzpath(to=[])`-pal mesterségesen szimulálva a Windows-
  ekvivalens állapotot (OS-szintű zoneinfo-útvonalak törölve) — a pip `tzdata` csomag
  önmagában, OS-segítség nélkül is feloldotta a zónát. `tests/test_meta_only.py`: 4/4 zöld
  (a jelentés szerint korábban Windows alatt 3 bukott ebből). Teljes suite: 555/555 zöld.
  **Korlát, amit maga jelzett:** a tényleges Windows-hibát nem tudta reprodukálni (Linux
  gépen fut, ahol az OS-szintű tzdata amúgy is elfedi a hibát) — a szimulált ellenőrzés
  funkcionálisan egyenértékű, de nem valódi Windows-futtatás. Nincs commit.

- **2026-08-20 — 1.6 megvalósítva (Sienna).** Új `tests/test_generate_stats_math.py`, hat
  teszt — ez az első, ami magára a `generate_stats()` matekjára fut, nem csak a
  deployment-panel segédfüggvényére. Minden layer-2 kulcsra assertion (tíz szintetikus
  szabály minden verdikt/staleness-kombinációval), plusz kifejezetten az 1.5-ben talált
  dupla-levonás regresszióra (`disabled: true` + 200 napos NOT_VERIFIED →
  `verified_stale=1, verified_expired=1, verified_testing_disabled=1,
  verified_testing_disabled_current=0`, `verified_current` sosem negatív), plusz a
  180 napos küszöb három határesete (179/180/181 nap, `>=` rögzítve). **Valódi
  regressziós próba:** szándékosan elrontotta a kódot kétszer (a `>=`-t `>`-ra cserélve,
  majd a `_current` levonást a teljes `verified_testing_disabled`-re), mindkétszer
  pontosan az új tesztek buktak (az utóbbi a megjósolt negatív nevezőt is megmutatta),
  utána mindkét törést visszavonta — `git diff` szerint a `generate_stats.py`-ban nincs
  tőle származó változás, csak az új tesztfájl. Teljes suite: 561/561 zöld (555 régi + 6
  új). Nincs commit.

- **2026-08-20 — 5.3 megvalósítva (Gaz, `update-config` skill).** `.claude/settings.json`
  (projekt-szintű, nem local): új `permissions` blokk. `allow`: `python -m pytest *`,
  `ruff check *`, `git status *`, `git log *`, `python scripts/validate/*` — a négy
  megnevezett rutinparancs, a validate könyvtár teljes egészére (nem csak egy fájlra).
  `deny`: `git commit *`, `git push *` — a "Bence commitol, az ügynök nem" szabály mostantól
  gépi kapu, nem csak minden dispatchbe kézzel beírt utasítás. JSON szintaxis `jq`-val
  ellenőrizve. A meglévő `attribution` és `hooks` blokk változatlan, merge-elve, nem
  felülírva.

- **2026-08-20 — 4.2 megvalósítva, szűkített hatókörrel (Jamal).** A felhasználó a három
  felkínált opció közül a legkisebb CI-felületűt választotta: nincs új job, nincs npm/eslint,
  csak egy új lépés a meglévő `static_analysis` jobban (`ci_code_checks.yml`) —
  `actions/setup-node@v5.0.0` (SHA-pinelve) + `node --check` a `page.js`-en, tisztán
  szintaxis-ellenőrzés. Mindkét új lépésen `if: ${{ !cancelled() }}`, hogy egy korábbi
  Ruff/Pytest-bukás ne némítsa el csendben — ugyanaz a minta, amivel a fájl saját maga
  indokolja, miért lett a PowerShell- és workflow-ellenőrzés külön job (csak itt lépés-szinten
  oldva meg, job helyett, a felhasználó kérésére). **Talált és önállóan kezelt akadály:** a
  `page.js` nem önálló JS — 14 db `@@TOKEN@@` placeholdert tartalmaz, amit csak a
  `generate_stats.py` helyettesít be a `docs/index.html`-be ágyazáskor. A szó szerint kért
  `node --check scripts/docs/assets/page.js` a committolt fájlon **garantáltan mindig bukna**,
  a tényleges kódminőségtől függetlenül. Jamal ezt egy `$RUNNER_TEMP`-beli, eldobható
  másolaton oldotta meg: minden `@@TOKEN@@`-et szintaktikailag érvényes helyettesítővel
  cserél ellenőrzés előtt (a követett fájlhoz nem nyúl), így a valódi szintaxishibákat továbbra
  is elkapja. Ellenőrzés: tiszta futás zöld; szándékosan elrontott szintaxis (hiányzó zárójel)
  nem-nulla exit kóddal bukott, majd pontosan visszaállítva; a módosított workflow-t
  `actionlint 1.7.12` + `shellcheck 0.10.0` (a repo által is használt, SHA-ellenőrzött verziók)
  hiba nélkül validálta. Hatókör betartva: `page.css`/`page.template.html` nem érintett, nincs
  `continue-on-error`, nincs linter/`package.json`.

- **2026-08-20 — 3.1 elutasítva.** A felhasználó (Bence) indoklása: a lab-környezet
  jellemzően offline (a `LAB_ONLINE` gate amúgy is kihagyná a legtöbb cron-futást), és a
  180 napos elévülés láthatósága már ma is megoldott — a dashboard mutatja, mikor jár le
  egy adott szabály verdiktje. Automatikus ütemezés helyett a meglévő kézi
  `workflow_dispatch` + `scope: unverified` marad a mechanizmus, amikor a lab ténylegesen
  online van. A tétel emellett érdemben nagyobb munka lett volna, mint amit a súlya
  indokolt: legalább tíz `if: (github.event_name == 'push' || 'workflow_dispatch')`
  feltétel bővítése kellett volna a `ci_dev_workflow.yml`-ben ahhoz, hogy egy `schedule`
  trigger egyáltalán lefuttasson bármit. Nincs végrehajtó.

- **2026-08-20 — 3.9 megvalósítva (Sienna).** `generate_stats.py`: új `_last_live_verification()`
  segédfüggvény — a ténylegesen megmért (nem `disabled`, nem never-tested) verdikteket
  `run_id` szerint csoportosítja, és a legfrissebb futás időbélyegét + darabszámát adja
  vissza. Két új, tisztán additív `stats.json` kulcs: `last_live_verification_at`,
  `last_live_verification_count` — egyetlen meglévő kulcs sem változott. Megjelenítve az
  1.5-ös "Out of testing scope" jelzés mellett, ugyanabban a magyarázó zónában (README
  blockquote, `docs/index.html` Evidence-kártya), semleges kék (nem figyelmeztető) színnel.
  JS-oldali újraszámítás a Python-logika tükörképeként (ugyanaz a predikátum), hogy a két
  oldal ne csússzon szét.
  **Valós adaton talált tény, amit nem korrigált mesterségesen:** `last_live_verification_count
  = 1` (nem 26, ahogy a régi register naplója alapján várható lett volna) — `git log -p`-vel
  ellenőrizte, hogy egy 26 szabályos éles futás (`run_id 32059698521`, 19:22) valóban történt
  ~46 perccel a tesztelés-kikapcsoló futás előtt, de annak `result.json` fájljait a későbbi
  futás felülírta a lemezen — ez az adat csak a git történelemben él, a generátor (a
  `stats.json`-hoz hasonlóan, szándékosan) csak a jelenlegi fájlállapotot olvassa. A jelenlegi,
  őszinte válasz 1/28, nem 26/28 — Sienna ezt nem erőltette át, és ez pontosan azt mutatja meg,
  amiért ez a tétel kellett (miért néz ki soványnak a szám ma). Ellenőrzés: valós adaton
  lefuttatva, `stats.json`/`docs/index.html` konzisztencia manuálisan visszaszámolva egyezik,
  `node --check` a beágyazott scriptre, nulla maradék `@@MARKER@@`. Nincs böngészős ellenőrzés
  (nem volt rá felhatalmazás). Nincs commit.

- **2026-08-20 — 5.9 megoldva, a másodikkénti alternatívával, nem `Write`-tal.** A
  klasszifikátor magától blokkolta a `Write` felvételét Kwame `tools:` listájába — ez a
  döntés utólag helyesnek bizonyult: Kwame szerepe kifejezetten szűk (verifikál és jelent,
  sosem implementál), a napi munkája kizárólag meglévő register-fájlok könyvelése, amihez
  az `Edit` elég. Az egyetlen eset, ami `Write`-ot igényelt volna (ennek a fájlnak a
  létrehozása), egy stratégiai, egyszeri döntés volt, nem Kwame rutinfeladata. A `CLAUDE.md`
  Kwame-sora kiegészült egy mondattal, ami ezt explicit rögzíti: Kwame csak meglévő
  registert könyvel, új auditfájlt Gaz kezdeményez és hoz létre. Nincs végrehajtó a
  kódoldalon.

- **2026-08-20 — 4.6 megvalósítva (Jamal).** Három új tesztmodul, mindegyik kizárólag
  `tmp_path`-ban dolgozik, a valós `rules/sigma/`-hoz vagy a Splunk/lab-oldalhoz nem nyúl:
  `tests/test_new_rule.py`, `tests/test_validate_sigma.py`,
  `tests/test_check_detect_id_uniqueness.py`. A legfontosabb, `test_scaffolded_skeleton_
  passes_schema_validation_unedited`, pontosan a `new_rule.py` fejléc-kommentjében tett
  állítást bizonyítja (a generált váz önmagában sémavalid) — ezt korábban nulla teszt fedte.
  **Valódi regressziós próba:** ideiglenesen kivette az `author:` mezőt a `SKELETON`-ból,
  a célteszt pontosan ezen bukott (`'author' is a required property`), a másik négy a
  fájlban változatlanul zöld maradt, utána visszaállította — `git diff` szerint a
  `new_rule.py` byte-azonos a HEAD-del. Teljes suite: 581/581 zöld (561 régi + 20 új). Nincs
  commit.

- **2026-08-20 — Utólagos pontosítás 5.3-hoz.** A `git commit` deny-szabály a gyakorlatban
  Gazt is blokkolta (a session maga, nem csak a dispatchelt specialisták) — ez technikai
  korlát: a `.claude/settings.json` permission-blokkja nem tud különbséget tenni a kettő
  között. A felhasználó (Bence) újragondolta: Gaz — miután átnézte egy specialista kész
  munkáját és jónak ítéli — commitolhat helyben; a specialisták továbbra sem commitolnak,
  de ez mostantól dispatch-utasítás, nem gépi kapu. A `git push` változatlanul `deny`-ben
  marad mindenkinek, Gaznak is — az már megosztott állapot és CI-t indít, az a felhasználó
  döntése. Kiegészítve egy szabállyal: az első commit előtt egy munkamenetben `git fetch` +
  ellenőrzés, hogy a helyi `dev` nincs-e lemaradva az `origin/dev`-től (a CI önállóan ír
  vissza a `dev`-re) — ha igen, előbb `git pull`, hogy ne halmozódjon commit egy elavult
  alapra. A `.claude/settings.json` és a `CLAUDE.md` 4. pontja frissült ennek megfelelően.

- **2026-08-20 — 4.4 részben megvalósítva (Jamal), a teljes konszolidáció szándékosan
  nyitva marad.** A `ci_dev_workflow.yml` `prepare_validate_convert` jobján belüli két
  commit (prune + SPL) eggyé vonva — futásonkénti gépi commit 4-ről 3-ra csökkent ebben a
  workflow-ban (`ci_code_checks.yml` + `ci_prod_audit.yml` 1-1 commitja változatlan).
  Kockázatmentes rész, mert ugyanabban a jobban, egymás után futottak, semmilyen másik job
  nem függ attól, mikor pusholódnak. Az `actionlint`/`shellcheck` hiba nélkül. **A teljes
  4→1 tervet (verify results + dashboard is egy végső commitba) Gaz szándékosan nem indította
  el** — a vizsgálat kimutatta, hogy részleges pipeline-hiba esetén (pl. az `update_dashboard`
  job nem fut le) a ma még köztes commitokban megőrzött haladás (prune, SPL) elveszne, ha
  minden a legvégén, egyetlen commitba tolódna — ez valódi hibatűrési visszalépés, nem
  kockázatmentes, döntést igényel (pl. `update_dashboard` `if: always()`-szel, részleges
  artifactokkal is fusson-e). **Mellékesen talált, Chloe hatáskörébe tartozó elavulás:**
  `docs/architecture/data_flow.md:123-124` és `pipeline_overview.md:93,367` még a két külön
  commitot nevezi meg — a nagy dokumentáció-kör hatóköre.

- **2026-08-20 — 5.2 megoldva (Gaz), más okból, mint az eredeti diagnózis.** Az eredeti
  probléma (a hook `git commit`-re tüzel, de az ügynökök sosem commitolnak) magától
  megoldódott a mai 5.3-amendmenttel — Gaz mostantól tényleg fut `git commit`-ot, tehát a
  trigger-esemény ma már valóban bekövetkezik. **Ez viszont felszínre hozott két önálló,
  valódi hibát**, amit a hook saját tesztje (`test-docs-drift-check.sh`) mutatott meg,
  miután lefuttattam: induláskor **5/7 zöld**, de a két bukó eset pont a pozitív út volt
  (amikor tényleg kellene jelentenie). Ok: (1) a hook `python -c`-t hív, ezen a gépen
  viszont nincs `python`, csak `python3` — a hívás csendben elhasal (`command not found`),
  a feltétel nélküli záró `exit 0` miatt ez teljesen láthatatlan, a hook "helyesen néma"-nak
  tűnik ahelyett, hogy törött lenne. Javítás: `python3` elsőbbséggel, `python`
  visszaesésként. (2) Miután ez kiderült, egy **második, korábban elfedett hiba** is
  előjött: a frissesség-ellenőrzés `-le`-t használt `-lt` helyett, így egy pontosan a
  küszöbön (0 másodperces) landolt commit tévesen "még friss"-ként jelentkezett — a
  teszt saját `test-docs-drift-check.sh` fájlja is ugyanezt a `python`-hiányt tartalmazta
  a kimenet feldolgozásában, azt is javítottam. Végállapot: **7/7 zöld**. A korábbi "5/7"
  részben hamis-pozitív volt — a néma-eseteket helyesen adta vissza, de a jelentő eseteket
  csak azért "adta vissza" helyesen silent-ként, mert maga a jelentés volt törött.

- **2026-08-20 — 5.1 lezárva (Gaz).** Döntés: `CLAUDE.md`, `TEAM.md`, `.claude/agents/*.md`,
  `.claude/skills/*` — a csapat saját delegálási szerződése — Gaz hatásköre marad, nem
  bővül bele Chloe-éba. Indoklás: Chloe a *kifelé mutató* dokumentációt birtokolja (mit
  csinál a pipeline, egy külső olvasónak) — ez a négy fájl a *befelé mutató* delegálási
  szerződés, amit Gaz élőben, a beszélgetés részeként szerkeszt, ahogy roster-döntések
  születnek (perszóna-csere, slug-átnevezés, tool-lista módosítás) — egy docs-kérés-és-
  teljesítés ciklusba terelve csak késleltetést adna hozzá olyan döntésekhez, amikről Gaznak
  már úgyis teljes kontextusa van. A `CLAUDE.md`-be bekerült egy explicit 8. pont, ami ezt
  kimondja. Nincs kódoldali végrehajtó.

- **2026-08-21 — 2.12 lezárva verifikációval, nem megvalósítással (Gaz döntése, Kwame
  könyvelte).** A tétel premisszája elavult volt, nem a hivatkozás. Ellenőrizve: a
  `.claude/skills/` alatt ma is pontosan három könyvtár van (`mitre-attack-mapping`,
  `sigma-rule-authoring`, `team-avatars`) — ez a rész a tétel eredeti megállapításából
  helytálló. Az viszont téves következtetés, hogy ettől a `dataviz` skill nem létezik: a
  `dataviz` nem projekt-helyi skill, hanem a Claude Code-hoz globálisan csomagolt skillek
  egyike (ugyanabban a rétegben, mint pl. `artifact-design`, `design`, `code-review`, amik
  szintén nem élnek a `.claude/skills/` alatt, mégis meghívhatók). Gaz a saját munkamenete
  elérhető-skillek listáján közvetlenül megerősítette, hogy szerepel benne egy pontosan
  `dataviz` nevű bejegyzés, leírása szinte szó szerint egyezik Sienna use case-ével
  („create ANY chart, graph, plot, dashboard… stat tile, sparkline, heatmap…"). Ez
  önmagában Gaz állítása, ezért független megerősítést kerestem a register saját
  naplójában: az **1.5 megvalósítva (Sienna, opus)** bejegyzés (fentebb, 2026-08-20) már
  konkrét, mérőszámos bizonyítékot rögzített arra, hogy Sienna egy korábbi, valódi
  dispatchben ténylegesen meghívta és használta ezt a skillt — „kontraszt-validált narancs
  `#db6d28`, ΔE 15.3-17.5 a `dataviz` skill validátora szerint". Ez nem Gaz mai
  kijelentésének visszamondása, hanem egy másik napon, más kontextusban rögzített,
  numerikus kimenetet is tartalmazó tény ugyanarról a skillről — vagyis a `dataviz` nem
  csak feloldható név egy skill-listában, hanem ténylegesen lefutott és hasznos kimenetet
  adott éles munka közben. `Sienna - Frontend Engineer.md:48` szövege ellenőrizve: nem
  állítja, hogy a `dataviz` projekt-helyi lenne, csak annyit mond, hívja meg — ez az
  állítás igaz, a sor nem hibás, nem is igényel szerkesztést. **Következtetés:** 2.12 nem
  élő hiba, hanem hiányos módszertan volt — a „hiányzik a `.claude/skills/`-ből" és a
  „nem hívható meg" nem ugyanaz, és az eredeti átvizsgálás (Yara, `grep`-alapú) ezt a
  kettőt összemosta. Nincs kódoldali/tartalmi végrehajtó, mert nincs mit javítani.
  **Módszertani megjegyzés a register további köreihez:** jövőbeli skill-hivatkozás-
  ellenőrzéskor (Yara vagy bárki más) nem elég a `.claude/skills/` könyvtárlistázás — a
  tényleges elérhető-skillek listája (a futó munkamenet skill-katalógusa) a mérvadó forrás,
  mert a globálisan csomagolt skillek onnan hiányoznak, mégis élnek. Nem kapott önálló
  tételszámot, mert nem repo-hiány, hanem az audit saját ellenőrzési lépésének korrekciója.

- **2026-08-21 — 4.5 lezárva (Sienna, opus), Kwame verifikálta.** A tétel saját szövege
  elavult volt már a munka *előtt* is: 277 sort és `863-1140`-et mond, a valós állapot a
  munka megkezdésekor 352 sor volt, `941-1292` (a diagnózis lényege — hogy a számítási mag
  egyetlen, tesztek szempontjából nehezen célozható függvény — attól még helytálló maradt,
  csak a konkrét sorhivatkozás csúszott el egy korábbi, nem naplózott módosítás miatt). Ez a
  bejegyzés a `863-1140`/277 sor számot **történeti, a munka előtti állapotként** rögzíti,
  nem javítja utólag a fenti tételszöveget — ugyanaz a konvenció, amit a 4.3 bejegyzés is
  követ (a tételszöveg az eredeti diagnózis pillanatképe marad, a felbontás ide, a Naplóba
  kerül).
  `commit 37d7c84` (`refactor(docs): split generate_stats() into focused helpers`,
  `scripts/docs/generate_stats.py` +383/−225, kizárólag ezt az egy fájlt érinti — `git show
  --stat`-tal ellenőrizve). `generate_stats()` ma `1335-1448` között él, **114 sor**, és
  végigolvasva ténylegesen összeszerelő függvény: `_collect_rule_details`,
  `_group_rule_dimensions`, `_tally_verdicts`, `_compute_rate_stats`,
  `_last_live_verification`, `_compute_mitre_coverage`, `update_trend_history` hívásaiból áll,
  ezek pedig további nevesített segédfüggvényekre bomlanak (`_verdict_standing`,
  `_build_rule_detail`, `_read_cached_mitre_total`) és négy `NamedTuple`-ra
  (`_VerdictStanding`, `_VerdictCounts`, `_RateStats`, `_MitreCoverage`) — összesen a Sienna
  által jelentett ~12 nevesített segéd/`NamedTuple` valóban létezik és ténylegesen hívva van,
  nem kozmetikus átnevezés.
  **Kimenet-azonosság:** Sienna jelentése szerint fagyasztott-órás, byte-azonos futtatással
  hasonlította össze a pre- és post-refaktor modult (`stats` dict kulcssorrenddel együtt,
  README badge-blokk, `docs/index.html`, `navigator_layer.json`). Ezt **nem futtattam újra
  önállóan** — a `generate_stats()` valódi hívása írna a `outputs/reports/coverage_history.json`
  és `rule_growth_history.json` gyorsítótárakba (`update_trend_history()`), ami piszkos
  munkafát hagyna maga után egy verifikációs lépéstől, ezért helyette kód-szintű átolvasással
  és a teszt-suite eredményével pótoltam (lásd lent) — ez a Sienna-jelentés spot-check-e, nem
  önálló újra-levezetése, a dispatch instrukciójának megfelelően.
  **Tesztek:** ezen a gépen nincs rendszerszintű `pytest` (`python3 -m pytest` →
  `No module named pytest`) — Sienna jelentése szerint ugyanez volt az ő gépén is, egyszer
  használt venv-vel oldotta meg, én is ugyanígy jártam el
  (`/tmp/.../scratchpad/venv`, `pip install pytest -r .github/requirements-dev.txt`).
  `tests/test_generate_stats_math.py` + `tests/test_deployment_panel.py`: **26/26 zöld**.
  Teljes suite: **581/581 zöld** — pontosan egyezik a Sienna commit-üzenetében jelentett
  581-es számmal. `ruff check scripts/` → **All checks passed!**. `git status` a futtatások
  után tisztán jött vissza (a tesztek fixtúrákon/tmp-útvonalon dolgoznak, nem a valódi
  gyorsítótár-fájlokon).
  **Nem történt meg:** a fagyasztott-órás pre/post frozen-clock összehasonlítás önálló
  újra-lefuttatása (lásd fent, miért) — ezen a ponton Sienna számszerű jelentésére
  támaszkodom, nem saját, független bájt-egyezés-mérésre.

- **2026-08-21 — 4.4 vizsgálat lezárva eredmény nélkül (Jamal, opus), a tétel
  változatlanul `[ ]` marad.** A 2026-08-20 részleges bejegyzés után Gaz a hátralévő
  hatókört (verify-results + dashboard commit összevonása, `if: always()`
  hibatűréssel) adta ki vizsgálatra. Jamal **nem implementált semmit** — ellenőrizve:
  `git status` és `git diff -- .github/workflows/ci_dev_workflow.yml` üres, a fájl
  byte-azonos a HEAD-del. A vizsgálat a kiinduló feltevést cáfolta meg, nem csak
  kockázatosnak találta: a `splunk_verify` job (self-hosted lab runner, `ci_dev_
  workflow.yml:1559`) és az `update_dashboard` job (ubuntu-latest, `:2251`) **két
  különböző runneren** fut. Az `update_dashboard` friss checkout-ot és `git reset
  --hard origin/dev`-et futtat (`:2332`) a statisztika-újragenerálás előtt; a
  `generate_stats.py` kizárólag a munkafát olvassa (`outputs/results/*/result.json`,
  `outputs/reports/deployment_inventory.json`) — nincs GitHub Actions artifact, ami a
  verify-eredményt átvinné a két job között. A `splunk_verify` commitja (`:2135`,
  szintén `git reset --hard origin/dev` előzi meg) **az egyetlen adatátviteli
  csatorna** az `update_dashboard` felé.
  **Konkrét hibaforgatókönyv:** egy `workflow_dispatch` újramérés (scope: all vagy
  egy adott szabály) egy, az elmúlt 180 napban PASS-t kapott szabályt élesben
  újramér, és FAIL/NOT_VERIFIED lesz belőle. Ha a verify-results commit elmaradna
  (elhalasztva/összevonva), és a dashboard mindenképp lefutna a végén (`if:
  always()`), az `update_dashboard` `origin/dev`-re resetelne, nem találna friss
  eredményfájlt, és a *korábbi* (életkor/verzió alapján még nem elévült) PASS
  verdiktet publikálná újra aktuálisként — egy zöld, teljesen hihetőnek tűnő commit,
  ami félreértelmezi, mi történt ténylegesen abban a futásban. A meglévő
  elévülés-kezelés (1.5/3.9 — verzió-alapú felülírás, 180 napos lejárat) ezt az
  esetet nem fogja meg, mert maga a szabály nem változott, csak az újramérés adott
  eltérő eredményt.
  **A két kézenfekvő megkerülés is kívül esik a hatókörön:** (a) az
  `outputs/results` cross-runner artifactként való átvitele — ez újraépítené a
  törékeny, append-only `history.jsonl`-összefésülő logikát (`ci_dev_workflow.yml`
  kb. `2111-2219`), és egy olyan futásban, ahol az `update_dashboard` sosem indul el,
  a verdiktek teljesen elvesznének — rosszabb hibatűrés, mint ma; (b) a
  `generate_stats.py` áthelyezése magába a `splunk_verify` jobba — ez visszavonná a
  tudatos `[dashboard-decoupling]` döntést, ami miatt a dashboard offline lab esetén
  is tovább frissül.
  **Rögzítve:** a commit-szám változatlan (3/futás: [prune+SPL], [verify-results],
  [dashboard]), kód nem változott, a 4.4 hátralévő hatóköréhez a tételszövegben már
  megnevezett nagyobb átalakítás kell (branch-eltávolítás / Pages-artifact
  alternatíva, a 3.5-tel összekötve), nem egy egyszerű write-back-összevonás — ezt
  explicit rögzítjük, hogy egy jövőbeli nekifutásnak ne kelljen nulláról
  újralevezetnie a cross-runner korlátot.

- **2026-08-21 — 4.7 lezárva (Sienna + Jamal), Kwame verifikálta, önálló futtatással.**
  Két commit: `df50d31` (Sienna) — új `scripts/docs/smoke_test_rule_browser.js` (373 sor),
  öt ellenőrzés: nulla kicseréletlen `@@MARKER@@` a `docs/index.html`-ben, oldalbetöltés
  hiba nélkül, nulla console/page error, a szabálysor-szám egyezése három forrás között
  (`stats.json` `total_rules`, az oldalba ágyazott `RULES` tömb hossza, a `#result-count`
  szöveg), és a Dashboards-fül két gyűrűje (`chart-evidence`, `chart-verify`) ténylegesen
  Chart.js-példányként létezik, látható méretű, és a mögötte lévő adathalmaz összege > 0.
  `35fb6c6` (Jamal) — bekötve a `ci_code_checks.yml` `static_analysis` jobjába: friss
  `python scripts/docs/generate_stats.py` futás, majd Playwright telepítés (pinelve
  `1.55.0`-ra, `--no-save`, mert nincs `package.json`), majd maga a smoke teszt, mindkét
  lépés `steps.generate_smoke_fixture.outcome == 'success'`-re kapuzva. `.gitignore`
  kiegészült a `node_modules/`-szal.
  **Ellenőrzés:** mindkét commit létezik és a leírtnak megfelelő tartalommal (`git show`
  teljes diff elolvasva, nem csak a commit-üzenet). A workflow-diff a `static_analysis`
  jobon belül landol, a meglévő `page.js`-szintaxis-lépés után, `regenerate_console` előtt
  — pontosan a Jamal-jelentésben leírt job-gráf. `actionlint 1.7.12` +
  `shellcheck 0.10.0` (frissen letöltve, mert ezen a gépen alapból nincs) → hiba nélkül.
  **Sienna és Jamal is jelezte, hogy nem futott náluk Playwright/Chromium** — ezen a gépen
  viszont igen: telepítettem `playwright@1.55.0`-t (`npm install --no-save`), a hozzá
  tartozó Chromium-revíziót (`1187`) a helyi `~/.cache/ms-playwright` már tartalmazta
  (`--with-deps` szudó nélkül elhasalt, sima `npx playwright install chromium` viszont csak
  "removing unused browser"-t írt ki, mert a szükséges revízió már megvolt), tehát **önállóan
  lefuttattam a smoke tesztet a valódi, frissen regenerált `docs/index.html`-en** (`python3
  scripts/docs/generate_stats.py`, majd `node scripts/docs/smoke_test_rule_browser.js
  --docs-dir docs --stats outputs/reports/stats.json`): mind az 5 ellenőrzés **PASS**, végső
  státusz `SMOKE TEST: PASSED`. A generálással keletkezett munkafa-változásokat
  (`README.md`, `docs/index.html`, `outputs/reports/*.json`) `git checkout --`-tal
  visszaállítottam, a `node_modules/`-t töröltem — a repó tisztán maradt, nincs commit.

- **2026-08-21 — 3.11 lezárva (feltárt, dokumentált korláttal), Kwame verifikálta.**
  `0c573e9`: új `scripts/verify/diff_matched_events.py` (308 sor, önálló CLI, tudatosan
  nincs CI-ba kötve — vizsgáló eszköz, nem kapu) + `tests/test_diff_matched_events.py`
  (252 sor, 22 teszt). A modul minden, legalább egy eseményen jelen lévő mezőre megnézi,
  van-e szigorú többségi érték (`> total/2`), és ha igen, a kisebbségi értékeket az
  eseményindexeikkel együtt jelenti; a mezőket a kisebbség méretének növekvő sorrendjében
  rangsorolja — pontosan a „FAIL(11) vs. PASS(10), melyik volt a plusz esemény" esetet
  célozva, ahogy a tétel és a modul saját docstringje is leírja. `_hashable()` a lista/dict
  mezőket hasható alakra hozza, hiányzó mező `"(missing)"` szentinelt kap. Alapértelmezett
  kizárás: `_`-prefixű Splunk-bookkeeping mezők + egy névvel felsorolt metaadat-halmaz
  (`linecount`, `punct`, `splunk_server`, …), `--include-field`/`--all-fields`-szel
  felülírható.
  **Ellenőrzés:** `python -m pytest tests/test_diff_matched_events.py` → **22/22 zöld**
  (pinelt `pytest==9.1.1`, izolált venv-ben, mert ezen a gépen sincs rendszerszintű pip/
  pytest). `ruff check scripts/verify/diff_matched_events.py tests/test_diff_matched_events.py`
  (pinelt `ruff==0.16.3`) → **All checks passed!**. A modul docstringje és a
  `find_splitting_fields()` törzse végigolvasva: a leírt majority/minority-logika és a
  kisebbség-szerinti rangsorolás valóban ezt csinálja, nem csak azt állítja.
  **Ismert korlát, amit nem takarok el a lezárással (a modul saját docstringje és a
  commit-üzenet is nevesíti):** a nyers illeszkedett-esemény adat (a
  `check_saved_search_hits.py` által termelt `events` tömb) **sosem kerül be az
  `outputs/`-ba** — kizárólag a `matched-events-sigma-<run_id>` CI-artifactban létezik,
  14 napos retencióval (`ci_dev_workflow.yml:1882`). Vagyis a `diff_matched_events.py` a
  3.11 tényleges hatókörére helyes és teljes, de **ma csak ezen a 14 napos ablakon belül
  ténylegesen használható** — utána nincs mit betölteni vele, hacsak valaki nem menti le
  kézzel az artifactot lejárat előtt. Ez ugyanaz a `matched-events-sigma-<run_id>` artifact,
  amit a **3.10** (a labor-névtan anonimizálása) is érint — bárki, aki legközelebb az egyiket
  nyitja meg, nézze meg a másikat is: mindkettő ugyanabból a perzisztencia-hiányból ered
  (a nyers matched-event adat sosem landol a repó/`outputs/` tartós rétegében), és egy közös
  megoldás (pl. az artifact tartalmának szűrt/anonimizált formában való megőrzése
  `outputs/`-ban) mindkettőt egyszerre zárná. Nem kapott önálló tételszámot — bekövetkezett
  tényként rögzítve itt, a 3.11 zárásában, a 2.12-nél alkalmazott konvenció szerint.

- **2026-08-21 — 3.10 lezárva (`4aedde3`), Kwame verifikálta.** Két új fájl +
  egy módosított workflow, `git show --stat`-tal ellenőrizve a commit-üzenet
  ellen: `scripts/verify/anonymize_matched_events.py` (706 sor, új),
  `tests/test_anonymize_matched_events.py` (502 sor, új, 39 `def test_`
  függvény — a commit-üzenet „43 new tests" száma a pytest-kollekciós
  darabszám lehet parametrizálás miatt, nem ellentmondás), `.github/workflows/
  ci_dev_workflow.yml` (+77/−18, kizárólag a `splunk_verify` jobon belül).
  **Modul-docstring (1-97. sor) végigolvasva:** a design-indoklás (azonosítók
  *felfedezése*, nem konfigurálása; a szabad szöveg miatti helyettesítés nem
  opcionális, 15/28 szabály `CurrentDirectory`-ja plain textben hordozza a
  fióknevet; a `_raw` kezelése `custom.splunk.raw_query` esetére; a
  só-alapú, futások közt stabil álnév-képzés) valóban megelőzi és
  megmagyarázza a kódot, nem utólagos magyarázat.
  **Teszt-suite, önállóan újrafuttatva** (izolált venv,
  `.github/requirements.txt` + `.github/requirements-dev.txt`, ugyanaz a
  mintázat, mint a 4.5/4.7/3.11 verifikációnál): `tests/test_anonymize_
  matched_events.py` önmagában zöld (39/39, pontkijelzéssel megszámolva —
  a `-q` összegző sora ezen a gépen nem jelenik meg, a pontok száma viszont
  egyezik); **teljes suite 646/646 zöld** (a kimenet 646 pontot tartalmaz,
  hibajel nélkül) — egyezik a Gaz által korábban, függetlenül jelentett
  646/646-tal. `ruff check scripts/verify/anonymize_matched_events.py
  tests/test_anonymize_matched_events.py` → **All checks passed!**.
  `actionlint`/`shellcheck` **nem állt rendelkezésre ezen a gépen** (a 4.4/4.7
  verifikációnál használt binárisok itt nincsenek telepítve) — ezen a ponton
  Jamal/Gaz korábbi, commit előtti futtatására támaszkodom, nem saját
  independens futtatásra; ezt explicit jelzem, nem hallgatom el.
  **Kódszintű ellenőrzés a három fő állításra:**
  (1) `HOST_FIELDS`/`USER_FIELDS`/`DOMAIN_FIELDS` (:146-192) mezőnév-
  halmazok, nem gépnév-lista; a fájlban `grep`-pel keresett lab-jellegű
  minták (`victim`, `dc01`, `.local`, `corp.local` stb.) kizárólag
  docstring-/kommentpéldákban fordulnak elő (pl. „`DC01.lab.local`"), soha
  literál azonosítóként a logikában — a tesztfájl saját, szintetikus
  fixture-neveket használ (`WIN-VICTIM01.delab.local`,
  `DELAB-DC01`), amik sehol máshol a repóban nem fordulnak elő, tehát nem
  szivárgott valódi labor-névtan. (2) `Pseudonymizer._mint` (:316-322)
  `hashlib.blake2s`-t hív egy `hashlib.sha256`-ból származtatott
  só-kulccsal, `(kind, key)` páron kulcsolva — ténylegesen hash-alapú, nem
  számláló (nincs inkrementált számláló változó a mintázási útvonalon).
  (3) CI-vezetéklet (:1904-1937): önálló `ANON_DIR=$(mktemp -d)`, a
  `matched_events_anon_dir` `$GITHUB_ENV`-export csak a `python …` hívás
  utáni sorban, `set -euo pipefail` mellett — egy nem-nulla exit a
  scriptből a step-et azelőtt állítja meg, hogy az export megtörténne. Az
  Upload-lépés `if:` feltétele ténylegesen `matched_events_anon_dir != ''`-re
  vált, nem a régi `matched_events_dir`-re — a `git diff` ezt megerősíti.
  **Tudatosan nyitva hagyott, nem e körben javított hiányok (a lezárás nem
  takarja el őket):**
  1. **Nincs valódi `LAB_ONLINE`-futással verifikálva** — csak szintetikus/
     lokális fixtúrákon lett tesztelve, a commit-üzenet ezt maga is kimondja.
  2. **Dokumentáció-drift négy helyen**, mind azt írja, hogy az artifact
     „nyers, mezőszűréstől mentes" marad: `README.md:116`,
     `docs/architecture/data_flow.md:24,112,115`,
     `docs/architecture/pipeline_overview.md:372` (a job-lépéslista nem
     tartalmazza az új „Anonymize matched events" lépést), plusz a
     `docs/architecture/scripts_reference.md`-ből hiányzik magának a
     scriptnek a bejegyzése (`grep` → 0 találat). Mind a négy Chloe
     hatásköre, és a felhasználó kérésére ez a kör szándékosan **nem** nyúl
     dokumentációhoz — rögzítve, hogy ne vesszen el.
  3. **Opcionális keményítés nincs alkalmazva:** egy `MATCHED_EVENTS_ANON_SALT`
     repository secret megszüntetné az alapértelmezett só körüli
     találgatás-megerősítési oldalcsatornát; a workflow már olvassa a
     secretet (`:1908`), de a secret maga nincs provisionálva — ez **Kai**
     döntése, nem történt meg itt, és semmi nem törik a hiányától.
  4. A **`DEFAULT_SALT` egy konstans literál** a committolt forrásban
     (`:130`) — ez **szándékos és dokumentált** (a modul-docstring
     „Pseudonym stability" szakasza), nem hiba: cross-run stabilitást ad, a
     titkosság hiányát a 3. pont oldja fel opcionálisan.

- **2026-08-21 — 3.5 lezárva mérés alapján (nem megvalósítás) (Sienna), Kwame könyvelte.**
  Nincs kódváltozás — a `git status`/`git diff` a mérés előtt és után is tiszta munkafát
  mutatott, ahogy a tétel jellege (mérés, nem javítás) is megkívánta.
  **Módszer, a tétel szövegétől eltérve, indokoltan:** a tétel a `chrome-devtools` MCP-t
  nevezte meg; Sienna sandboxában nincs rendszerszintű Chrome, ezért a helyette önálló
  `lighthouse` CLI-t futtatta Playwright Chromiumja ellen, ugyanazokkal az audit-
  kategóriákkal és ugyanazzal a motorral — érvényes helyettesítés, de eltérés a tétel
  szó szerinti szövegétől, ezért itt rögzítve.
  **Mérés (friss `docs/index.html`, mobil + desktop preset):** Performance 78/100 mobil,
  96/100 desktop; Accessibility 86/100 mobil, 81/100 desktop; Best Practices 96/100; SEO
  100/100.
  **A mobil performance-szám mérési módszertan műterméke, nem valós tünet.** A mérés
  Python `http.server`-rel kiszolgált, tömörítetlen fájl ellen futott (681 KB átvitel).
  Sienna külön ellenőrizte a valódi production URL-t (GitHub Pages) `curl`-lel — ezt
  itt önállóan megismételtem: `https://martonbence.github.io/Detection-Engineering/`
  `content-encoding: gzip`, `content-length: 114220` (~114 KB), `HTTP/2 200`, saját
  mérésem szerint ~200 ms teljes idő / ~183 ms TTFB erről a gépről (más hálózati út,
  mint Sienna méréséé — a nagyságrend, a gzip-tömörítés ténye és a ~114 KB méret
  egyezik az állítással, az abszolút ezredmásodperc-szám hálózatfüggő, nem
  összehasonlítható 1:1). JS-futási költség ~0 (0 ms total-blocking-time, 0,1 s
  main-thread munka) — a mérőszámot a Lighthouse-fékezési feltételezések torzítják egy
  nem production-hű teszt-felállásban, nem az oldal tartalma.
  **Fájlméret-bontás** (680 982 bájt, tömörítetlen — a helyi fájl mérete önállóan
  ellenőrizve: `ls -la docs/index.html` → pontosan 680 982 bájt; `page.js` 134 412 bájt
  egyezik, `page.css` 98 349 bájt a jelentett 98 356-tal szemben, 7 bájt eltérés,
  elhanyagolható, valószínűleg más mérési időpont): MITRE Navigator mátrix HTML
  267 345 bájt (39,3%, **nem nő** a szabályszámmal — fix rács a 222 ATT&CK technikán),
  `page.js` 134 412 (19,7%, statikus), RULES JSON 71 111 (10,4%, a ténylegesen
  szabályszám-lineáris rész, ~2,5 KB/szabály), `page.css` 98 356 (14,4%, statikus),
  deployment-panel HTML 57 819 (8,5%, részben lineáris), history JSON 15 214 (2,2%,
  idő-, nem szabályszám-alapú), maradék statikus markup ~36 725 (5,4%).
  **Következtetés, rögzítve:** 28 szabálynál nem élő probléma, és a növekedési görbe
  enyhébb, mint a tétel eredeti keretezése feltételezte — a legnagyobb szelet (39%, a
  MITRE-mátrix) már mérethatáron van, nem nő tovább; csak ~2,5 KB/szabály valóban
  lineáris, tehát 10x növekedés (~280 szabály) is csak ~120 KB-ot tenne a mai ~114 KB
  gzippelt méretre — még mindig gyors oldal bármilyen normál mércével. Ha a növekedés
  valaha valódi gonddá válik, a böngészőbeli DOM-méret/render-költség valószínűbb
  jövőbeli fájdalompont, mint a hálózati átviteli bájtszám — ezt érdemes követni, nem a
  nyers fájlméretet. **Revizit-küszöb, explicit rögzítve:** nincs mai indok az
  átdolgozásra; a következő nézőpont a DOM-méret/render-költség legyen, nem a
  fájlméret, ha ez a tétel valaha újranyílik.
  **Mellékes, opcionális flag:** egy hiányzó `favicon.ico` miatti konzol-404 a Best
  Practices alatt — triviális, nem kapott önálló tételszámot, csak itt jegyezve.
  **Négy, a mérés által feltárt, valódi és önálló accessibility-hiba nem ennek a
  tételnek a lezárásába, hanem egy új, nyitott tételbe (3.12) került** — lásd alább.

- **2026-08-21 — 3.12 felvéve (Kwame könyvelte, Sienna Lighthouse-mérése alapján).** A
  3.5 mérése négy, a szabályszámtól független, ma javítható accessibility-hibát hozott
  fel (`button-name`, `color-contrast`, `landmark-one-main`, `target-size`) — ezek nem
  tartoznak a 3.5 mérés-alapú lezárásába, mert nem mérési következtetések, hanem
  konkrét, azonnal cselekvő hibák. Új tételszám: **3.12** (a szakasz addigi legmagasabb
  tétele a 3.11 volt). A szakaszfejléc `(11)` → `(12)`-re módosult, a teljes register-súly
  **79 → 80,5** (a funkció-kategória 11×1,5=16,5 → 12×1,5=18). A `target-size` találatot
  (MITRE taktika-pill jelvények érintési célmérete) szándékosan elhatárolva a régi
  `remediation-plan.md` „amit nem fedett" szakaszában rögzített, sosem újraellenőrzött
  sormagasság-hibától (badge-listás sorok `vertical-align`-problémája) — a kettő
  szomszédos felület, de különböző hiba; ebben a körben egyiket sem ellenőriztem újra a
  kettő közül, csak a mostani Lighthouse-találatot verifikáltam. Ellenőrzés a felvétel
  előtt: `grep`-pel megerősítve, hogy a `button.drawer-close` (`page.template.html:587`)
  ténylegesen nem kap `aria-label`-t, míg az `.info-close` gomb ugyanabban a fájlban
  igen (`:61`); hogy `<main` egyszer sem fordul elő a template-ben; és hogy az
  `a.badge.badge-mitre` (`page.js:1583`, `page.css:1134`) ténylegesen létező, a leírt
  módon használt osztály. A színkontraszt-állítást (4 elem) nem tudtam önállóan
  újramérni (nincs Lighthouse/böngésző-eszköz ebben a munkamenetben) — ezen a ponton
  Sienna jelentésére támaszkodom.

- **2026-08-21 — 3.2 elutasítva.** Gaz Jamalt bízta meg a `schedule:` trigger
  hozzáadásával a `ci_prod_audit.yml`-hez, a tétel saját indoklása alapján (a
  `LAB_ONLINE` gate offline labnál is tisztán kihagyná az ütemezett futást). Jamal
  megvalósította, `actionlint`-tel ellenőrizte, és megerősítette, hogy a mechanizmus
  technikailag helyes: a `vars.LAB_ONLINE` a GitHub vezérlősík által a job `if:`
  feltételénél kiértékelt repository-változó, *mielőtt* a job egyáltalán igényelné az
  önhosztolt `de-lab` runnert — tehát `LAB_ONLINE == 'false'` esetén a futás tiszta
  „skipped", nulla runner-kontaktussal.

  A felhasználó a commit előtt elkapta a valódi hibát, ami a tétel *előfeltevését*
  dönti meg, nem csak a megvalósítást: a mechanizmus csak akkor biztonságos, ha a
  `LAB_ONLINE` naponta pontosan követi, hogy a lab VM ténylegesen be van-e kapcsolva.
  `gh variable list` szerint `LAB_ONLINE` ma `true`, utoljára 2026-08-15-én változott —
  hat nappal e lezárás előtt. A felhasználó megerősítette, hogy **nincs megbízható
  szokás vagy automatizmus**, ami a változót a VM valódi áramellátásához
  szinkronizálná; mivel a VM állítása szerint ritkán van bekapcsolva, a `true` érték a
  legtöbb napon valószínűleg elavult alapállapot.

  Ennek a következménye: ha a `LAB_ONLINE` `true`-n áll, miközben a VM valójában ki
  van kapcsolva, egy ütemezett futás **nem** ugrik ki tisztán — átmegy az `if:`
  kapun, igényli az önhosztolt `de-lab` runnert, majd sorban vár egy runnerre, ami nem
  figyel (a runner-folyamathoz magának a VM-nek fent és csatlakozva kell lennie). Ez
  minden ütemezett ciklusban egy beragadt/várakozó futás (a GitHub végül
  időtúllépésbe futtatja, de csak hosszú várakozás után) — ami szigorúan rosszabb a
  mai kézi-only állapotnál: napi zajt termel az Actions fülön, megfelelő audit-érték
  nélkül, pontosan amiért a workflow saját eredeti (a változtatás előtti) kommentje
  már megmondta: „the self-hosted de-lab runner and its prod Splunk are usually
  offline, so a nightly cron mostly no-ops… run this by hand when the lab is actually
  up."

  Jamal diffje commit előtt vissza lett állítva (`git checkout --
  .github/workflows/ci_prod_audit.yml`) — verifikálva: `git status` tiszta, `git
  diff` üres a fájlra, és a fájl az `1113a4d` (2026-08-17, „drop nightly schedule,
  keep manual dispatch") commit óta változatlan; más fájlt sem érintett a
  megszakított kísérlet.

  A tétel premisszája (a `LAB_ONLINE` gate biztonságossá teszi az ütemezést)
  technikailag helyes volt magára a kapu-mechanizmusra nézve, de téves az
  előfeltételre nézve — feltételezte, hogy a `LAB_ONLINE` a gyakorlatban követi a
  valódi VM-állapotot, ami itt nem igaz. Újranyitható, ha valaha megbízható mód
  (kézi fegyelem vagy automatizálás) születik a `LAB_ONLINE` és a VM tényleges
  áramállapotának szinkronban tartására — addig az eredeti workflow-szerző
  indoklása áll, és a tétel nem valósítandó meg. **Megjegyzés: ugyanez a minta
  zárta le a szomszédos 3.1-et is 2026-08-20-án** (lásd fent) — a lab jellemzően
  offline állapota mindkét tételnél ugyanazt a következtetést hozta ki, csak itt
  egy konkrét, mért `LAB_ONLINE`-drift bizonyítja is, nem csak feltételezi.

- **2026-08-21 — 3.12 lezárva, Kwame verifikálta.** A `c178581` commit (2 fájl:
  `page.css`, `page.template.html`) mind a négy megnevezett hibát javítja, a
  diff ellenőrizve a tétel négy állítása ellen: **(1) `button-name`** —
  `aria-label="Close rule details"` került a `button.drawer-close`-ra
  (`page.template.html:589`), pontosan az `.info-close`-nál már meglévő
  mintát követve. **(2) `color-contrast`** — `.strip-total`, `.tab-btn`
  (alap állapot) és `.result-count` a `page.css`-ben `text3`-ról `text2`-re
  váltott; `.tab-btn:hover` `text2`-ről `text`-re, hogy a hover-eszkaláció ne
  vesszen el azzal, hogy az alapállapot feljebb került. **(3)
  `landmark-one-main`** — egy `<main>` elem veszi körbe mindhárom fület
  (`#tab-rules`, `#tab-navigator`, `#tab-dashboards`), kísérő
  `main { flex:1; min-height:0; … }` CSS-szabállyal, ami a korábbi
  layoutot változatlanul tartja. **(4) `target-size`** — `.badge-mitre`
  `min-height`/`min-width: 24px` + `padding` kapott (korábban ~17px magas
  volt), `.cell-pills` gap 4px→6px. Mind a négy állítás valós a diffben, nem
  csak a commit-üzenetben.

  Önálló verifikáció, nem csak a register saját szövegének visszaolvasása:
  friss `docs/index.html` regenerálva (`python3 scripts/docs/generate_stats.py`,
  utána `git checkout` a mellékesen módosult `README.md` / `outputs/reports/*`
  fájlokra, hogy a munkamenet ne hagyjon a saját felületemen kívüli
  változást). `node scripts/docs/smoke_test_rule_browser.js` PASS mind az öt
  ellenőrzésen (nincs `@@MARKER@@` maradék, oldal hiba nélkül tölt be, 28
  sor, mindkét gyűrű renderel, nincs konzolhiba) — helyi Playwright-csomag
  hiányzott a rendszeren, egy korábbi munkamenet gyorsítótárából
  (`NODE_PATH`) pótoltam, verzió és Chromium-revízió (1187) egyezik. Lighthouse
  is elérhető volt (helyi `npx`-gyorsítótárban lévő `lighthouse@13.4.1` +
  Playwright Chromium 140.0.7339.16 mint `CHROME_PATH`) — tehát a Sienna által
  jelentett előtte/utána pontszámokat nem csak átvettem, hanem ugyanazzal a
  módszerrel újra lefuttattam: **accessibility desktop 0,95** (1 preset ×
  `--only-categories=accessibility`), **mobil 1,00** — mindkettő egyezik
  Sienna jelentésével (0,81→0,95 desktop, 0,86→1,00 mobil), és a négy
  megnevezett audit (`button-name`, `landmark-one-main`, `target-size`, és a
  4 eredeti `color-contrast` elem) mind zöld a friss mérésben. Az egyetlen
  megmaradó `color-contrast` bukás egy **másik** elemhalmazon jelentkezik —
  ez nem cáfolja a 3.12 zárását, hanem az alább nyitott 3.13 tárgya.

- **2026-08-21 — 3.13 felvéve (Kwame könyvelte, saját Lighthouse-mérés
  alapján, Sienna jelentésének megerősítéseként és pontosításaként).** A
  3.12 zárásához futtatott Lighthouse-újramérés (lásd fent) egy hat elemből
  álló, korábban dokumentálatlan `color-contrast` bukást mutat:
  `.filter-group-label`, `.filter-uniq`, `.filter-supergroup-title`,
  `.filters-generated`, `.kbd-hint`, és a szabálytáblázat verdikt-jelvényei
  (`badge-category` / `badge-service`). Ez a hatókör-elhatárolás szándékos
  volt a 3.12 lezárásakor (lásd a `c178581` commit-üzenetének utolsó
  bekezdését) — nem menet közbeni hatókör-tágítás, hanem egy önálló,
  mellékesen felfedezett hiba, amit külön tételbe kell venni. Új tételszám:
  **3.13** (a szakasz addigi legmagasabb tétele a 3.12 volt, ellenőrizve
  `grep`-pel a szakasz teljes tartalmán). A szakaszfejléc `(12)` → `(13)`-ra
  módosult, a teljes register-súly **80,5 → 82** (a funkció-kategória
  12×1,5=18 → 13×1,5=19,5); a `Kész súly` sor nevezője és a projektált
  pontszám képlete is frissült ugyanerre.

  A számokat nem csak átvettem: saját Lighthouse-mérést futtattam a friss
  `docs/index.html`-en (desktop preset, ugyanaz a `color-contrast` audit),
  ami megerősíti a hibát, de **tágabb tartományt mér, mint Sienna
  jelentése**. Sienna 4,19–4,47:1-et jelentett; a saját mérésem szerint ez
  csak a verdikt-jelvényekre igaz (4,19–4,47:1, `#f85149`/`#332227` és
  `#38272c`, `#2ea44f`/`#1e302c`) — a `.filter-group-label` /
  `.filter-uniq` / `.filter-supergroup-title` hármas ennél lényegesen
  rosszabb, **3,52:1** (`#6e7681` a `#1c2128` háttéren), a
  `.filters-generated` **3,76:1** (`#161b22` háttéren), a `.kbd-hint`
  **4,11:1** (`#0d1117` háttéren). Ez a tétel szövegében rögzítve van, hogy
  a jövőbeli javítás ne a szűkebb, Sienna-jelentette tartományból induljon
  ki. Nem javítottam semmit — a tétel nyitva marad, gazdája **Sienna** →
  lásd a tétel szövegét a 3. szakaszban.

- **2026-08-21 — 3.13 lezárva, Kwame verifikálta.** Az `593e181` commit (1
  fájl: `page.css`, 33 sor hozzáadva / 7 törölve) a tétel mind a hét
  elemtípusán javít, a diff ellenőrizve a tétel állításai ellen, nem csak a
  commit-üzenet elfogadva. **(1)** `.filter-group-label` (`:479`),
  `.filter-uniq` (`:494`), `.filter-supergroup-title` (`:402`),
  `.filters-generated` (`:128`), `.kbd-hint` (`:775`) mind `text3`-ról
  `text2`-re váltottak — pontosan a saját, a tétel felvételekor mért
  3,52–4,11:1 tartomány ellen, a diff minden egyes hunkja idézi a saját
  mérésemet kommentben (`register 3.13, color-contrast`). **(2)**
  `.badge-category` / `.badge-service` (`:1158`, `:1177`) nem
  token-cserét kapott, hanem új, konkrét színt: `color: #f85149` →
  `#ff7b72`, `color: var(--green)` → `#3fb950`. A commit indoklása
  (a `--red`/`--green` alapszín a féláttetsző jelvény-háttéren minden
  valós renderelési kontextusban — táblázatsor, hover, drawer — AA alatt
  marad, mert az alfa-emelés rontja, nem javítja a kontrasztot) ellenőrizve:
  a `#ff7b72` valóban a `.t-kw`/`.t-cond` szintaxis-kiemelés szín
  (`grep #ff7b72 page.css` → ugyanaz az érték már használatban), a
  `#3fb950` valóban a `.fc-service` szűrő-chip akcentusszíne — egyik sem új
  szín, mindkettő már megalapozott máshol az oldalon, a commit-üzenet
  állítása pontos.

  Önálló verifikáció, nem csak a register/commit saját szövegének
  visszaolvasása: `node scripts/docs/smoke_test_rule_browser.js` PASS mind
  az öt ellenőrzésen (helyi Playwright-hiány ugyanúgy a korábbi munkamenet
  gyorsítótárából pótolva, `NODE_PATH`, Chromium-revízió 1187 — ugyanaz a
  módszer, mint a 3.12 zárásakor). Friss `docs/index.html` regenerálva
  (`python3 scripts/docs/generate_stats.py`), Lighthouse újrafuttatva
  ugyanazzal a helyi `npx`-gyorsítótárban lévő `lighthouse@13.4.1` +
  Playwright Chromium 140.0.7339.16 (`CHROME_PATH`) párossal, `file://`
  helyett helyi HTTP-szerveren át (a `file://` séma `INVALID_URL`-lel
  bukott ezen a Lighthouse-verzión): **`color-contrast` 1,0/0 bukás mind
  desktop, mind mobil preseten**, teljes accessibility-pontszám mindkettőn
  **1,0** — egyezik Sienna jelentésével. A munkamenet a saját felületemen
  kívül (`docs/index.html`, `README.md`, `outputs/reports/*.json`) nem
  hagyott változást — a regenerált fájlokat `git checkout`-tal
  visszaálltam, ugyanúgy, ahogy a 3.12 zárásakor.

  **Mellékes, opcionális flag, nem kapott önálló tételszámot:** a `593e181`
  commit-üzenete jelzi, hogy a javítás közben Sienna holt CSS-t talált —
  `.sev-critical`, `.sev-high`, `.sev-medium`, `.sev-low`,
  `.sev-informational`, `.status-stable`, `.status-test`,
  `.status-experimental`, `.status-deprecated` a `page.css`-ben, amit
  semmi nem hivatkozik. Ellenőrizve `grep`-pel mindkét fogyasztó fájlon
  (`page.js`, `page.template.html`): **nulla valódi találat** — a
  severity/status legend-kártyák ténylegesen a `LEVEL_COLORS[lvl]` /
  `STATUS_HEX[k]` inline JS színkonstansokból építik a pöttyöt
  (`.sev-legend-dot` / `.status-legend`, `page.js:229,437,491`), a
  `.sev-*`/`.status-*` szelektorok tényleg sehol nincsenek bekötve. Az
  állítás igaz. **Miért footnote, nem új tétel:** ez ma nem élő,
  Lighthouse-mérhető hiba — holt CSS-t a böngésző nem renderel, tehát nem
  is bukhat rajta felhasználó —, és a javítása triviális (törlés, vagy ha
  valaha be lesz kötve, a 3.13-ban most alkalmazott mintát kell rá
  másolni). A `.sev-critical`/`.sev-high` és a `.status-stable`/… valóban
  ugyanazt a féláttetsző-jelvény piros/zöld mintát hordozza, ami a
  `badge-category`/`badge-service`-t buktatta — ha valaki ezt a holt kódot
  a jövőben szó szerint bekötné legend-swatchnak a mai inline JS-szín
  helyett, ugyanaz a kontraszt-hiba térne vissza némán. Ez a kockázat
  eléggé konkrét ahhoz, hogy megérje leírni, de nem elég sürgős/valós ahhoz,
  hogy a register súlyát/nevezőjét egy ma-nem-létező hibáért módosítsuk →
  **Sienna** dönt (törlés vagy tudatos megtartás indoklással), ha időszerű.

  A checkbox-matek ellenőrizve a lezárás után: `grep -c '^- \[x\] \*\*'` /
  `'^- \[ \] \*\*'` a fájlon **21 kész / 30 nyitott, összesen 51** (a
  3.12 zárása után a szakaszfejléc-számok és a 82-es teljes súly már
  frissültek, a `Kész súly` sor `0/82` maradt — az a numerátor a v1.0
  kiindulási alapállapotot rögzíti, nem élő számláló, korábbi lezárások
  sem módosították).

- **2026-08-21 — 2.8 lezárva, Kwame verifikálta.** Gaz munkafa-szerkesztése
  (nem commitolt): `TEAM.md` mind a 11 sora `*Avatar: pending*`-ről
  `![Name](.claude/agents/avatars/Name.png)`-re váltott, a bevezető
  „avatars are pending” mondat eltűnt. Önálló ellenőrzés, nem a register
  saját szövegének visszaolvasása: `grep -i pending TEAM.md` → **0
  találat**; mind a 11 hivatkozott fájl (`Bjorn.png` … `Yuki.png`)
  ténylegesen létezik `.claude/agents/avatars/`-ban (`ls -la`, mind
  2026-08-20-i keltezéssel, a jelen munkameneten kívül generálva) — az
  eredeti tétel csak kettőt talált (`Bjorn.jpg`, `Yuki.png`, rossz
  elnevezéssel), ma mind a 11 megvan, a skill saját elnevezési
  konvenciójának megfelelően (nagybetűs név, `.png`, alkönyvtár nélkül).
  Teljes, hiánytalan lezárás.

- **2026-08-21 — 5.5 részben verifikálva, a tétel `[ ]` marad.** Gaz
  munkafa-szerkesztése (nem commitolt) mind a három megnevezett fájlt
  (`Kwame`, `Jamal`, `Bjorn`) módosította; a negyediket (`Priya`)
  szándékosan érintetlenül hagyta.
  **Kwame fájlja — pontos.** „closed at 54/54 as of 2026-08-15" —
  ellenőrizve `audit/remediation-plan.md`-n: `grep -c '^- \[x\] \*\*'` →
  **54**, `'^- \[ \] \*\*'` → **0**. Az új mondat a második registerre is
  helyesen utal, és arra is, hogy annak saját státuszoszlopa sem
  megbízható forrás.
  **Bjorn fájlja — pontos.** A „prod re-converts and byte-compares …
  drift gate" mondat „prod verifies build provenance (`gh attestation
  verify` against the attested dev bundle) … attestation chain"-re
  változott — ellenőrizve `.github/workflows/ci_prod_workflow.yml`-ben: a
  fájl ténylegesen `gh attestation verify`-t hív a
  `.bundle-provenance.json` pointer ellen (`:166,237`), és nincs benne
  újrakonverziós lépés. A `rule_documentations/` mondatot Gaz eredetileg is
  pontosnak találta és nem nyúlt hozzá — ellenőrizve, a fájl valóban
  explicit jelzi, hogy a könyvtár megszűnt, és megkérdezi a felhasználót a
  céldirektóriumról commit előtt.
  **Jamal fájlja — részben hibás, új elavulással.** A workflow-tábla
  helyesen bővült négy sorra, és a `ci_prod_workflow.yml` sora pontosan
  írja le az attesztációs mechanizmust (ugyanaz az ellenőrzés, mint
  Bjornnál). **De** az új `ci_prod_audit.yml` sor azt állítja, hogy a
  workflow „scheduled + `workflow_dispatch`" triggerre fut — ez **ma nem
  igaz**: `.github/workflows/ci_prod_audit.yml:24-25` kizárólag
  `workflow_dispatch:`-et tartalmaz, nincs `schedule:` blokk, és a fájl
  saját fejléc-kommentje (`:19-21`) explicit indokolja, miért nincs cron.
  Ez nem régi, hátrahagyott elavulás, hanem a **mai batch-szerkesztés
  terméke** — és pontosan azzal a ténnyel áll ellentmondásban, amit ez a
  register saját maga rögzített ugyanaznap: a **3.2 tétel 2026-08-21-i
  elutasítása** (fentebb), ahol Jamal egy `schedule:` trigger hozzáadását
  próbálta ki, a felhasználó a `LAB_ONLINE`-drift miatt leállította, és a
  diffet commit előtt visszaállította — a workflow ma pontosan olyan, mint
  a kísérlet előtt (nincs schedule). Az ügynökfájl így egy friss, hamis
  tényt állít, amit a register saját naplója ugyanabban a körben cáfol.
  **Priya fájlja — érintetlen, egyetértek Gaz döntésével.** A fájl már ma
  is explicit figyelmezteti az olvasót („Confirm current state yourself …
  environments drift"), ami az 5.5 által hiányolt védelmi mintát más
  eszközzel valósítja meg, mint a másik három (nem a tényt frissíti, hanem
  bizonytalanná teszi, ahol az valóban bizonytalan). Spot-check ezen a
  gépen: `semgrep` valóban elérhető (`~/.local/bin/semgrep`, symlink),
  `pip-audit` valóban telepítve `pipx`-szel, PDF-eszköz (`pandoc` /
  `wkhtmltopdf` / `weasyprint`) valóban egyik sincs — a fájl állítása ma is
  helytálló. Nem tekintem nyitott résznek.
  **Következtetés:** a tétel nem zárható le hiánytalanul — 3 a 4 fájlból
  pontos, a negyedik (Jamal) egy új, konkrét, azonosított hibát tartalmaz.
  A tétel `[ ]` marad, szövege változatlan; a hátralévő javítás egysoros
  (a `ci_prod_audit.yml` táblasorból törölni a „scheduled + " részt) →
  **vissza Gaznak**, a fájl gazdájának (5.1 döntés szerint).

- **2026-08-21 — 5.7 lezárva, Kwame verifikálta.** Az eredeti tétel két
  konkrét hiányt nevezett meg: a 11 fős rosterből csak kettő avatár készült
  el, és egyik sincs bekötve a `TEAM.md`-be. Mindkettő megszűnt: lásd 2.8
  (mind a 11 megvan, mind a 11 be van kötve, helyes elnevezéssel). A skill
  saját fájlja (`.claude/skills/team-avatars/SKILL.md:79-88`) ma már a
  valódi állapotot írja le konvencióként („Capitalized first name,
  directly in `avatars/`… this is the convention all current files
  follow"), nem ellentmond neki.
  **Maradék, nem blokkoló rés, footnote-ként rögzítve (a 2.12/3.11-nél
  alkalmazott konvenció szerint):** a SKILL.md kifejezetten előírja, hogy
  minden legenerált avatar prompt-szövegét naplózni kell magában a
  skill-fájlban, tartós rekordként (`:90-94`) — ma ennek csak **1/11**
  felel meg (Jamal worked example-je, `:41-52`); a `## Background colors
  already in use` táblázat is elismeri, hogy Yuki háttérszíne „not
  recorded, check `Yuki.png` directly", a többi 9 személy prompt-szövege
  pedig sehol nincs rögzítve a fájlban. Gaz nem pótolta ezt utólagos
  kitalált prompttal — helyesen, mert az hamis rekordot hozott volna létre.
  Ez a rés más jellegű, mint az eredeti tétel diagnózisa (nem hiányzó
  kimenet, hanem hiányzó dokumentáció a meglévő kimenetről), ezért nem
  tartja nyitva 5.7-et, de érdemes egy jövőbeli körben külön megnézni, ha
  valaki a `team-avatars` skillhez nyúl.

- **2026-08-21 — 5.8 lezárva caveattal, Kwame verifikálta.**
  `.claude/commands/` létezik, 4 fájllal (`register-status.md`,
  `rebuild-dashboard.md`, `local-gate.md`, `new-rule.md`), mindegyik
  helyes `description`/`argument-hint` frontmatterrel.
  **`register-status.md`, `rebuild-dashboard.md`, `new-rule.md` — pontos.**
  A `rebuild-dashboard.md` normalizáló `sed` kifejezését szó szerint
  összevetettem a `ci_code_checks.yml` `regenerate_console` jobjának saját
  `normalize()` függvényével (`:571-576`) — byte-azonos minta
  (timestamp-regex, 40 karakteres SHA-regex), ugyanaz a kizárt útvonal
  (`outputs/results/` kihagyva, csak `outputs/reports/`, `README.md`,
  `docs/index.html` figyelve), ugyanaz a „byte-identical, nothing to
  publish" / „only generation timestamps moved" megkülönböztetés. A
  `new-rule.md` `python scripts/new_rule.py "$ARGUMENTS"` hívása egyezik a
  script tényleges pozicionális-argumentum szignatúrájával (`--help`
  ellenőrizve), és a Yuki→Bjorn átadási sorrend egyezik a `CLAUDE.md`
  delegálási modellel.
  **`local-gate.md` — a parancsok és flag-ek pontosak, a sorrend-állítás
  nem.** Mind a hét lépés (`ruff check .`, `pytest`,
  `validate_sigma.py --schema …`, `check_mitre_tags.py`,
  `check_detect_id_uniqueness.py`, `check_test_routing.py`,
  `check_version_bump.py --base-ref …`) létező scriptre és valós, `--help`-
  fel ellenőrzött szignatúrára hivatkozik (a `check_test_routing.py`
  „warns, doesn't hard-fail without `--strict`" állítása is egyezik a
  tényleges `--help` szöveggel). **De** a fájl kifejezetten azt állítja,
  hogy „the same order `ci_code_checks.yml` and the validation stage of
  `ci_dev_workflow.yml` do" — ez a 4-6. lépésre **nem igaz**: a
  `ci_dev_workflow.yml` tényleges lépéssorrendje (`git show`, sorszám
  szerint olvasva) `Validate Sigma rules` → `Check every rule has a job
  that can run its test` (`check_test_routing.py`, `:529-535`) → `Check
  detect_id uniqueness` (`:552-557`) → `Check MITRE ATT&CK tags`
  (`:577-582`) → `Check version bump discipline` (`:625-647`) — vagyis
  `check_test_routing` → `check_detect_id_uniqueness` → `check_mitre_tags`,
  míg a `local-gate.md` `check_mitre_tags` → `check_detect_id_uniqueness`
  → `check_test_routing` sorrendet ad. Funkcionálisan ártalmatlan (a hét
  ellenőrzés egymástól független, a „stop at first failure" viselkedés
  ugyanazt az eredményt adja, csak más hibaüzenet-sorrendben többszörös
  bukás esetén), de a fájl saját állítása a sorrendről pontatlan. Egysoros
  javítás (3 lépés felcserélése) → **vissza Gaznak**, a fájl gazdájának.
  Nem tartom ezt elég súlyosnak ahhoz, hogy a tételt nyitva hagyja — a
  tényleges parancsok és kapuk helyesek, csak a leírás egy mondata nem —,
  de rögzítve, hogy ne vesszen el.

- **2026-08-21 — 5.5 lezárva, a Jamal-fájl javítását Kwame verifikálta.**
  Gaz javította a korábban jelzett hibát: `.claude/agents/Jamal - DevOps
  Engineer.md` `ci_prod_audit.yml` tábla-sora mostantól „`workflow_dispatch`
  only, manually triggered" (a „scheduled + " rész törölve), plusz egy
  megjegyzés, hogy egy ütemezett változatot felvetettek és elutasítottak
  ugyanaznap (register 3.2) `LAB_ONLINE`-drift kockázat miatt.
  **Önálló ellenőrzés, nem a javítás saját szövegének visszaolvasása:**
  `.github/workflows/ci_prod_audit.yml:24-25` `on:` blokkja ma is
  kizárólag `workflow_dispatch:`-et tartalmaz, nincs `schedule:` — a fájl
  saját fejléc-kommentje (`:19-21`) ugyanezt indokolja, változatlanul. A
  register saját 3.2 tétele (fentebb, 119. sor és a hozzá tartozó
  2026-08-21-i Napló-bejegyzés) szó szerint alátámasztja az új megjegyzés
  állítását: Jamal ténylegesen megpróbált egy `schedule:` triggert
  hozzáadni, a felhasználó a `LAB_ONLINE` és a lab tényleges
  áramállapotának szétcsúszása miatt leállította, és a diffet commit előtt
  visszaállította — a mai `workflow_dispatch`-only állapot ennek pontosan
  megfelel. A mai javítás nem termelt új elavulást (ellentétben a tegnapi
  első kísérlettel).
  A `.claude/commands/local-gate.md` mellékesen említett sorrend-cserét
  (4-6. lépés `check_test_routing` → `check_detect_id_uniqueness` →
  `check_mitre_tags`-re) is ellenőriztem: a fájl ma pontosan ezt a
  sorrendet adja, egyezik a `ci_dev_workflow.yml` tényleges lépéssorrendjével
  (lásd az 5.8 lezárásának fenti indoklását) — ez az 5.8-hoz tartozó
  tisztogatás volt, nem önálló tétel, és nem igényelt újranyitást, ahogy
  Gaz is jelezte.
  **Következtetés:** mind a négy megnevezett ügynökfájl (Kwame, Jamal,
  Bjorn) pontos, illetve (Priya) szándékosan és indokoltan érintetlen. A
  tétel hiánytalanul lezárva.

- **2026-08-21 — 5.6 lezárva, három megnevezett hiányból egy megvalósítva,
  kettő tudatosan elhalasztva — a tétel a régi register „elutasítás is
  lezárás" szabálya szerint (26-27. sor) ennek ellenére hiánytalanul zárt,
  nem marad nyitva a fel nem épített részekért.**
  **(a) `pipeline-ci-gotchas` — megépült, verifikálva.**
  `.claude/skills/pipeline-ci-gotchas/SKILL.md` létezik, 269 sor, 8
  kategória (A–H), 24 megnevezett csapda, mindegyik konkrét
  `.github/workflows/*.yml` fájl:sor-hivatkozással és valós incidenssel
  vagy védekező kódrészlettel alátámasztva (pl. `run 31307470773`,
  `run 30154222981`, „named incident run #67") — nem spekulatív lista,
  minden bejegyzés forrása visszakereshető. Nem stub. A `Skill` tool
  ellenőrizve mind a három megnevezett ügynökfájl frontmatterjében:
  `Jamal - DevOps Engineer.md` (`tools: … Bash, Skill`), `Priya -
  Application Security Engineer.md` (`tools: … Bash, Skill, WebSearch…`),
  `Kwame - Compliance Analyst.md` (`tools: … Edit, Skill`) — egyiknél sem
  volt ott korábban, tehát egyik sem tudott volna ténylegesen skillt hívni
  előtte. Mindhárom fájlban van tényleges hivatkozás a skillre a releváns
  ponton (`grep -n pipeline-ci-gotchas` mindhárom fájlon talál — Jamal:
  „Check the `pipeline-ci-gotchas` skill (via the Skill tool) first",
  Kwame: ugyanez a mondat a saját instrukciómban, Priya: két külön helyen,
  a függőség-audit és a workflow-mintázat-értékelés lépésénél). A hivatkozás
  a `pipeline-ci-gotchas` skill saját leírásában is szerepel a triggerek
  között. Teljes, valódi lezárás erre a részre.
  **(b) rule-browser generátor-konvenciók — kiértékelve, tudatosan
  elhalasztva, nem épült meg.** Sienna vizsgálata szerint az eredeti
  indoklás két lába kidőlt: a `@@MARKER@@`-hiba (2026-08-10) mára
  kódszintű védelmet kapott (`generate_stats.py` `SystemExit`-et dob
  eltérésnél, nem emberi tudásra van szükség hozzá), a „hiányzik a
  `dataviz` skill" hivatkozás pedig a register saját, azóta korrigált
  téves ellenőrzésén alapult (lásd **2.12** lezárása, 2026-08-21 — a
  `dataviz` létezik, csak nem a `.claude/skills/` alatt). A
  cross-specialista-facing rész (normalizált diff-logika) ma a
  `.claude/commands/rebuild-dashboard.md`-ban él, amit Gaz ugyanazon a
  napon épített — ellenőrizve az 5.8 lezárásakor, hogy a fájl normalize()
  mintája byte-azonos a `ci_code_checks.yml` `regenerate_console` jobjáéval.
  **(c) audit-register konvenciók — kiértékelve, tudatosan elhalasztva, nem
  épült meg.** Saját vizsgálatom szerint a Napló/státuszjelölő konvenció
  már ma is jól lefedett a „olvasd el a fájlt, kövesd a konvencióját"
  elvvel (ez már a saját ügynökfájlam instrukciója is), és ezt a mai
  körben kétszer is bizonyítottam működés közben (2.8/5.7/5.8, majd 5.5
  lezárása — mindkétszer a fájl saját, meglévő mintáját követtem, skill
  nélkül). Egy valódi, szűk rést találtam — a „Kész súly" sor más
  jelentéssel bír itt (befagyasztott induló állapot), mint a lezárt
  `remediation-plan.md`-ben (élő számláló) — de ezt Gaz egy egysoros
  pontosítással oldotta meg a skill helyett; ellenőrizve, a megjegyzés
  ténylegesen ott van a 31-34. sorban: „Ez a v1.0 kiindulási alapállapot,
  szándékosan befagyasztva — nem élő számláló, egyetlen lezárás sem
  növeli, ellentétben a lezárt `remediation-plan.md` azonos formátumú
  sorával."
  **Következtetés:** (a) valódi, verifikált megvalósítás; (b) és (c) nem
  hiányzó munka, hanem szakértői ajánlásra tudatosan elutasított/elhalasztott
  megoldás — pontosan az a mintázat, amit a register saját maga „elutasítás
  is lezárás" elve előír. A tétel nem marad nyitva a fel nem épített
  részek miatt.

- **2026-08-21 — 5.11 lezárva, Kwame verifikálta a Yara által épített
  táblát a `remediation-plan.md` ellen.** Új **8. szakasz** ("Lépték- és
  feltételfüggő döntések — élő figyelőlista", fentebb) rögzíti a tábla-
  javaslatot, ahogy a tétel szövege kérte: kiváltó / mérhető-e ma / mai
  státusz oszlopokkal, a régi register négy elutasított tételére
  (**3.8**, **4.1**, **4.4**, **4.11**), a **4.4**-et a saját maga
  hordozta két független feltétel szerint (**4.4a** ES/RBA, **4.4b**
  throttling/drilldown) szétbontva.
  **Önálló ellenőrzés, nem a relé-üzenet visszaolvasása:** mindhárom
  forrásidézetet közvetlenül `audit/remediation-plan.md`-ben néztem meg.
  (1) **4.11** — `:186` szó szerint tartalmazza: „mert 500+ szabálynál nem
  skálázna". (2) **3.8** — `:171` szó szerint: „a felhasználó
  rákérdezésére kiderült, hogy sosem volt tényleg alátámasztva"; a Napló
  `:1134` ugyanezt ismétli meg, más szavakkal, közvetlenül a döntés
  napján rögzítve („az eredeti audit-tétel »27 még kezelhető, 150 már
  nem« állítása nem volt ténylegesen alátámasztva — átvett feltételezés
  volt a 2026-07-26-os statikus átvizsgálásból") — két független helyen,
  nem csak egyszer állítva. Ez a sor korábban már egyszer helyesen
  visszautasításra került ebben a registerben is (lásd a 2026-08-18-i
  revíziós Napló-bejegyzést, Yara eredeti briefjének 2. pontosítása) —
  ma ugyanez a korrekció épül be a táblába, nem újra felfedezve, hanem
  megerősítve. (3) **4.1**/**4.4** — `:176` és `:179` mindkettő explicit
  „megvizsgálva, elutasítva" fejléccel zár, feltételt (nem számot) ad meg;
  a `:179` szövege szó szerint „Splunk Enterprise Security"-t mond, nem
  Elastic-et — Yara saját maga vette észre és javította ezt a dispatch-
  brief-jében, mielőtt a tábla elkészült volna, ellenőrizve, hogy a végső
  táblasor is a helyes terméknevet hordozza.
  **Repo-oldali spot-check a "mai státusz" oszlophoz:** `ls rules/sigma/
  *.yml *.yaml 2>/dev/null | wc -l` → **28** (a `remediation-plan.md`
  4.11-es lezárásakor 27 volt, a tábla ezt helyesen frissként, nem a
  register eredeti számaként adja meg); `find rules/sigma -mindepth 1
  -type d` → **üres**, a könyvtár ma is flat, megerősítve a 3.8 sor „nincs
  nyitott kiváltó" állítását.
  **Következtetés:** mindhárom forrásidézet pontos, a 4.4a/4.4b szétválás
  indokolt és a register saját szövegéből következik, a termék-névkorrekció
  (Splunk ES, nem Elastic) helytálló. A tábla élő figyelőlistaként kerül a
  registerbe, nem a Naplóba — a Napló egyszeri esemény, ez viszont minden
  jövőbeli Kwame-körön újranézendő; a 4.1/4.4a sorok kifejezetten nem
  git-ből deríthetők, azokhoz direkt kérdés kell a felhasználónak minden
  körben. A tétel hiánytalanul lezárva.

- **2026-08-21 — 5.4 lezárva, Kwame verifikálta.** Kai két új fájlt épített:
  `.mcp.json` (repógyökér) és `docs/mcp-setup.md`; Gaz saját hatáskörben
  (a `.claude/agents/*.md` az ő felülete) egy mutatót tett Kai ügynökfájljába
  a doksira.
  **`.mcp.json` — valódi, nem stub.** `python3 -m json.tool` → érvényes JSON.
  Mind a négy megnevezett szerver jelen van (`python3 -c "json.load(...).
  keys()"` → `github`, `semgrep`, `playwright`, `chrome-devtools`). Nulla
  literális titok: `grep -nE 'ghp_|gho_|github_pat_|Bearer [A-Za-z0-9]'` a
  fájlon **nulla találat**; az egyetlen auth-sor `"Authorization": "Bearer
  ${GITHUB_TOKEN}"` — környezeti változó, nem beégetett érték, pontosan a
  tétel saját követelése („a titkokat környezeti változóból olvasva").
  **`docs/mcp-setup.md` — valódi, nem stub.** 130 sor, mind a négy
  szerverhez saját szakasz egy-egy „One-time setup" listával, plusz egy
  explicit „Things this doc deliberately does not solve" szakasz (CI
  npm-egress, verziópinelés) — ez utóbbi nyitva hagyva, nem eltitkolva.
  **Kereszt-ellenőrzés a doksi állításai és a `.mcp.json` tényleges tartalma
  között, soronként:** `github` — a doksi „`https://api.githubcopilot.com/
  mcp`" URL-t és „`Authorization: Bearer ${GITHUB_TOKEN}`" fejlécet állít —
  mindkettő szó szerint egyezik a `.mcp.json` 5. és 7. sorával. `semgrep` —
  a doksi „just runs `semgrep mcp`" — egyezik (`"command": "semgrep",
  "args": ["mcp"]`). `playwright` — a doksi „runs `npx -y @playwright/
  mcp@latest` with no `--executable-path` override" — egyezik, és a
  `.mcp.json`-ban ténylegesen nincs `--executable-path` kulcs (a felhasználói
  scope-ban a doksi szerint volt egy gép-specifikus Chromium-útvonal, ez a
  checked-in configból tudatosan kimaradt). `chrome-devtools` — a doksi
  „runs `npx -y chrome-devtools-mcp@latest` as-is" — egyezik.
  **Mellékes ellenőrzés:** `.claude/agents/Kai - Platform Engineer.md`
  ténylegesen tartalmaz egy mutatót (`:16`, „see `docs/mcp-setup.md` for
  what each server needs") — a Gaz által állított külön szerkesztés valós.
  **Nem verifikálható innen, a doksi maga is így jelzi:** hogy a leírt
  one-time setup lépések (token-mintés, `pipx install semgrep`, `npx
  playwright install chromium`) ténylegesen működnek-e egy tényleg friss
  klónon vagy CI-környezetben — ez a repón kívüli, élő végrehajtást igényelne,
  amit ez a kör nem futtatott le; a doksi két nyitva hagyott korlátja (helyi
  scope felülírás, CI npm-egress/verziópinelés) pontosan ezt a határt jelöli
  ki, nem próbálja elfedni. A tétel hiánytalanul lezárva.

- **2026-08-22 — 4.4 részlegesen lezárva, Jamal jelentése alapján
  könyvelve (nem újra levezetve).** A `ci_dev_workflow.yml`-ben a
  korábbi 4 gépi commit (prune / SPL / verify results / dashboard)
  közül az első kettő már `6e29280` óta (2026-08-20, „refactor(ci-dev):
  merge prune and SPL commits into one") egy commitba van összevonva —
  az a commit-üzenet saját maga mondja, hogy „Register item 4.4, safe
  half only." Mai spot-check: `grep -n "git commit -m"
  ci_dev_workflow.yml` → pontosan **3** találat marad (`:949` összevont
  prune+SPL, `:2267` verify-results, `:2385` dashboard) — egyezik
  Jamal állításával.
  **A maradék két commit (verify-results, dashboard) nem vonható
  tovább össze a jelenlegi architektúrában:** a `splunk_verify` a
  self-hosted lab runneren fut, az `update_dashboard` gyakran másik
  runneren, friss checkout-tal, és kizárólag `origin/dev`
  munkafájából olvas — a git commit az egyetlen runnerek közötti
  adatátviteli út. Ez pontosan a `pipeline-ci-gotchas` skill D
  szakaszában (`ci_dev_workflow.yml:2116-2141`) és a projekt-memóriában
  („verify/dashboard commit coupling") már rögzített tény, ezt a kör
  nem vizsgálta újra, mert nincs miért — összevonásuk azt kockáztatná,
  hogy az `update_dashboard` egy elavult PASS-verdiktet republikál
  csendben, ha a friss verify-eredmény éppen nem ért be időben.
  **Két valódi további út maradt, egyik sem közeli munka:** (a) az
  `outputs/results/` GH Actions cross-runner artifactként utazzon git
  helyett, (b) a generált artefaktumok teljesen kikerüljenek a `dev`
  branchről — ez utóbbi a 3.5-tel ér össze. Mindkettő nagyobb léptékű
  átalakítás, nem ennek a tételnek a hatóköre.
  **Következtetés:** a tétel se nem „folyamatban" (nincs tervezett
  következő lépés a közeljövőben), se nem teljesen lezárt (a hat
  eredeti út ötre csökkent, nem egyre) — a tételszöveg és a
  státuszjelző ezért „részlegesen lezárva"-ra módosult, a checkbox
  `[ ]` marad, mert a maradék kockázat és a döntés (3.2/3.5-ös léptékű
  redesign) valós és nyitva van. `ci_code_checks.yml` és
  `ci_prod_audit.yml` egyenként továbbra is 1-1 gépi commitot csinál,
  ezt ez a tétel sosem célozta, változatlan. **Modell:** ez a
  könyvelési kör Sonnet 5-ön futott.

- **2026-08-22 — 5.10 lezárva, Kwame verifikálta.** `CLAUDE.md` 7. pontja
  ma valóban tartalmazza a „Leave a trace, or the rule is unfalsifiable"
  alpontot — közvetlenül a fájlból ellenőrizve, nem a register saját
  szövegét visszaolvasva. Az alpont pontosan azt a rést zárja, amit a
  tétel leírt: egy per-dispatch modell-override csak az adott hívásban él,
  utólag semmi nem rögzíti, melyik diszpécselés melyik modellen futott,
  tehát nem lehetne megmondani, segít-e az eszkalációs szabály; a fix egy
  sornyi konvenció, nem új artefaktum — amikor egy specialista
  zárójelentése amúgy is tartós helyre kerül (register Napló, commit-
  üzenet), a modell neve is odakerül, rutin diszpécseléseknél nem
  visszamenőlegesen. `git log --oneline -1 --grep="5.10"` → `f5373e5`
  („docs(process): trace which model ran a dispatch, where it's already
  logged"); a commit-üzenet szó szerint mondja: „Register item 5.10." A
  diff (`git show f5373e5`) pontosan ezt a 10 sort adja hozzá `CLAUDE.md`
  7. pontjához, más fájlt nem érint. Gaz jelzése szerint a konvenciót még
  aznap éles Napló-bejegyzésben is használta (a 4.4 zárásánál, „ez a
  könyvelési kör Sonnet 5-ön futott") — ez tehát nem csak papíron létező
  szabály, hanem már bizonyítottan alkalmazott, ez a jelen bejegyzés a
  második valódi előfordulása. A tétel hiánytalanul lezárva. **Modell:**
  ez a könyvelési kör Sonnet 5-ön futott.

- **2026-08-22 — 4.8 felvéve és azonnal lezárva, Kwame könyvelte
  (retroaktív tétel, Gaz nyomozása alapján, önállóan ellenőrizve, nem a
  dispatch-üzenet visszaolvasva).** Az 5 `[dashboard-decoupling]`
  kódkomment (`ci_dev_workflow.yml:1131,1601,2116,2295,2578` — `grep -n`-nel
  frissen ellenőrizve; az audit v1.0 kiadásakor még csak 3 volt, a szám a
  fájl azóta történt szerkesztései miatt nőtt 5-re) egy sosem regisztrált,
  de valós döntést takar. `git show cb99a97` (2026-08-14, „fix(ci): decouple
  dashboard/Pages publish from Splunk-dependent chain") — a diff maga
  ellenőrizve, nem csak a commit-üzenet elfogadva: az `update_dashboard`
  job ténylegesen létezik, `needs: [prepare_validate_convert, splunk_verify]`,
  és a jelenlegi kódkommentek (`:1131`, `:2295`, `:2578`) egybehangzóan
  írják le, hogy LAB_ONLINE-tól és `splunk_verify` tényleges kimenetelétől
  függetlenül fut; a `generate_stats.py` hívás és a README/`docs/index.html`
  commit ténylegesen a `splunk_verify` jobból ebbe a jobba költözött át
  (a diff törli a régi „Generate stats and update README" lépést
  `splunk_verify`-ból, és hozzáadja az egyenértékű lépést `update_dashboard`-
  hoz); a `deploy_pages` `needs: [update_dashboard]`-ra vált a korábbi
  `splunk_verify`-függés helyett (`:2578` kommentje ezt a régi
  `needs.splunk_verify.result == 'success' || 'failure'` feltételt idézi
  szó szerint, mint amit a változás lecserélt). A commit-üzenet állítása
  (LAB_ONLINE=false esetén a korábbi lánc a dashboard-publikálást is némán
  kihagyta, ezért egy új szabály SPL-je bekerült, de sosem jelent meg a
  dashboardon) egyezik mindhárom megmaradt kódkomment tartalmával.
  **Új tétel: 4.8**, a `4 · Robusztusság és karbantarthatóság` szakaszban
  (a `4.7` volt eddig a szakasz legmagasabb tétele, `grep`-pel ellenőrizve)
  — ez a szakasz illik rá tartalmilag, nem a 2. (dokumentáció): maga a
  döntés pipeline-robusztusság (a Pages-publikálás ne függjön hamisan egy
  másik alrendszer állapotától), nem dokumentáció-hiány; a **2.10** marad
  a *dokumentálatlanság* tünetének helye, nem a döntés tartalmának.
  A szakaszfejléc `(7)` → `(8)`-ra módosult, a teljes register-súly
  **82 → 84** (a robusztusság-kategória 7×2=14 → 8×2=16), a `Kész súly`
  sor nevezője és a projektált pontszám képlete is frissült ugyanerre —
  ugyanaz a minta, mint a 3.13 felvételekor (ld. fent, 2026-08-21).
  **2.10 ezután lezárva, de nem hiánytalanul.** A tétel saját maga két
  remediációs formát ajánlott: (a) valódi, számozott, lezárt tétel a
  tényleges tartalommal, vagy (b) a kódkommentek a commitra/PR-re
  hivatkozzanak a placeholder helyett. Gaz az (a) utat választotta — ez
  most elkészült, tehát a register-oldali hiány (nulla előfordulás a
  lezárt `remediation-plan.md`-ben, egy sosem regisztrált munka) megszűnt.
  A kódkommentek szövege viszont **ma is szó szerint** `[dashboard-
  decoupling]`-et mond mind az 5 helyen — ezt még nem cserélték `4.8`-ra,
  és ez a csere kifejezetten Jamal hatásköre (`ci_dev_workflow.yml`
  tartalma), Kwame nem szerkesztheti. A 2.10 checkboxa `[x]`-re váltott,
  mert az eredeti hiba (a hivatkozott register-tétel nem létezett) valóban
  megszűnt, de a tétel szövege és az → sor mostantól a fennmaradó, Jamalnak
  szánt lépésre mutat (5 komment cseréje), nem a régi hiányra. **Modell:**
  ez a könyvelési kör Sonnet 5-ön futott.

- **2026-08-22 — 3.7 elutasítva.** A felhasználót közvetlenül megkérdezték,
  érdemes-e egy lefedettségi *cél* (következő prioritási technikák,
  cél-szám vagy -ütem) adatként rögzíteni, hogy a dashboard ne csak a mai
  állapotot mutassa, hanem a felé haladást is. A válasz elutasító, saját
  szavaival: „szerintem erre nincsen szükség. Én majd a saját ütememben
  akarom fejleszteni ezeket a szabályokat." Ez kifejezetten a *célkitűzés
  formalizálása és követése* ellen szól, nem a mögöttes lefedettség-
  priorizálás ellen — a **3.8** tétel Yara/Masha-javaslata (Privilege
  Escalation és Lateral Movement előrevétele) ettől függetlenül,
  változatlanul áll, végrehajtásra vár. Nincs végrehajtó.

- **2026-08-22 — 2.11 lezárva, Kwame verifikálta.** `.github/dependabot.yml:1-14`
  ma valóban az átírt fejlécet mutatja, közvetlenül a fájlból ellenőrizve
  (uncommitted working tree állapotban, ahogy a mai többi tétel esetén is).
  **Előtte** (a tétel eredeti idézete szerint): „The pins exist because prod
  re-runs the converter over the same Sigma source dev already converted…" —
  ez a `3.2` előtti világot írta le, amikor a prod-oldali újrakonverzió és a
  drift-gate még létezett. **Utána** (`:4-8`): „The pins exist for dev's own
  conversion reproducibility (register item 2.11): dev converts every Sigma
  rule to SPL with this exact toolchain, and the bytes it produces are what
  gets committed, atomic-tested, and eventually deployed, so the conversion
  needs to be reproducible on its own terms, not tied to whatever happens to
  resolve on a given day…" — az indoklás most a `3.2` utáni valós mechanizmust
  írja le (dev saját reprodukálhatósága), és a mondat maga is hivatkozza a
  `2.11` tételszámot. **Jamal** végezte a szerkesztést, ma korábban, a mai
  könyvelési kör előtt. A tétel hiánytalanul lezárva. **Modell:** ez a
  könyvelési kör Sonnet 5-ön futott.

- **2026-08-22 — 3.6 lezárva, implementálva, éles megerősítés még nyitott,
  Kwame verifikálta.** `ci_dev_workflow.yml` új `notify_pipeline_status`
  jobja (jelenleg uncommitted a munkafában, közvetlenül a fájlból
  ellenőrizve, nem a dispatch-üzenet visszaolvasva) — `open_promotion_pr`
  után, `deploy_pages` előtt beszúrva (`:2878-3009`). Megfelel a tétel
  szövegének: (1) **Slack-üzenetet küld** a `dev` environment-hez kötött
  `SLACK_WEBHOOK_URL` secreten keresztül — a secret jelenlétét és
  helyes hatókörét Kai már ellenőrizte (ezt a jelen könyvelési kör nem
  ismételte meg, mert nincs hozzáférése a titkosított értékhez; a
  workflow-oldali *használat* helyessége viszont igen, ld. lent). (2)
  **A futás PASS/FAIL verdiktjét** `needs.splunk_verify.result`-ból
  veszi (`RUN_RESULT` env, `:2929`, `case` ág `:2944-2949`) — ugyanaz a
  minta, mint `open_promotion_pr`-nál (job *result*, nem `.outputs`,
  a fájl saját, korábban rögzített okából). (3) **A `stats.json`
  aktuális számait** (`verified_pass`, `verified_fail`,
  `verified_not_verified`, `verified_stale`, `total_rules`,
  `pass_rate_pct`) a contents API-n olvassa dev HEAD-jéről (`:2961-2980`),
  ugyanazzal a mintával, mint `open_promotion_pr` `stats_json`
  lekérése. **Nem blokkoló:** minden hibaág (`SLACK_WEBHOOK_URL` hiányzik
  `:2933-2936`, `stats.json` nem olvasható `:2962-2965`, `curl` nem éri el
  a webhookot `:2999-3002`, nem 2xx válasz `:3003-3007`) kizárólag
  `::warning::`-ot ír, a lépés minden ágon `exit 0`-val zár (`:3009`) —
  ellenőrizve, hogy egyik hibaág sem hagyja el a scriptet nem-nulla
  kilépőkóddal. **Helyesen skópolt:** `environment: dev` job-szinten
  (`:2920`), a `SLACK_WEBHOOK_URL` kizárólag a lépés saját `env:`
  blokkjában olvasva (`:2926`), a job-szintű `if:` (`:2906-2909`) csak
  `github.event_name`/`github.ref`/`needs.update_dashboard.result`-ot néz,
  environment-scope-olt secretet vagy var-t nem — pontosan az a csapda,
  amit a `pipeline-ci-gotchas` skill B szakasza ismertet
  (`SPLUNK_APP`/`SPLUNK_VERIFY_TLS` a job-szintű `if:`-ben üresként
  olvasna), és amit a job saját kommentje (`:2913-2919`) kifejezetten
  nevesít is, helyesen hivatkozva `audit/remediation-plan.md` 2.20-ára
  (a jelen, aktív register 2. szakasza csak 2.14-ig megy — a fájlnevesítés
  itt helyes, a `pipeline-ci-gotchas` skill I szakaszában leírt csapda
  elkerülve). **Eltérés a tétel saját javaslatától:** a tétel szövege a
  „legolcsóbb formaként" egy GitHub Issue automatikus nyitását/frissítését
  javasolta; a felhasználó saját döntése alapján helyette egy általa
  most először beállított Slack webhook lett a választott megoldás — ez a
  tétel saját „vagy bármilyen tartós felület" záradéka alá fér, csak nem
  a legolcsóbb útvonal. **Nyitva maradó rész, explicit:** az élő
  Slack-posztolás ma **nincs valódi pipeline-futáson igazolva** — Jamal
  jelentése szerint a script logikáját helyi stub-harnessel validálta
  (siker / hiba / kihagyott / hiányzó-secret / curl-hiba / nem-2xx-válasz
  ágak, mindegyik `exit 0`-val), de nem indított és nem posztolt valódi
  workflow-futást; ezt a jelen könyvelési kör sem tudta pótolni (nincs
  élő dispatch-hozzáférés ehhez). A tétel ezért **implementálva, első
  éles megerősítésre várva** státusszal zár, nem teljesen bizonyított
  lezárásként — ugyanaz a mintázat, mint a 4.3-nál (2026-08-20, szimulált
  Windows-ellenőrzés helyi futtatással, valódi Windows-futtatás nélkül) és
  a lab-függő tételeknél általában: a checkbox `[x]`-re vált, mert a
  megvalósítás valós és a leírt viselkedésnek megfelel, de a fennmaradó
  bizonyítási rés (első valódi Slack-poszt megfigyelése egy tényleges
  `dev` push/`workflow_dispatch` futáson) itt, a Naplóban rögzítve marad,
  nem hallgatva el. → **Jamal** (a tényleges, első éles futás megfigyelése,
  amikor a lab/pipeline legközelebb fut). **Modell:** ez a könyvelési kör
  Sonnet 5-ön futott.

- **2026-08-22 — register-audit (Kwame): 2.10 leíró szövege elavult, a
  checkbox marad `[x]`.** A teljes kört ellenőrizve: `remediation-plan.md`
  változatlanul 54/54 (54 `[x]`, 0 `[ ]`), `register.html` és a `.md`
  ugyanattól a commit-tól (`facae74`, 2026-08-15) datálódik, egyik sem
  módosult azóta — nincs drift a lezárt register és a renderelt oldala
  között. A jelen (aktív) register: **34/52 lezárva** (nem 21/51 —
  a 2026-08-21-i állapot óta 13 tétel zárult, plusz retroaktívan felvett
  **4.8**, súly 82→84, a fejléc `84 = 6×3+8×2+13×1,5+11×1,5+14×1` képlete
  és a szekciófejlécek (6/14/13/8/11) `grep`-pel egyezik a tényleges
  tételszámmal). Spot-check a friss lezárásokon, közvetlenül a kódból:
  **2.11** (`dependabot.yml:4-8` valóban az új indoklást mutatja, a `2.11`
  hivatkozással), **3.6** (`notify_pipeline_status` job létezik
  `ci_dev_workflow.yml:2878`-tól, `SLACK_WEBHOOK_URL` fail-open logikával),
  **5.10** (`CLAUDE.md` 7. pontja tartalmazza a „Leave a trace" alpontot,
  `git log --grep=5.10` → `f5373e5`), **4.4 részleges** (`ci_dev_workflow.yml`
  ma valóban egy összevont prune+SPL commitot ír, `6e29280`) — mind valós.
  **Egy tétel szövege viszont elavult, magának a lezárt tételnek a
  ellenőrzésén belül:** a **2.10** (lezárva, tartalma átvitt **4.8**-ba) azt
  állítja, hogy a `[dashboard-decoupling]` placeholder-komment ma **5**
  helyen fordul elő (`:1131,1601,2116,2295,2578`). Közvetlen `grep` a mai
  `ci_dev_workflow.yml`-en: **8** előfordulás (`:1131,1606,2121,2278,2358,
  2581,2901,3014`). `git blame` szerint a záró commit (`1a5b4c2`,
  2026-08-22 17:02:45) már ekkor is tévedett — a 3 sorból álló **4.4**
  munkarész (`28f47e7`, 17:02:18, 27 másodperccel korábban) már bekerült,
  tehát a valós szám a zárás pillanatában **7** volt, nem 5; utána a
  **3.6** Slack-munka (`67e6805`, 17:37:25) hozzáadott egy nyolcadikat.
  A checkbox és a `→ Jamal (5 komment … → 4.8)` átnevezési feladat maga
  helyes marad — csak a szám és a sorhivatkozás stale. Nem javítom a
  tétel törzsszövegét (a mögöttes felület Jamalé), csak itt, a Naplóban
  rögzítem a pontos mai számot a következő végrehajtónak. **Következő
  valós, nem-docs tétel:** **3.8** (MITRE taktika-lefedettség, Privilege
  Escalation + Lateral Movement előrevétele Yara/Masha javaslata szerint,
  „Nincs végrehajtó" — lásd a 3.7 elutasítás Napló-bejegyzését fent) →
  **Yuki** (megvalósítás), **Bjorn** (review). **Modell:** ez a könyvelési
  kör Sonnet 5-ön futott.

- **2026-08-22 — 3.8 elutasítva/hatókörön kívül.** A felhasználó döntött: az
  új detekciós szabályokat mostantól személyesen írja, kifejezetten azért,
  hogy a detection engineeringet gyakorlatban tanulja meg — ez **nem**
  kerül átadásra Yukinak. Ez nem egyszeri kihagyás, hanem álló hatókör-
  döntés: a register mostantól nem tart nyilván szabályfejlesztési/
  lefedettségi-rés-írási tételt csapat-végrehajtandó „nincs végrehajtó"
  sorként — ez a fajta munka strukturálisan kívül esik azon, amit ez a
  register követ. A mögöttes megállapítás (a hét nulla-lefedettségű
  taktika, Yara/Masha priorizálása a Privilege Escalation és a Lateral
  Movement mellett) ettől még tényszerűen érvényes marad, és háttér-
  kontextusként megáll, ha a felhasználó saját maga veszi fel később —
  csak nem register-követett szállítandóként. Ezzel a nyitott halmaz
  **34/52**-ről **35/52**-re zárva. **Következő valós, nem-docs tétel:**
  a soron következő, ténylegesen csapat-végrehajtható tétel a listából
  (lásd a fenti nyitott `[ ]` tételeket, pl. **3.3**, **3.4**, **4.1**,
  **4.4** maradék fele) — Gaz dönt a sorrendről, miután ezt a hatókör-
  változást figyelembe vette. **Modell:** ez a könyvelési kör Sonnet 5-ön
  futott.

- **2026-08-23 — 3.3 elutasítva.** Gaz a lezárás előtt ellenőrizte a
  mögöttes tényeket: `config/backends.yml`-ben ma is egyetlen `splunk`
  blokk van; `.github/requirements.txt` kizárólag
  `pysigma-backend-splunk==2.1.0`-t pineli, tehát a repo ma egy második
  pySigma backend csomag nélkül fizikailag sem tudna másik célra
  konvertálni; a „több backend is működik" állítást a tesztfájlban
  felépített `TWO_BACKENDS` fixtúra (`tests/test_backend_config.py:106`
  körül) hordozza, ami a betöltőt teszteli, nem valódi `sigma convert`
  futást. A tétel javasolt megoldása (Yara ötlete) egy önálló CLI-próba
  lett volna, ami valódi backend + mintaszabályok ellen futtatná a
  konverziót és megmondaná, mi fordul le. A felhasználót közvetlenül
  megkérdezték, és megerősítette: **nincs terv második SIEM/backend
  bevezetésére** ebben a repóban. Terv nélkül a próba-eszköz megépítése
  ma hipotetikus jövőre tervezés lenne, ami ütközik a repo saját rögzített
  elvével („Don't design for hypothetical future requirements", CLAUDE.md)
  — ha valaha felmerül egy második backend, a kérdés újranyitható, de
  proaktívan nem épül rá eszköz addig. A `config/backends.yml` fejléc-
  kommentje ma valóban enyhén túlígér („a new backend is a new block
  below"), de ez önmagában dokumentációs pontatlanság, nem indokol
  munkatételt. Ezzel a nyitott halmaz **35/52**-ről **36/52**-re zárva.
  **Következő valós, nem-docs tétel:** a soron következő, ténylegesen
  csapat-végrehajtható tétel a fenti nyitott `[ ]` tételek közül (pl.
  **3.4**, **4.1**, **4.4** maradék fele) — Gaz dönt a sorrendről.
  **Modell:** ez a könyvelési kör Sonnet 5-ön futott.

- **2026-08-23 — 3.4 elutasítva.** Gaz a lezárás előtt ellenőrizte a
  mögöttes tényeket: a `scripts/verify/check_saved_search_hits.py`
  `dispatch_saved_search()` függvénye (kb. `:172-176`) a Splunk job
  státuszvégpontját (`/search/jobs/{sid}`) pollozza, amíg
  `dispatchState == "DONE"` nem lesz, és ehhez minden pollozási körben
  már ma is letölti a job teljes `entry[0].content` JSON-objektumát —
  ebből ma kizárólag a `dispatchState` mezőt olvassa ki. Ugyanez a
  válasz Splunk-natív módon tartalmazza a `scanCount` (a keresés által
  ténylegesen átvizsgált eseményszám — a keresés valódi költsége) és a
  `runDuration` (a job futásideje másodpercben) mezőket is, tehát a
  tétel javasolt megoldása (a szabály „költségének" rögzítése a
  `result.json`-ban a tüzelt/nem tüzelt verdikt mellett) **technikailag
  olcsón megvalósítható lett volna** — nulla új Splunk API-hívást
  igényelt volna, csak két további kulcs kiolvasását egy már úgyis
  minden futásnál letöltött válaszból. Gaz ezt a konkrét megvalósítási
  tervet (mit jelent a `scanCount`/`runDuration`, miért különbözik a
  helyesség-verdikttől mint „költség"-jelzés) részletesen elmagyarázta
  a felhasználónak. A felhasználó válasza, a pontos terv ismeretében:
  „nem látom értelmét ennek a fejlesztésnek" — gyakorlati haszon
  hiányára hivatkozó, nem a megállapítást vagy az olcsóságot vitató
  elutasítás. A mai, egyszemélyes/egy-labor környezetben nincs olyan
  helyzet, ahol a keresés „költsége" (scan-terjedelem, futásidő)
  számítana. **Ez nem azonos a lezárt register 4.1-es tételének
  (csendes ablak / FP-budget) elutasításával**, bár rokon indíttatású:
  mindkettő egy Splunk-oldali mérési finomítás, aminek ma nincs
  rákényszerítő operatív igénye. Ezzel a nyitott halmaz **36/52**-ről
  **37/52**-re zárva. **Következő valós, nem-docs tétel:** a fenti
  nyitott `[ ]` tételek közül a soron következő, ténylegesen
  csapat-végrehajtható (pl. **4.1**, **4.4** maradék fele) — Gaz dönt a
  sorrendről. **Modell:** ez a könyvelési kör Sonnet 5-ön futott.
