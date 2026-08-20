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

Kiindulás: **7,0 / 10**. Kész súly: **0 / 79**.

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
A teljes súly **79** = 6×3 + 7×2 + 11×1,5 + 11×1,5 + 14×1.
Projektált pontszám = `7,0 + 2,5 × (kész súly / 79)`.

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
- [ ] **2.8** `TEAM.md`: 11/11 „Avatar: pending", holott két avatár létezik · `TEAM.md:5,63,80,96,…` vs. `.claude/agents/avatars/Bjorn.jpg`, `Yuki.png` · Ráadásul a `team-avatars` skill (`.claude/skills/team-avatars/SKILL.md:84-89`) `<firstname-lowercase>.png` elnevezést és `![Bjorn](...)` bekötést ír elő — a két meglévő fájl nagy kezdőbetűs, az egyik `.jpg`, és egyik sincs bekötve. A `Yuki.png` 1,1 MB, a repo legnagyobb követett fájlja. **Kwame és Yara egymástól függetlenül ugyanezt találta meg** — a két átvizsgálás egyetlen teljes átfedése, ami önmagában is jelzés arról, mennyire látható ez a rés → **gazdátlan, lásd 5.1**
- [ ] **2.9** Nincs per-szabály dokumentáció, és a hozzá tartozó hivatkozás holt · `README.md:175` (issue #20), `.claude/agents/Bjorn - Detection Quality Engineer.md` frontmatter (a `rule_documentations/` könyvtárra hivatkozik, ami már nincs a repóban — az ügynökfájl maga jelzi ezt, de a mondat így is félrevezető) · A README szerint a metaadat-forrás kérdése megoldódott (minden a `rules/sigma/*.yml`-ben van), tehát az automatizálásnak nincs technikai akadálya. Ma egyetlen szabályról sincs önálló, olvasható lap sem a repóban, sem a rule browserben → **Gaz** priorizál, **Sienna** (generátor) vagy **Jamal** (CI-lépés)
- [ ] **2.10** Feloldatlan register-hivatkozás a kódban: `[dashboard-decoupling]` · `.github/workflows/ci_dev_workflow.yml:2064,2243,2526` · Három komment hivatkozik erre a „register item"-re; a lezárt `audit/remediation-plan.md`-ben **nulla** előfordulása van. A repo minden más ilyen kommentje valódi számozott tételre mutat (38 különböző azonosító). Ez egy elvégzett, de sosem regisztrált munka — a lezárt register így nem teljes rekord. Javaslat: vagy ebbe az új registerbe kerüljön be utólagos, lezárt tételként a tényleges tartalmával, vagy a kommentek a PR-re/commitra hivatkozzanak helyette → **Kwame** (register-könyvelés) + **Jamal** (kommentek)
- [ ] **2.11** A `dependabot.yml` indoklása a 3.2 előtti világot írja le · `.github/dependabot.yml:5-8` · „The pins exist because prod re-runs the converter over the same Sigma source dev already converted…" — a prod ezt már nem teszi (a `.github/requirements-deploy.txt` fejléce ezt helyesen le is írja). A pineknek ma is van értelme (a dev saját reprodukálhatósága), csak nem ez az. Konfigurációs komment, de a repo szerkesztési kultúrájában ezek dokumentumértékűek → **Jamal**
- [ ] **2.12** Élő hivatkozás egy nem létező skillre · `.claude/agents/Sienna - Frontend Engineer.md:48`: „when adding or redesigning any chart, graph, stat tile, or dashboard element, **invoke the `dataviz` skill first** … before writing chart code" · A `.claude/skills/` alatt három skill van: `mitre-attack-mapping`, `sigma-rule-authoring`, `team-avatars`. `dataviz` **nincs**. Ez nem elavulás, hanem működő hiba: kötelező érvényű utasítás egy nem teljesíthető lépésre, ami minden front-end diagram-munka elejére be van építve. Két út: megírni a skillt (a repo diagram-konvenciói ma a `page.css` 4 036 sorában és a `page.js` chart-kódjában élnek, tehát lenne mit rögzíteni), vagy törölni a sort. Yara találata, `grep`-pel megerősítve → **Gaz** dönt (skill-gazda kijelölése az 5.1-gyel együtt), tartalom **Sienna**
- [ ] **2.13** Nincs architektúra-dokumentum magáról a `.claude/` ökoszisztémáról · `docs/architecture/` négy mély referenciát ad a pipeline-ról, a csapatmodellről egyet sem · A `CLAUDE.md` előíró (ki mit birtokol, hogyan megy a delegálás), a `TEAM.md` roster — egyik sem „hogyan folyik a munka a gyakorlatban" referencia valódi példákkal. Egy `docs/architecture/agent_workflow.md` (Yuki→Bjorn átadás, egy Kwame-féle drift-elkapás, egy Gaz-féle feladatszétvágás, mindegyik valós esettel) egyszerre lenne onboarding-anyag és annak a dokumentálása, ami ebben a repóban ténylegesen újszerű. Yara javaslata; a jelen audit 5. szakasza pont azt bizonyítja, hogy van mit leírni → **Chloe**
- [ ] **2.14** Nincs `CONTRIBUTING.md` · ellenőrizve: a fájl nem létezik · A régi register **2.11**-e a CODEOWNERS-t és a PR-sablont utasította el mint „checklist-ballaszt" egy egyszemélyes repóban — ez a döntés áll. A `CONTRIBUTING.md` viszont más kérdésre válaszol: nem kapu, hanem egy helyen összeszedett szerzői folyamat (szabály-scaffold → validálás → review → promotion), ami ma öt dokumentum és három skill között van szétszórva. Alacsony prioritás az egyszemélyes valóság miatt, de olcsó, és a 2.6 (lokális futtatás) természetes otthona lenne. Yara javaslata → **Chloe**

## 3 · Funkció- és képességhiányok (11) · ×1,5

- [x] **3.1** Az elévülés mechanizmusa megvan, a visszamérésé nincs · nincs `schedule:` trigger egyetlen workflow-ban sem (`grep cron` → 0 találat; a `ci_prod_audit.yml:19` tudatosan indokolja a magáét) · A `REVIEW_INTERVAL_DAYS = 180` gondoskodik róla, hogy egy verdikt lejárjon, és a README büszkén állítja, hogy „a pipeline that stopped running would drive the pass rate to zero within 180 days" — de semmi nem méri újra automatikusan. A „Needs Re-run" halmaz csak nőhet, amíg valaki kézzel nem indít `workflow_dispatch`-et. A `select_unverified.py` + a dispatch `unverified` scope pontosan ehhez készült; hiányzik a heti/havi ütemezés `LAB_ONLINE`-tudatos kapuval (ami már létezik, és pont ezt a helyzetet kezeli offline lab esetén) → **Jamal**
- [ ] **3.2** A prod-audit csak kézzel indul · `.github/workflows/ci_prod_audit.yml:19-22` · A „nincs schedule" indoklás (offline lab) helytálló volt, de a `LAB_ONLINE` gate azóta pont ezt a helyzetet kezeli máshol. Egy ütemezett futás `LAB_ONLINE != 'false'` feltétellel offline labnál is csak kihagyja magát — cserébe a „prod még az, aminek hisszük?" kérdés nem attól függ, hogy valakinek eszébe jut-e megkérdezni. Ugyanaz a minta, mint a 3.1, ezért érdemes egyszerre → **Jamal**
- [ ] **3.3** Egyetlen backend, és a második létezését csak szintetikus teszt bizonyítja · `config/backends.yml`, `tests/test_backend_config.py:106-148` · A régi register 3.7 kivette a backend-döntést a kódból adatba — a fájl saját kommentje szerint „a new backend is a new block below, and the converter's code path is unchanged". Ezt ma **semmi valódi futás nem támasztja alá**: a `config/backends.yml`-ben egyetlen `splunk` blokk van, a „több backend is működik" állítást pedig kizárólag a tesztfájlban felépített, kitalált `esql` / `elastic` konfiguráció támasztja alá — ami a *betöltőt* teszteli, nem a konverziót. Yara ugyanide jutott, és egy konkrét eszközt javasolt hozzá: egy kis CLI, ami kap egy backend-konfigurációt + mintaszabályokat, és megmondja, mi fordul le és mi nem. Ez egyszerre lenne a 3.7 falszifikálása és egy jövőbeli „adjunk hozzá Elasticet" kör önellenőrző eszköze → **Gaz** dönt hatókört, **Jamal** hajtja végre (a `scripts/convert/` mellé)
- [ ] **3.4** A verdikt csak azt méri, hogy „tüzelt-e" — a zajszintről nincs adat · `scripts/verify/pass_fail_eval.py` (`1 ≤ events ≤ 10`) · A README maga nevezi meg a korlátot („A PASS still only proves the search fired once, on one synthetic execution"). A lezárt register **4.1**-e (csendes ablak mérése) jó okkal lett elutasítva: a laborban nincs háttérforgalom. De a maradék rés más alakban is megfogható: pl. a saved search futásidejének / `scanCount`-jának rögzítése a verify során, ami a szabály *költségét* méri, nem az FP-arányát, és háttérforgalom nélkül is értelmes szám → **Yara** (formálás) → **Jamal**
- [ ] **3.5** A rule browser egyetlen 674 KB-os fájl, mindent előre betöltve · `docs/index.html` (674 590 bájt), forrás: `page.js` 2 878 sor / 128 KB, `page.css` 4 036 sor / 98 KB · 28 szabálynál ez működik; a növekedés viszont lineáris, mert a teljes szabálytest, a MITRE-mátrix, két history-idősor és a deployment-panel is beágyazottan utazik. Nincs mérés arról, hol a fájdalomküszöb — egy Lighthouse-futás (a `chrome-devtools` MCP-eszközök Sienna készletében megvannak) megmondaná, hogy ez ma probléma-e vagy csak később az → **Sienna**
- [ ] **3.6** Nincs értesítés a pipeline eredményéről a GitHub felületén kívül · A PASS/FAIL verdikt ma a job exit-kódjában, a step summaryben és a promotion PR meglétében jelenik meg. Aki nem nézi az Actions fület, semmiről nem tud — arról sem, hogy 27 szabály hetek óta `NOT_VERIFIED` (1.5). Legolcsóbb forma: GitHub Issue automatikus nyitása/frissítése a lejárt+superseded halmazról, vagy bármilyen tartós felület a step summary helyett → **Jamal** (CI), **Kai** (ha issue/platform-oldali)
- [ ] **3.7** A lefedettségi cél nincs adatként jelen · `outputs/reports/stats.json`: `mitre_covered_techniques: 12`, `mitre_total_techniques: 222`, `mitre_coverage_pct: 5,4` · A dashboard megmutatja, mi van; nem mutatja, mi lenne a cél, és milyen ütemben haladunk felé. A `coverage_history.json` és a `rule_growth_history.json` már gyűjti az idősort — hiányzik a szándék (célhalmaz, prioritás, „következő 5 technika") rögzítése adatként, amihez a trend mérhető. Ez az a pont, ahol Yara és Masha kimenete tényleges repo-artefaktummá válhatna → **Yara** (tartalom), **Sienna** (megjelenítés)
- [ ] **3.8** A szabálykönyvtár két taktika-családra szűkül, hét taktikán nulla szabály · gépi számlálás a 28 szabály `attack.*` tactic-tagjein: `execution` 14, `credential_access` 13, `stealth` 8, `persistence` 2, `defense_impairment` 2, `command_and_control` 1, `initial_access` 1, `discovery` 1 · A felső ATT&CK enterprise-taxonómiához mérve **hét taktikán nulla szabály van**: Reconnaissance, Resource Development, Privilege Escalation, Lateral Movement, Collection, Exfiltration, Impact. Teljes technika-lefedettség 12/222 (5,4%). Ez nem hiba — tudatos mélységi fókusz lehet —, de sehol nincs kimondva, hogy az, és a hét üres taktika kész felvételi lista a következő körhöz. Yara javaslata a sorrendre, amivel egyetértek: a **Privilege Escalation** és a **Lateral Movement** az a kettő, amihez a meglévő victim + DC labor-hostokon reálisan van valódi Atomic-teszt — vagyis ezekre nemcsak szabály írható, hanem a repo lényegét adó *élő verifikáció* is elvégezhető rajtuk. (Pontosítás Yara briefjéhez: a repo saját taktika-szótára nem azonos az upstream ATT&CK-kal — `stealth` és `defense_impairment` itt valós taktika, lásd a `mitre-attack-mapping` skillt —, tehát nyolc taktikán *van* szabály, nem kettőn; a koncentráció állítása viszont változatlanul áll.) → **Masha** (külső megalapozás) → **Yara** (priorizálás) → **Yuki** (megvalósítás), dokumentálva **Chloe**
- [x] **3.9** A publikált szám mellett nincs ott, hogy mikor mértek utoljára élesben · `README.md` badge-sor, `docs/index.html` Verification-gyűrű · Ma a `stats.json` (generálva 2026-08-17) 4% pass rate-et és 27/28 `NOT_VERIFIED`-et mutat, három nappal azután, hogy a régi register naplója egy valódi `LAB_ONLINE=true` futást rögzített 26 szabály éles history-jával. Aki csak a badge-et látja, romlásnak olvassa. Hiányzik egy „utolsó éles verifikáció: `<dátum>`, N/M szabály" jelzés közvetlenül a Pass Rate badge és a gyűrű mellett, plusz a rule browserben egy önkiszolgáló szűrő/jelvény a „újramérésre vár" halmazra, ami megkülönbözteti a *szerkesztés miatt felülírt* és az *elévült* esetet (az adat mindkettőre megvan a `stats.json`-ben). Yara ezt priorizálta a legmagasabbra a briefjében, és egyetértek a *javaslattal* — a diagnózisával nem (lásd a Naplót és az 1.5-öt: a mai 4% nem elévülésből jön, `verified_stale = 0`) → **Sienna**
- [ ] **3.10** Nincs anonimizálás a publikusan letölthető diagnosztikai artifactban · `ci_dev_workflow.yml:1882` (`matched-events-sigma-<run_id>`, 14 napos retention, publikus repón bárki által letölthető) · A régi register **2.16**-a ezt a kockázatot megvizsgálta, és tudatosan a **rövidebb retenciót** választotta (90 → 14 nap) a mezőszűrés helyett — az indoklás jó volt (a nyers esemény maga a hibakeresési érték) —, de a tétel szövege maga nevezi meg, mi maradt kitéve: **a labor névtana** (gépnevek, domain, szolgáltatásfiókok). Egy verify és artifact-feltöltés közé illesztett eszköz, ami a labor-azonosítókat stabil, entitásonként konzisztens álnevekre cseréli (megőrizve az események közti korrelációt, tehát a debug-értéket is), pontosan azt a maradékot zárná le, amit a 2.16 nyitva hagyott. Yara javaslata, a register szövegével megerősítve. Önálló eszköz, nincs mai gazdája — a CI-ba **Jamal** kötné be → **Gaz** dönt gazdát
- [ ] **3.11** Nincs eszköz egy találatszám-eltérés kivizsgálására · verifikálva a `outputs/results/DETECT-2026-0019/history.jsonl`-ből: ugyanaz a szabály négy futás alatt **FAIL (11 esemény) → NOT_VERIFIED (1) → FAIL (0) → NOT_VERIFIED (kikapcsolva)** három nap alatt, közben a `rule_version` 1.6-ról 1.7-re mozdult · A régi register **2.7**-e a globális `--max-pass 10` ablakot vizsgálta, és elutasítással zárult: a felső korlát rossz eszköz, mert az *attack-ablak* számából elvből nem derül ki, hogy a szabály túl tág-e vagy a technika generál tényleg annyi eseményt. Ez a következtetés áll — de a gyakorlati rés megmaradt: ha egy szám 11 lesz 10 helyett, ma **semmi nem mondja meg, melyik esemény volt a plusz egy**. Egy script, ami betölti egy szabály illeszkedett eseményeit és megmutatja, mely mező(k) mentén válik szét a halmaz, a mai „ismert flakiness"-t vizsgálhatóvá tenné. Yara javaslata; a register 2.7-hez fűzött indoklása pontosítva (nem „not-a-bug flakiness"-ként lett lezárva, hanem a felső korlát elvi elutasításaként) → **Jamal** (a `scripts/verify/` kiterjesztéseként), vagy önálló eszköz, ha külön akarjuk tartani a CI-tól

## 4 · Robusztusság és karbantarthatóság (7) · ×2

- [ ] **4.1** 1 827 sor inline shell a workflow-kban, ebből 1 263 a dev workflow-ban · `ci_dev_workflow.yml` 2 572 sor (1 005 komment, 1 263 inline `run:` shell), `ci_code_checks.yml` 252, `ci_prod_audit.yml` 175, `ci_prod_workflow.yml` 137 · Ez a repo legnagyobb tesztelhetetlen kódfelülete: unit-teszt nem éri el, csak a shellcheck látja (actionlinten keresztül) — az pedig szintaxist ellenőriz, nem viselkedést. A pipeline logikájának jelentős része itt él (verify-ablak számítása, commit-visszaírás retryvel, bundle-kezelés, provenance-ellenőrzés). Nem az egész kiszervezése a cél, hanem a leghosszabb, legtöbb elágazást tartalmazó blokkoké `scripts/ci/*.sh` vagy Python alá, ahol a pytest is látja őket. (Helyi megjegyzés: az actionlint Windowson beragad nagy `run:` blokkokon — a méret már ma is fáj.) → **Jamal**
- [x] **4.2** 7 500 sor front-end, nulla automatizált ellenőrzés · `scripts/docs/assets/page.js` (2 878), `page.css` (4 036), `page.template.html` (586) · A `ci_code_checks.yml` négy checkerje Pythont (ruff+pytest), PowerShellt (parser+PSScriptAnalyzer), workflow-YAML-t (actionlint+shellcheck) és függőséget (pip-audit) fed — JS/CSS/HTML-t **egyiket sem**. `grep eslint|stylelint|prettier|npm` a workflow-kban: 0 találat. Arányában: 3 400 sor Pythont 555 teszt véd, 7 500 sor front-endet semmi. Belépő szint: `eslint` minimál szabálykészlettel + HTML-validáció a generált oldalon, önálló jobként (hogy egy JS-hiba ne maszkolja a ruffot, a repo bevált mintája szerint) → **Sienna** (tartalom) + **Jamal** (job)
- [x] **4.3** A teszt-suite bukik a fejlesztő saját gépén · `python -m pytest` → **3 failed, 552 passed**, mindhárom a `tests/test_meta_only.py`-ban, hibaüzenet: `'No time zone found with key Europe/Budapest'` · Ok: a `scripts/convert/sigma_to_spl.py:334` `ZoneInfo("Europe/Budapest")`-et használ, Windows alatt viszont nincs rendszerszintű tzdata, és a `.github/requirements-dev.txt` (pytest, ruff) nem tartalmazza a `tzdata` csomagot. CI-ban (ubuntu) zöld, helyben piros — ez a legrosszabb fajta eltérés, mert a fejlesztőt arra tanítja, hogy a piros suite normális. Javítás: `tzdata` a dev-requirementsbe (és/vagy a sidecar időbélyegének UTC-re váltása) → **Jamal**
- [ ] **4.4** Hat különböző commit-visszaírási út, futásonként 3-4 gépi commit · `ci_dev_workflow.yml` (4 commit: prune / SPL / verify results / dashboard), `ci_code_checks.yml` (1), `ci_prod_audit.yml` (1) · 894 commitból **256** (29%) `[skip ci]` gépi commit; a `docs/index.html`-t 185, az `outputs/`-ot 221 commit érinti. Következmény a napi munkára: a felhasználó minden helyi commit előtt rebase-elni kényszerül, mert a CI mindig elé ír (ez már rögzített projekt-tapasztalat). A történet ettől olvashatatlan is: egy valódi változtatás körül 3-4 zajcommit ül. Irány: egy futás = legfeljebb egy visszaírás (az `update_dashboard` amúgy is külön jobban fut, oda összevonható), vagy a generált artefaktumok kivezetése a branchről (Pages-artifact + release-asset), ami a 3.5-tel is összeér → **Jamal** ⟶ folyamatban
- [ ] **4.5** A generátor központi függvénye 277 soros, és egyetlen tesztmodul importálja · `scripts/docs/generate_stats.py:863-1140` (`generate_stats()`), a fájl összesen 1 812 sor · A régi register **3.4 phase 1** kiszedte az inline HTML/CSS/JS literált (6 000 → 1 812 sor); a phase 2, a számítási mag szétbontása nem történt meg. Ez a függvény állítja elő egyszerre az összes publikált számot, a MITRE-lefedettséget, a README-blokkot és a history-idősorokat. Az 1.6 (tesztek) ennek a szétbontásával lesz olcsó, nem előtte → **Sienna**
- [x] **4.6** Három hard CI-kapu körül nincs teszt · `scripts/validate/validate_sigma.py` (a séma-kapu, amin minden szabály átmegy), `scripts/validate/check_detect_id_uniqueness.py`, `scripts/new_rule.py` · A `tests/` egyik modulja sem importálja őket (a `check_version_bump`, `check_test_routing`, `check_mitre_tags`, `check_spl_syntax` viszont mind fedve van, jól). A `new_rule.py` külön súlyos: a `sigma-rule-authoring` skill *minden* új szabályt ezzel indíttat, tehát a scaffold hibája minden jövőbeli szabályba beépül; a skill állítása („every placeholder already satisfies the schema, `validate_sigma.py` passes on the untouched skeleton") ma nincs teszttel bizonyítva, pedig pontosan egy ilyen `scaffold → validate` round-trip teszt írná le → **Jamal**
- [ ] **4.7** Nincs UI-regressziós ellenőrzés, pedig az ügynök-szerződés előírja a manuálisat · `.claude/agents/Sienna - Frontend Engineer.md` („Verifies their own changes with Playwright before calling them done") · A Playwright-ellenőrzés így minden alkalommal kézi, egyszeri és nyomtalan: nincs elmentett snapshot, nincs CI-ban futó smoke-teszt, ami észrevenné, hogy egy `@@MARKER@@` kicseréletlenül maradt, egy doughnut nem renderelődik, vagy a Navigator-nézet elszáll. Egy egyszerű headless smoke (az oldal betölt, nincs console error, megvan a várt N szabálysor és a két gyűrű) a `ci_code_checks.yml`-ben megfogná a leggyakoribb regressziót → **Sienna** + **Jamal**

## 5 · A Claude-munkamodell mint fejlesztési folyamat (11) · ×1,5

Ez a szakasz azt vizsgálja, hogy a `CLAUDE.md`-ben leírt tizenegyfős
delegálási modell a gyakorlatban hozza-e, amit ígér. Rövid válasz: a
*szerepfelosztás* jó és látszik is a repón (a specialistánként szűk hatókör
tényleg jobb, reviewálhatóbb kimenetet adott), a *körülötte lévő gépezet*
viszont hiányos — a konfiguráció nagy része nincs a repóban, egy hook halott,
és a legfontosabb közös fájlokat senki nem birtokolja.

- [ ] **5.1** A csapat saját operatív fájljai gazdátlanok · `CLAUDE.md`, `TEAM.md`, `.claude/agents/*.md`, `.claude/skills/*` · A roster-tábla minden sora egy-egy felületet nevez meg; egyik sem tartalmazza ezt a négyet. Chloe kifejezetten „README.md prose, `docs/architecture/*.md`, the GitHub Wiki"-t birtokol — a `TEAM.md`-t nem. Ennek közvetlen, mérhető következménye a 2.8 (két avatár létezik, a `TEAM.md` mind a tizenegyet „pending"-nek mondja) és az 5.5 (elavult tények az ügynökfájlokban). Javaslat: a `CLAUDE.md` kapjon egy explicit sort arról, ki tartja karban a roster-fájlokat — akár Chloe hatóköre bővül a `TEAM.md`-vel, akár Gaz tartja meg magának, csak legyen kimondva → **Gaz**
- [x] **5.2** A docs-drift hook olyan eseményre tüzel, amit a projekt konvenciója kizár · `.claude/settings.json:5-19`, `.claude/hooks/docs-drift-check.sh:22-26` · A hook a Bash-hívás payloadjában a `git commit` szövegre szűr, majd ellenőrzi, hogy tényleg landolt-e friss commit. Csakhogy a projekt álló szabálya az, hogy **a commitokat a felhasználó csinálja, nem az ügynök** — így az ügynök Bash-hívásaiban gyakorlatilag sosem szerepel `git commit`, és a hook a gyakorlatban soha nem fut le. A kód maga jó minőségű (determinisztikus, LLM-mentes, saját teszt-scripttel `.claude/hooks/test-docs-drift-check.sh`), csak rossz eseményhez van kötve. Helyesebb trigger: `PostToolUse` `Edit|Write` matcher a `scripts/**` és `.github/workflows/**` útvonalakra, vagy `Stop` hook, ami a munkamenet végén összegzi az érintett fájlokat → **Jamal** (a hook script), **Gaz** (a konvenció eldöntése)
- [x] **5.3** Nincs `permissions` blokk a `.claude/settings.json`-ben · `.claude/settings.json` (mindössze `attribution` + `hooks`) · Két külön veszteség. (a) *Hatékonyság*: nincs allow-lista a rutinparancsokra (`python -m pytest`, `ruff check`, `git status`, `git log`, `python scripts/validate/*.py`), tehát minden ügynök minden ellenőrző futása kézi jóváhagyást kér — pont az a művelet, amit a legtöbbször kell megismételni. (b) *Biztonság/konvenció*: a „Bence commitol, az ügynök nem" szabály ma csak emlékezetben és prózában él; egy `deny` bejegyzés (`Bash(git commit:*)`, `Bash(git push:*)`) gépiesen kikényszerítené. A repo egyébként pontosan ezt a filozófiát követi mindenhol máshol: ami szabály, az legyen kapu, ne emlékeztető → **Gaz**
- [ ] **5.4** Nincs `.mcp.json` a repóban, három ügynök viszont MCP-eszközökre épül · `.claude/agents/Kai - Platform Engineer.md` (~40 `mcp__github__*` eszköz), `Priya - Application Security Engineer.md` (`mcp__semgrep__*`), `Sienna - Frontend Engineer.md` (`mcp__playwright__*`, `mcp__chrome-devtools__*`) · Ezek a szerverek felhasználói szinten vannak konfigurálva, nem a repóban (`find . -name .mcp.json` → nincs találat). Következmény: egy friss klónban (más gép, más felhasználó, vagy CI-környezet) ez a három ügynök csendben elveszti az eszközkészlete nagy részét — nem hibaüzenettel, hanem úgy, hogy a képességei egyszerűen nincsenek ott. Egy projektszintű `.mcp.json` (a titkokat környezeti változóból olvasva) tenné a csapatot hordozhatóvá; ahol ez nem megy (pl. felhasználóhoz kötött auth), ott legalább dokumentálva kellene lennie, mit kell egyszer beállítani → **Gaz** dönt, **Kai** hajtja végre
- [ ] **5.5** Elavult tények az ügynökfájlokban — és senki nem nézi őket rendszeresen · `.claude/agents/Kwame - Compliance Analyst.md` („last known count: 54 items, 43 done" — a register azóta 54/54 és lezárt), `Jamal - DevOps Engineer.md` (háromsoros workflow-tábla, a negyedik workflow hiányzik; a `ci_prod_workflow.yml` sora „Re-converts, drift-gates, deploys" — mindkettő megszűnt, lásd 1.1), `Bjorn - …md` (a megszűnt `rule_documentations/` könyvtár), `Priya - …md` (pontos telepítési útvonalak és MCP-elérhetőség, saját „confirm current state yourself, environments drift" kitétellel) · Ezek nem kozmetikai hibák: az ügynökfájl az első dolog, amit a diszpécselt specialista elolvas, tehát minden ilyen mondat egy hamis kiindulópont minden jövőbeli futásban. Kwame sajátja külön ironikus: a register-auditáló ügynök leírása maga elavult a registerhez képest. **Yara ugyanide jutott, egy fokkal általánosabban**, és a hiányzó *mechanizmust* nevezte meg: a `remediation-plan.md`-t Kwame állandó jelleggel ellenőrzi a valósággal szemben, az ügynökdefiníciókat viszont **semmi és senki** — nincs az a szerep, ami ezekre nézve játszaná Kwame szerepét. A tétel ezért kettős: (a) a mai konkrét elavulások javítása, (b) egy visszatérő „ügynökfájl-spot-check" beépítése valamelyik meglévő audit-körbe, hogy ne kelljen újra egy teljes átvizsgálás ahhoz, hogy kiderüljön → **gazdátlan, lásd 5.1**; a visszatérő ellenőrzés természetes helye **Kwame** köre
- [ ] **5.6** Megosztott, gyorsan avuló tudás perszóna-fájlokba égetve, nem skillbe · `.claude/skills/` ma három skillt tartalmaz: `sigma-rule-authoring`, `mitre-attack-mapping`, `team-avatars` · Mindhárom a szabály-szerzés / kozmetika körül forog. A commit-történet szerint viszont a munka zöme a pipeline-on (Jamal) és a rule browseren (Sienna) folyik, és ezeknek a konvenciói ma kizárólag 1 005 sornyi workflow-kommentben és az ügynökfájlok prózájában élnek — vagyis minden diszpécselés újra levezeti őket. **Yara adta hozzá a döntési szabályt, ami ezt élessé teszi:** ha egy perszóna-fájl saját szövege azt mondja, hogy „ezt ellenőrizd, mielőtt megbíznál benne" (szó szerint ez áll Priya környezet-bekezdésében), az pont az a pont-idejű, avuló tudás, amit a skill-mechanizmus izolálni hivatott — perszóna-fájlba égetve minden jövőbeli szerkesztésbe belemásolódik az elavulás. Konkrétan hiányzó skillek: (a) **`pipeline-ci-gotchas`** — Jamal fájlja (`:29-30`) két olyan csapdát dokumentál, amelyek saját bevallása szerint már okoztak valódi hibát (a `changes` step üres szabálylistája → minden downstream job kimarad, a run mégis zöld; és a `--diff-filter=AMRC`, ami a törléseket kizárja) — ez a tudás ma **láthatatlan** Priya (CI-konfigurációt auditál) és Kwame (pipeline-állításokat verifikál) számára, hacsak külön újra fel nem fedezik; (b) **rule-browser generátor-konvenciók** (a `docs/index.html` build-artefaktum, `@@MARKER@@` behelyettesítés, asset-inline-olás, normalizált diff-összehasonlítás) — ide tartozik a 2.12-ben hiányzónak talált `dataviz` is; (c) **audit-register konvenciók** (ennek a fájlnak a formátuma, súlyozás, naplóbejegyzés). Yara egy megjegyzése ide tartozik ellensúlyként: a `team-avatars` a három meglévő közül az egyetlen, ami nem szabály-helyességet kapuz — ha a skill-készlet karbantartása később teherré válik, ez az, amit a legkönnyebb visszaolvasztani egy egyszeri beszélgetésbe → **Gaz** dönt, tartalom a felület gazdájától
- [ ] **5.7** A `team-avatars` skill kimenete félkész és nincs bekötve · `.claude/skills/team-avatars/SKILL.md` · A skill precízen definiálja a stílus-lockot és a fájl helyét, de a tizenegy fős rosterből két avatár készült el, azok is a skill saját elnevezési szabályát megsértve, és egyik sincs bekötve a `TEAM.md`-be (lásd 2.8). Ez a legtisztább példa arra, amit az 5.1 leír: van skill, van kimenet, nincs gazda, aki végigvinné → **Gaz** dönt (befejezni vagy tudatosan lezárni „két avatár elég" indoklással)
- [ ] **5.8** Nincs `.claude/commands/` — a visszatérő műveletek nincsenek parancsba zárva · A repóban ma nulla slash-parancs van. Legalább négy művelet ismétlődik felismerhetően: register-állapot ellenőrzése, dashboard/statisztika helyi újragenerálása + normalizált diff, teljes lokális kapu-futtatás (ruff + pytest + validate + check_mitre_tags), és új szabály scaffoldolása a review-átadásig. Mindegyik ma prózából kerül újra összerakásra minden alkalommal → **Gaz**
- [x] **5.9** Kwame eszközkészletében nincs `Write` · `.claude/agents/Kwame - Compliance Analyst.md` frontmatter: `tools: Read, Grep, Glob, Bash, Edit` · A szerepdefiníció szerint Kwame „reports accurate progress" és vezeti a registert — de új auditdokumentumot létrehozni nem tud, csak meglévőt szerkeszteni. Ez a dokumentum is `printf`-fel létrehozott helyőrző-fájl + `Edit` kerülőúton készült. Vagy a `Write` kerüljön be az eszközök közé, vagy legyen kimondva, hogy Kwame kizárólag meglévő registert könyvel, és új auditfájlt más hoz létre → **Gaz**
- [ ] **5.10** A modellválasztási szabály nem mérhető és nem visszakövethető · `CLAUDE.md` 7. pont · A szabály jó (komplexitás-alapú eszkaláció dispatchenként, nem szerepenként), de semmilyen nyoma nem marad annak, melyik diszpécselés futott melyik modellen, tehát utólag nem lehet megmondani, hogy a szabály segít-e vagy sem. **Kwame és Yara egymástól függetlenül ugyanezt emelte ki**, és Yara pontosítása helytálló: ez futásidejű döntés, nem repo-artefaktum, tehát nem is lehet fájlban kikényszeríteni — amit viszont lehet, az a *nyom*. Legolcsóbb forma: a specialisták zárójelentése nevezze meg a modellt egy sorban, és a nagyobb körök (mint ez az audit) rögzítsék a Naplóban. Ez pontosan a repo saját „bizonyíték az állítás helyett" kultúrája, csak a folyamatra alkalmazva → **Gaz**
- [ ] **5.11** A méret- és feltételfüggő elhalasztott döntéseknek nincs követett listája · a régi register négy tételt zárt le a *jelenlegi lépték* miatt: **3.8** (alkönyvtár-bontás), **4.1** (noise budget), **4.4** (Splunk ES / RBA), **4.11** (tömeges újramérés) · Mindegyik indoklása valós kiváltó feltételt tartalmaz, de az sűrű prózába temetve — senki nem figyeli, mikor lépjük át. Yara javaslata egy „lépték-függő döntések" tábla (tétel / mai mutató / küszöb / mi változik), ami Kwame következő körén gépiesen ellenőrizhető. Jó ötlet, **de a négy példa közül kettő pontosításra szorul**, és ez a pontosítás a tábla lényege: a **4.11** küszöbe valós és idézhető (a felhasználó a tömeges újramérést kifejezetten azzal utasította el, hogy „500+ szabálynál nem skálázna"); a **3.8**-é viszont **nem** — a register szó szerint rögzíti, hogy a „27 szabály még kezelhető, 150-nél nem" állítás rákérdezésre kiderülten *sosem volt alátámasztva*, tehát a 150-es szám nem küszöb, hanem visszavont feltevés, és a táblába is így kell bekerülnie, különben egy elvetett számot élesztünk újra. A **4.1** és a **4.4** pedig nem lépték-, hanem **feltételfüggő**: az egyik akkor nyílik újra, ha a labor Splunkja valódi háttérforgalmat kap, a másik akkor, ha telepítenek ES-t vagy megjelenik egy második üzemeltető. A tábla tehát „lépték- és feltételfüggő döntések" legyen, három oszloppal: mi a kiváltó, mérhető-e ma, és hol áll → **Kwame** (könyvelés), **Yara** (keretezés)

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

## Napló

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
