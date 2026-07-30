# Pipeline audit — remediációs terv

**Ez a fájl az állapot egyetlen igazság-forrása.** A publikált register-oldal checkboxai a
böngésző `localStorage`-ában élnek, tehát csak annak látszanak, aki kattintotta — Claude nem
tudja visszaolvasni őket. Ami itt `[x]`, az a kész.

- Publikált register: <https://claude.ai/code/artifact/5652c3d4-019b-4b60-b963-667ffef1f573>
- Az oldal forrása: `audit/register.html` (ugyanebben a könyvtárban, a tételek teljes prózájával)
- Az audit alapja: `dev @ 22799a5`, statikus átvizsgálás, 2026-07-26

Nincs menetrend — a tempó ad-hoc, tételenként.

## Munkamenet

1. Egy tétel elvégzése után itt `[ ]` → `[x]`, és egy sor a Naplóba a végére.
2. Folyamatban lévő tételnél a sor végére `⟶ folyamatban`.
3. Ha a register-oldalt is frissítjük, a `audit/register.html`-be a kész tételek
   `<input>` elemére bekerül a `checked` attribútum (így a publikált oldal is a valós
   állapotot mutatja, nem csak a kattintgatót). Publikáláskor **az `url` paraméterrel**
   kell hivatkozni a fenti linkre, különben új URL keletkezik.

## Pontszám

Jelenlegi: **6,5 / 10**. Minden tétel elvégzése után: **9,0 / 10**.
A register meterének súlyozása: kritikus ×3, architektúra ×2, feature ×1,5, kisebb ×1
(összesen **88** súlypont a 4.11 felvétele óta; korábban 85).
Projektált pontszám = `6,5 + 2,5 × (kész súly / 88)`.
A register JS-e a súlyokat a DOM-ból számolja, tehát új tétel felvételekor magától újraskálázódik.

Dimenziók — most → javítva: koncepció 9→9 · dokumentáció 9→9 · robusztusság 5→8-9 ·
hitelesség 4→9 · karbantarthatóság 5→8 · biztonság 6→8.

## Javasolt sorrend

~~1.1~~ → ~~1.2~~ → **1.3.** Az 1.1 lezárva (nem defekt), az 1.2 kész. Következik az 1.3:
négy sor YAML, és utána a prod trust boundary bizonyított, nem remélt.

A 3.3 (reconcile) lefedi az 1.7-et és az 1.8-at, és az 1.1 lezárása után megmaradt
*láthatósági* igényt is (melyik szabály él ténylegesen prodban) — ha van rá idő, érdemes az
egyedi javítások helyett rögtön azt megcsinálni.

---

## 1 · Kritikus hibák (12) — a repo jelenlegi állapotán bizonyítva

- [x] **1.1** 13 szabály soha nem kerül ki prodba (27 sigma / 14 spl, `main`-en is) · `ci_prod_workflow.yml:76` · **lezárva 2026-07-30: nem kódhiba.** A 13 szabályra a teljes dev workflow még nem futott le, ezért nincs committolt `.spl`-jük; a `git ls-files`-alapú prod deploy pontosan a pipeline-on átment halmazt telepíti. Amint végigmennek a dev futáson, a prod magától kiviszi őket. A „semmi nem szól róla" rész a **3.3** + **4.7** alá kerül
- [x] **1.2** A PASS verdiktek elévülnek, a dashboard friss igazságként mutatja (12 → 15 elévült) · `generate_stats.py` · **kész 2026-07-30:** a `pass_rate_pct` már csak a friss verdiktekből számol (96% → **92%**, 11/12), mellé `verification_current_pct` (**44%**, 12/27) és `confirmed_working_pct` (41%); `Outdated` szegmens a Verification doughnutban, `n of m current` alsor az overlayben, kontúros verdikt-badge a táblában, Legend-bejegyzések. A `pass_fail_eval.py` szándékosan érintetlen — az elévülés render-időben származtatott
- [ ] **1.3** A prod nem azt deployolja, amit jóváhagytak (re-konverzió + pin nélküli deps) · `ci_prod_workflow.yml:42-60,40`, `ci_dev_workflow.yml:154` · fix: pinelt `requirements.txt` + `git diff --exit-code -- rules/splunk`
- [ ] **1.4** Az `-5m` verify-ablak rövidebb az atomic tesztek futásidejénél · `ci_dev_workflow.yml:428,670` · fix: run-start timestamp job outputként, abból `--earliest`
- [ ] **1.5** A Splunk-lekérdezés timeoutja hamis FAIL-ként jelenik meg (+ `FINALIZING` részleges eredmény) · `check_saved_search_hits.py:120-164,138` · fix: explicit timeout-error, olvasás csak `DONE`-nál
- [ ] **1.6** A `scripts/docs/**` nincs a trigger-path-ok között · `ci_dev_workflow.yml:7-28` · fix: path felvétele, vagy inkább a 4.10 saját CI
- [ ] **1.7** Nincs törlés/kivezetés: `--diff-filter=AMRC`, árva `.spl`, árva saved search, 3 árva result, holt `status: deprecated` · `ci_dev_workflow.yml:89` · fix: 3.3 reconcile; addig min. a deprecated kizárása a deployból
- [ ] **1.8** A title átírása árva saved search-öt hagy a Splunkban · `rule_naming.py:10` · fix: objektumnév csak `detect_id`-ból, title a description-be
- [ ] **1.9** Egy hibás szabály `throw`-ja megbuktatja az egész batch tesztelését · `run_atomic.ps1:313,338`, `sigma_schema.json` · fix: séma `if/then` a `type`↔`atomics`/`custom` párra + `Write-Warning` + `continue`
- [ ] **1.10** Atomic higiénia: nincs `-GetPrereqs` és nincs `-Cleanup` · `run_atomic.ps1:178-242` · fix: mindkettő hozzáadása
- [ ] **1.11** A Defender kikapcsolva maradhat, ha a stepet a timeout hard-kill-eli · `run_atomic.ps1:496-498` · fix: független visszaállítás (scheduled task / runner startup)
- [ ] **1.12** A MITRE hőtérkép soha nem mutat FAIL-t: `best_verdict` a legjobb verdiktet választja, így a FAIL `DETECT-2026-0012` zöld cellák alá bújik (19 zöld / 0 vörös, a FAIL legend-szűrő halott) · `generate_stats.py:368-399,475-481` · fix: cella színe maradhat best-verdict, de jelölés kell, ha bármelyik fedő szabály FAIL — a szűrő ezt izolálja. Ma dokumentált döntés, nem elírás; a következmény viszont az, hogy a hőtérkép elrejti a megerősített hibát

## 2 · Kisebb hibák és optimalizálás (18)

- [ ] **2.1** A `splunk_verify` OR-lánca gyakorlatilag mindig igaz (nem kapu) · `ci_dev_workflow.yml:563-573`
- [ ] **2.2** Egyetlen jobon sincs `timeout-minutes` (a self-hosted runner beragadhat, prodot is blokkolva)
- [ ] **2.3** `SPLUNK_VERIFY_WAIT_SECONDS` soha nincs beállítva → mindig fix 60s · `ci_dev_workflow.yml:636` · fix: poll
- [ ] **2.4** A prod futásnak nincs audit-nyoma (nincs step summary, nincs deploy-artifact)
- [ ] **2.5** Deploy-script javítás nem jut ki prodba (paths filter) · `ci_prod_workflow.yml:6-9` · fix: `workflow_dispatch`
- [ ] **2.6** A „már létezik" detektálás a hibaszöveget stringkeresi · `deploy_spl_to_splunk.py:160-163` · fix: upsert az objektum-endpointra
- [ ] **2.7** A pass-ablak globális (`--max-pass 10`) · `pass_fail_eval.py:167` · fix: `custom.testing.expected_events`
- [ ] **2.8** A `NOT_VERIFIED` kapu csak atomicra vonatkozik (8 emulation szabály kimarad) · `pass_fail_eval.py:244`
- [ ] **2.9** Az index-prefix beszúrása elhasal pipe-pal kezdődő queryn · `sigma_to_spl.py:162-185`
- [ ] **2.10** Szabályonként két Python-process egy mező kiolvasásához · `ci_dev_workflow.yml:323-324` · fix: 3.1 manifest
- [ ] **2.11** Hiányzó repo-higiénia: requirements/pyproject/Makefile/pre-commit/CODEOWNERS/PR template/dependabot, actions csak major taggel pinelve
- [ ] **2.12** Nulla teszt és nulla linter · fix: 4.10
- [ ] **2.13** A `rule_documentations/` üres könyvtár · fix: 4.8 vagy törlés
- [ ] **2.14** A TLS-verifikáció csendben kikapcsol, ha a secret nincs beállítva · `ci_dev_workflow.yml:386`, `ci_prod_workflow.yml:69` · fix: fail-closed
- [ ] **2.15** A `fields:` metaadat halott (séma kötelezi, converter kidobja, SPL nem használja) · `sigma_to_spl.py:255` · fix: `| table` vagy kivenni a sémából
- [ ] **2.16** Nyers Splunk-eventek 90 napig publikusan letölthető artifactban · `ci_dev_workflow.yml:691-698` · fix: rövidebb retention vagy mezőszűrés
- [ ] **2.17** Az `emulation` + `windows-dc` kombináció csendben kiesik · `ci_dev_workflow.yml:527`, `run_atomic.ps1:300`
- [ ] **2.18** A `SPLUNK_APP` secretként van kezelve, holott `vars`-ba tartozik

## 3 · Architektúra (8)

- [ ] **3.1** Egy manifest helyett négyszer parse-olt metaadat · `sigma_to_spl.py`, `run_atomic.ps1:26-43`, `deploy:46`, `verify:56` · fix: `manifest.json` a converterből, a workflow `jq`-val olvassa (≈60-80 sorral rövidebb dev workflow)
- [ ] **3.2** Artifact-promóció újraépítés helyett (a bundle legyen az artifact, digesttel) · fix: release asset / build provenance, a prod letölti és ellenőrzi
- [ ] **3.3** Nincs desired-state ↔ actual-state rekonciliáció · fix: `scripts/state/reconcile.py` (`--check` / `--apply`), a `ci_managed: true` sidecar-mezőre építve — egyben lezárja 1.1 + 1.7 + 1.8-at
- [ ] **3.4** A `generate_stats.py` 4392 soros monolit (~3300 sor inline HTML) · `generate_stats.py:986-4275` · fix: template + assetek külön fájlba, egy JSON-blokk a 16 placeholder helyett
- [ ] **3.5** A verziózás a git history-hoz kötött, két helyen duplikálva · `sigma_to_spl.py:219`, `generate_stats.py:590` · fix: explicit `version:` a YAML-ben + CI-check a bumpra
- [ ] **3.6** A `scripts/lib/` alulhasznált (meta IO és verzió 2-2 példányban, nincs `SplunkClient`)
- [ ] **3.7** Backend lock-in a converterben · `sigma_to_spl.py:14-15,41-47` · fix: `config/backends.yml`
- [ ] **3.8** Flat rule-könyvtár és manuális ID-kiosztás (lyukak: 0001, 0002, 0004, 0017) · fix: alkönyvtárak + 4.5 scaffolder

## 4 · Profibb hatás, egyszerűbb folyamat (11) — hatás/ráfordítás szerint

- [ ] **4.1** False-positive / noise budget mérése (csendes 24h ablak → `events/day`, noise score, trend, `noise_budget` mint CI-gate) — a legnagyobb szakmai különbség demo és éles program között
- [ ] **4.2** SPL szintaxis-validáció deploy előtt a Splunk `search/parser` endpointon
- [ ] **4.3** MITRE tag-validáció a már cache-elt technique map ellen (nem létező/revoked technika, tactic-mismatch)
- [ ] **4.4** Splunk ES / RBA a deploy payloadban: `alert.suppress` throttling, drilldown, severity → risk score · `deploy_spl_to_splunk.py:115-129`
- [ ] **4.5** `new_rule.py` scaffolder (következő szabad `detect_id`, séma-konform skeleton) + `Makefile` a lokális futtatáshoz
- [ ] **4.6** Per-rule verdict history (append-only `history.jsonl`) a „flaky / mikor romlott el" kérdésekhez
- [ ] **4.7** Deployment inventory a dashboardon (dev/prod hol él, milyen verzióval) — a 3.3 kimenetéből
- [ ] **4.8** A `rule_documentations/` generálása a `stats.json`-ból (runbook-oldal szabályonként)
- [ ] **4.9** A promotion PR body-ja legyen érdemi: per-szabály breakdown · `ci_dev_workflow.yml:814`
- [ ] **4.10** Saját CI a pipeline-ra: ruff, pytest, actionlint, PSScriptAnalyzer, shellcheck, pip-audit
- [ ] **4.11** Az elévülés riportálási korrekció, nem kapu — a `splunk_verify` exit kódja és a promotion PR gate csak az adott futás szabályait látja, azok verdiktje pedig definíció szerint friss, így egy lejárt vagy felülírt verdiktű szabály **soha nem blokkolja a promóciót**, és mérés nélkül ülhet prodban akármeddig (ma 15 ilyen). A dashboard 2026-07-30 óta megmondja, a pipeline nem tesz vele semmit · fix: re-validation gate a promotion előtt, vagy ütemezett újramérés az elévült halmazra · a `docs-maintainer` észrevétele az 1.2 dokumentálása közben

---

## 5 · Amit ez az audit nem fedett

Nem munkatételek, hanem a lefedettség őszinte korlátai. Bármelyik külön kör lehet.

- **A 27 szabály detekciós logikájának tartalmi minősége.** Csak a `0019` lett végigolvasva.
  FP-kockázat, átfedések, ATT&CK-tag helyesség → `detection-content-reviewer`.
- **A `docs/index.html` 3287 sora front-endként.** Csak szerkezetileg; nem futott Playwright,
  nincs accessibility/perf audit. *Korrekció:* az első kiadásban itt az állt, hogy a korábbi
  „a Navigator elrejti a FAIL verdikteket" jegyzet nem igazolható — ez téves volt. A `.tc.fail`
  stílus létezik, de elérhetetlen; a megállapítás igaz és ma is él → **1.12** tétel.
- **A tábla sormagasság-hibája sok technika-badge esetén** (korábbi Playwright-megfigyelés:
  `vertical-align: middle`, ~183px-es sor a `DETECT-2026-0022`-nél). Ebben a körben nem lett
  újraellenőrizve — vagy javítva lett a rule browser átdolgozásakor, vagy még él.
- **Az élő CI-futások logjai.** Minden megállapítás statikus elemzés; a tényleges
  flakiness-mintákat csak a run history mutatná.
- **A Splunk tényleges állapota.** A drift-megállapítások repo-oldali következtetések.
- **Dependency- és supply-chain szkennelés** (semgrep, pip-audit) → `security-scanner`.

## 6 · Amit ne rontsunk el

- A `NOT_VERIFIED` mechanizmus a progress-markerekkel: szinkron `WriteAllText`, stale-marker
  takarítás, „started/completed" különválasztás. Precíz „nem tudjuk"-kezelés.
- A `${{ }}` interpolációk konzisztensen quoted heredocban / PowerShell literál here-stringben —
  tudatosan elkerült script injection.
- A workflow-kommentek, amik konkrét run ID-kkal dokumentálják, *miért* van ott egy `always()`
  vagy egy `fetch-depth: 0`. Enélkül valaki fél év múlva „egyszerűsítené" és újra elrontaná.
- A `docs/architecture/` három dokumentuma pontos, és jelzi a saját korlátait.

---

## Napló

- **2026-07-26** — Audit elvégezve (`dev @ 22799a5`), 47 tétel rögzítve, register publikálva.
  Semmi nincs még javítva.
- **2026-07-26** — Korrekció: az 5. szakasz eredetileg azt állította, hogy a korábbi
  Playwright-megállapítás („a Navigator elrejti a FAIL-t") nem igazolható. Téves volt — méréssel
  megerősítve, hogy él, felvéve **1.12**-ként. Így 48 tétel, 12 kritikus, 85 súlypont.
- **2026-07-28** — **1.2 félig kész.** A stats-generátor mostantól kiviszi a
  `verdict_rule_version`-t a rule browserbe, a lap pedig `verdictSync` állapotot származtat
  belőle: `Verdict → Sync` facet (Current / Outdated), `Δ` jelölés a Verdict oszlopban,
  provenance-mondat a drawerben („Measured via … on …, against rule v1.3 — but the rule is now
  v1.5"), és `Rule Version` / `Tested Version` / `Verdict Sync` oszlopok az exportban. Az
  elévülés tehát látható, szűrhető és exportálható. **Ami nincs meg:** a `pass_rate_pct`
  változatlanul minden PASS-t számol (`generate_stats.py:890`), és a `pass_fail_eval.py`-ban
  nincs `STALE` állapot — a 96% továbbra is részben örökölt. A drift mértéke az audit óta nőtt:
  12 → **15 elévült a 27-ből**; a `0022` az auditban v1.6/v1.7 volt, ma v1.6/v1.8.
- **2026-07-28** — Nem audit-tételek, de ugyanezen a napon a rule browserbe került: naptári napos
  korszámítás (a „2 days ago · 2026-07-25" eltérés javítása), rangsor szerinti rendezés a
  Severity / Status / Verdict oszlopokon, `Verification` szűrőcsoport (Method + Runner a
  `testing` blokkból — ez teszi egy kattintással láthatóvá a **2.8**-ban említett 8 emulation
  szabályt, de magát a kaput nem javítja), „generated file" banner és meta/OG tagek.
  Mellékhatás **3.4**-re: a `generate_stats.py` ~360 sorral hosszabb lett, a monolit tehát nőtt.
- **2026-07-30** — **1.1 lezárva, nem javítással.** A felhasználó tisztázta: a 13 hiányzó `.spl`
  nem pipeline-defekt, hanem a repo pillanatnyi állapota — az érintett szabályokra a teljes dev
  workflow még nem futott le, ezért nincs mit committolni, és a prod `git ls-files`-a helyesen
  csak az átment halmazt telepíti. A tétel megmaradó, valós magja (semmi nem jelzi, mi él
  ténylegesen prodban) átkerült a **3.3** reconcile és a **4.7** inventory alá. Kész súly: 3/85,
  projektált pontszám **6,59 / 10**.
- **2026-07-30** — **1.2 kész.** A `pass_rate_pct` mostantól `friss PASS / friss verdikt`
  (**92%**, 11/12) a korábbi `összes PASS / összes szabály` (96%, 26/27) helyett, és soha nem
  jelenik meg egyedül: mellette a `verification_current_pct` (**44%**, 12/27) áll — a doughnut
  overlayben egy vizuális egységben („92% Pass Rate · 12 of 27 current"), a README-n szomszédos
  badge-ként, a meta description-ben egy mondatban. Új `stats.json` mezők: `verified_stale` (15),
  `verified_pass_current` (11), `verified_fail_current` (1), `verified_current` (12),
  `verification_current_pct` (44), `confirmed_working_pct` (41). A régi `verified_pass` /
  `verified_fail` / `not_verified` jelentése változatlan, hogy a meglévő badge-ek ne törjenek el —
  a README Pass és Fail badge-e viszont mindkettő a friss populációra állt át, hogy ne legyen
  aszimmetria (a `verified_fail_current` a `docs-maintainer` észrevétele nyomán került be, az
  első körben csak a Pass állt át).
  A Verification doughnut kapott egy **Outdated** szegmenst (drift-lila `#bc8cff`, ugyanaz a szín,
  mint a sorjelölő háromszögé és a `Verdict → Sync` faceté), és a szegmensek mostantól a
  böngészőben, a `RULES`-ból számolódnak ugyanazzal az `isVerdictStale()`-lel, amit a tábla használ
  — így a chart nem tud eltérni a soroktól. A táblában az elévült verdikt-badge kontúros
  (szaggatott lila keret, nincs kitöltés), nem tömör zöld. Legend: az Outdated-sor átírva, a
  `NOT VERIFIED` mellé bekerült a **2.8** korlát (emulation szabályoknál FAIL-ként jelenik meg),
  a Dashboards szekcióba a pass rate / coverage páros magyarázata, plusz egy jegyzet arról, hogy
  a verzió git-history-alapú (**3.5**), tehát egy leíró-átfogalmazás is elévültté tesz.
  A `pass_fail_eval.py` **szándékosan érintetlen** — a mérés pillanatában minden verdikt friss,
  az elévülés utólag áll be, ezért render-időben származtatjuk. A terv eredeti szövege
  („`STALE` állapot a `pass_fail_eval.py`-ban") ennyiben téves volt.
  Mellékhatás **3.4**-re: a `generate_stats.py` további ~90 sorral hosszabb.
- **2026-07-30** — **Az elévülés két feltétele egy fogalommá vonva** (nem külön audit-tétel, az
  1.2 kiterjesztése a felhasználó kérdése nyomán). Egy verdikt tanúsítvány: kétféleképpen szűnik
  meg érvényesnek lenni — lejár (>180 nap) vagy felülírják (a szabály változott). Azonos
  következmény, azonos teendő, tehát azonos vödör minden számításban; a *címke* különbözik.
  A korábbi két facet (`Verdict → Sync`: Current/Outdated, és `Review`: Up to date/Overdue)
  **egyesítve** `Verdict → Evidence`-szé: `Current` / `Superseded` / `Expired` / `Never tested`.
  A régi szóhasználat fordítva állt az intuícióhoz képest (az „Outdated" a verzióváltozást
  jelentette, miközben a ténylegesen régi verdiktek „Overdue" néven futottak). A doughnut két
  szegmenst kapott (`Superseded` lila, `Expired` türkiz); az üres szegmenseket a meglévő
  `n > 0` szűrő elrejti, tehát az `Expired` csak akkor jelenik meg, amikor tényleg van ilyen —
  nem kellett gyűjtőfogalmat kitalálni. Export: a `Review Status` + `Verdict Sync` oszloppár
  helyett egy `Evidence`. Új `stats.json` mezők: `verified_superseded` (15), `verified_expired` (0).
  **A pass rate mostantól a böngészőben újraszámolódik** az olvasó órája szerint (a lejárat a
  megnyitás idejétől függ), a `stats.json` és a README-badge marad build-idejű pillanatkép.
  Ma egyik szám sem mozdult (a legrégebbi verdikt 54 napos, a 180 napos ablak még sosem sült el) —
  szándékosan most, amíg ingyen van. Mellékhatás: a megosztott URL-ekben a `verdictSync` /
  `reviewStatus` szűrőkulcsok megszűntek, régi linkek nem találnak.
  Ebből fakadóan felvéve: **4.11** (az elévülés nem kapu).
- **2026-07-30** — **A két dimenzió szétválasztva két diagramra** (felhasználói javaslat). A
  Verification doughnut két kérdést sűrített egybe (mit talált a mérés + érvényes-e még), pedig egy
  szeletnek egy neve lehet. Új **Evidence** kártya a Rule Overview második sorának első helyén
  (Current 12 / Superseded 15 / Expired 0 / Never tested 0, középen `44% Current`), a
  **Verification** eggyel jobbra csúszott és visszakapta az egydimenziós szerepét: már csak a
  *friss* verdikteket bontja (Pass 11 / Not Verified 0 / Fail 1), tehát az `92% Pass Rate`
  overlay pontosan a saját gyűrűjét írja le. A két nevező szándékosan eltér (27 vs 12) — ezt a
  `12 of 27 current` alsor mondja ki. Sor 2 rácsa 2 → 3 oszlop, `Verification Age` a harmadik
  helyre. Elkerült hiba: a `.verify-canvas-wrap` osztályt már két kártya használja, a korábbi
  dokumentum-szintű `querySelector` a pass rate-et az Evidence gyűrűjébe írta volna.
  Javítva továbbá két, a `docs-maintainer` átvizsgálásából eredő szétcsúszás a Python és a JS
  osztályozás között: a **hiányzó** és az **olvashatatlan** `run_timestamp` mostantól mindkét
  oldalon `Expired` (nem `Never tested`, mert a mérés megtörtént — és nem `Current`, mert a
  frissesség nem igazolható; egy datálhatatlan verdiktet frissnek venni cáfolhatatlan zöld lenne).
  Mind a 7 határeset egyezése Python és JS oldalon egyenként ellenőrizve.
  Kész súly: 6/88, projektált pontszám **6,67 / 10** (a nevező 85 → 88 a 4.11-gyel).
