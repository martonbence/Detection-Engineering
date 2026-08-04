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

Jelenlegi: **6,5 / 10** (kiindulás). Mai állás: **7,8 / 10**, kész súly 47,5/88,5. (A nevező nőtt: a 2.19 és a 2.20 új, futás közben talált tétel — a súlyuk a kész oldalon *és* a teljes oldalon is beleszámít.)
Minden tétel elvégzése után: **9,0 / 10**.
A register meterének súlyozása: kritikus ×3, architektúra ×2, feature ×1,5, kisebb ×1
(összesen **88** súlypont a 4.11 felvétele óta; korábban 85).
Projektált pontszám = `6,5 + 2,5 × (kész súly / 88)`.
A register JS-e a súlyokat a DOM-ból számolja, tehát új tétel felvételekor magától újraskálázódik.

Dimenziók — most → javítva: koncepció 9→9 · dokumentáció 9→9 · robusztusság 5→8-9 ·
hitelesség 4→9 · karbantarthatóság 5→8 · biztonság 6→8.

## Javasolt sorrend

~~1.1~~ → ~~1.2~~ → ~~1.3~~ → ~~1.4~~ → ~~1.5~~ → ~~1.6~~ → ~~1.12~~ → ~~1.11~~ → ~~1.10~~ →
~~1.9~~ → ~~1.8~~ → ~~3.3~~ → ~~1.7~~ → **a következő kör szabadon választható.**
**Mind a 12 kritikus tétel kész.** A prod trust boundary bizonyított (pinelt konverter + drift-gate), a verify-ablak a valós
tesztfázishoz horgonyzott, a mérés-oldali bizonytalanság már nem FAIL-nek álcázza magát, a
pipeline saját kódjára is fut végre CI (**4.10** részben kész), a hőtérkép nem rejti el a
megerősített hibát, és a runner oldalán sem egy hibás szabály, sem egy megölt step nem visz
magával mást (**1.9–1.11**).

A **3.3** 2026-08-04-én lezárult: a `--check` mellé megvan a beavatkozás is, kétféle hatósugárral
(`--apply` automatikusan a CI-ban, `--apply-removals` kézzel). Az eredeti terv egy második lépést
is tartalmazott (objektumnév csak `detect_id`-ból, `rule_naming.py`), ami az **1.8**-at zárta
volna. **Ezt elutasítottuk** — a Splunk objektumnév marad beszédes —, tehát az 1.8 tünetét
(title-átírás → árva objektum) tartósan a reconcile `orphan_renamed` vödre kezeli. Ebből
következik, hogy a renamed-vödör takarítása nem egyszeri migráció, hanem **állandó üzemi
mechanizmus** — ezért fut az `--apply` felügyelet nélkül minden dev futásban.

Az **1.7** ugyanaznap zárult, a kivezetés mindhárom rétegével: Splunk-oldal (fent), `deprecated`
státusz (a deploy kihagyja, a reconcile nem-kívántként kezeli), és repo-oldal (`prune_orphans.py`).
A tünetek 2026-08-03 óta **nullák** (27 sigma / 27 spl / 27 result, nincs árva semmi, nincs
deprecated szabály) — a mechanizmusok tehát tiszta állapotból indulnak, és mostantól nem is
engedik felgyűlni a szemetet.

**A következő kör szabadon választható**, és érdemes újra megnézni, mi maradt valóban nyitott: a
register a 2026-07-26-i állapotra készült, azóta több tétel a saját munkája mellékhatásaként
oldódott meg (lásd az 1.12-t). Kézenfekvő jelöltek: a **4.10** maradéka (actionlint, shellcheck,
pip-audit), a **2.x** blokk olcsó darabjai (**2.2** `timeout-minutes`, **2.14** fail-closed TLS,
**2.5** `workflow_dispatch` a prodnak), vagy a nagyobb architektúra-lépések (**3.2** artifact-promóció,
**3.1** manifest, **3.4** a monolit bontása).

---

## 1 · Kritikus hibák (12) — a repo jelenlegi állapotán bizonyítva

- [x] **1.1** 13 szabály soha nem kerül ki prodba (27 sigma / 14 spl, `main`-en is) · `ci_prod_workflow.yml:76` · **lezárva 2026-07-30: nem kódhiba.** A 13 szabályra a teljes dev workflow még nem futott le, ezért nincs committolt `.spl`-jük; a `git ls-files`-alapú prod deploy pontosan a pipeline-on átment halmazt telepíti. Amint végigmennek a dev futáson, a prod magától kiviszi őket. A „semmi nem szól róla" rész a **3.3** + **4.7** alá kerül
- [x] **1.2** A PASS verdiktek elévülnek, a dashboard friss igazságként mutatja (12 → 15 elévült) · `generate_stats.py` · **kész 2026-07-30:** a `pass_rate_pct` már csak a friss verdiktekből számol (96% → **92%**, 11/12), mellé `verification_current_pct` (**44%**, 12/27) és `confirmed_working_pct` (41%); `Outdated` szegmens a Verification doughnutban, `n of m current` alsor az overlayben, kontúros verdikt-badge a táblában, Legend-bejegyzések. A `pass_fail_eval.py` szándékosan érintetlen — az elévülés render-időben származtatott
- [x] **1.3** A prod nem azt deployolja, amit jóváhagytak (re-konverzió + pin nélküli deps) · `ci_prod_workflow.yml:42-60,40`, `ci_dev_workflow.yml:154` · **kész 2026-08-03:** pinelt `.github/requirements.txt` (a `pySigma` külön is, mert ő szerializál) mindkét workflow-nak, drift-gate a re-konverzió és a deploy közé, dev pip-cache kulcs a `requirements.txt`-re állítva, a `pipeline_overview.md` hamis „byte-identical" állítása javítva. A **3.2** (artifact-promóció) a gyökér — az teszi majd feleslegessé a gate-et
- [x] **1.4** Az `-5m` verify-ablak rövidebb az atomic tesztek futásidejénél · `ci_dev_workflow.yml:428,670` · **kész 2026-08-03:** mindhárom teszt-job első stepként lebélyegzi az indulását (epoch), a `splunk_verify` a minimumukat veszi −60s margóval `--earliest`-nek; fallback `-15m` + warning. A `check_saved_search_hits.py` érintetlen (a Splunk elfogadja az epochot). A szabályok `custom.splunk.earliest` mezője más dolog — a prod saved search ütemezési ablaka —, nem változott
- [x] **1.5** A Splunk-lekérdezés timeoutja hamis FAIL-ként jelenik meg (+ `FINALIZING` részleges eredmény) · `check_saved_search_hits.py:120-164,138` · **kész 2026-08-03:** explicit timeout-error, olvasás csak `DONE`-nál, plusz a hibák `error_kind`-ot kapnak (`unmeasured` → NOT_VERIFIED, `rule_error` → FAIL) — a script javítása önmagában kevés lett volna, mert az `evaluate()` minden hibát FAIL-re képezett. A legend és a `VERDICT_RANK` komment is átírva
- [x] **1.6** A `scripts/docs/**` nincs a trigger-path-ok között · `ci_dev_workflow.yml:7-28` · **kész 2026-08-03:** a 4.10 útján, mert a path felvétele önmagában nem működött volna (a run elindulna, majd `has_rules=false` miatt mindent átugrana). Új `ci_code_checks.yml`: ruff + pytest minden kód-változásra, plusz `regenerate_docs` és `deploy_pages` job — a Pages ugyanis artifactból publikál, nem a branchről, tehát a commit önmagában nem frissítette volna az élő oldalt
- [x] **1.7** Nincs törlés/kivezetés: `--diff-filter=AMRC`, árva `.spl`, árva saved search, 3 árva result, holt `status: deprecated` · `ci_dev_workflow.yml:89` · **kész 2026-08-04, három rétegben:** (1) Splunk-oldal — a 3.3 `--apply` / `--apply-removals` kivezeti az árva objektumokat; (2) `status: deprecated` — a deploy kihagyja (dev és prod egyaránt, mert a prod is regenerálja a meta sidecarokat és ugyanezt a scriptet futtatja), a reconcile pedig nem-kívántként kezeli, tehát az élő objektuma eltávolítás-árvaként kivezethető; (3) repo-oldal — új `scripts/state/prune_orphans.py` takarítja a törölt szabály `.spl`-jét és result könyvtárát, **saját CI-steppel és saját committal**, mert a `--diff-filter=AMRC` miatt egy tisztán törlő push a többi jobot el sem indítja
- [x] **1.8** A title átírása árva saved search-öt hagy a Splunkban · `rule_naming.py:10` · **lezárva 2026-08-04: a javasolt javítást elutasítottuk.** A `detect_id`-only objektumnév nem elfogadható — az analitikus a Splunk keresőmezőjében és a riasztás-listákban a *nevet* látja, nem a description-t, tehát a beszédes név megmarad. A kiváltó ok ezzel tudatosan felárazott állapot, nem nyitott defekt. A tünetet a **3.3** `orphan_renamed` vödre + `--apply` kezeli: az árvaság nem szűnik meg keletkezni, hanem észlelt és takarított lesz
- [x] **1.9** Egy hibás szabály `throw`-ja megbuktatja az egész batch tesztelését · `run_atomic.ps1:313,338`, `sigma_schema.json` · **kész 2026-08-03:** séma `allOf`+`if/then` (`enabled: true`-ra szűkítve), és mind a négy `throw` → `Write-Warning` + `continue` `$malformed` számlálóval; új `exit 1` ág, ha a batch minden szabálya hibás
- [x] **1.10** Atomic higiénia: nincs `-GetPrereqs` és nincs `-Cleanup` · `run_atomic.ps1:178-242` · **kész 2026-08-03:** `Invoke-AtomicTestCompat -Mode GetPrereqs|Run|Cleanup` (egymást kizáró kapcsolók, tehát három invokáció), cleanup `finally`-ben, egyik segédfázis hibája sem számít `$failures`-nek; `ATOMIC_SKIP_PREREQS` / `ATOMIC_SKIP_CLEANUP`
- [x] **1.11** A Defender kikapcsolva maradhat, ha a stepet a timeout hard-kill-eli · `run_atomic.ps1:496-498` · **kész 2026-08-03:** scheduled task deadman (Once +20p **és** AtStartup), a kikapcsolás *előtt* regisztrálva, fail-closed (`ATOMIC_ALLOW_UNPROTECTED_DISABLE` a felmentés), leftover task `::warning`-gal jelezve
- [x] **1.12** A MITRE hőtérkép soha nem mutat FAIL-t: `best_verdict` a legjobb verdiktet választja, így a FAIL `DETECT-2026-0012` zöld cellák alá bújik (19 zöld / 0 vörös, a FAIL legend-szűrő halott) · `generate_stats.py:368-399,475-481` · **kész 2026-08-03 (a rule browser átdolgozásában, utólag beazonosítva):** `fail-flag` osztály a cellán (`:556,612`), piros sarok-háromszög (`:2421-2428`), és `tcHasFail()`/`failAny` (`:5497,5506,5601`), amitől a FAIL legend-szűrő keresztbe vág a best-verdict csoportosításon. A cella színe szándékosan maradt best-verdict

## 2 · Kisebb hibák és optimalizálás (20)

- [x] **2.1** A `splunk_verify` OR-lánca gyakorlatilag mindig igaz (nem kapu) · `ci_dev_workflow.yml:563-573` · **kész 2026-08-04:** az OR-blokk törölve; ami valóban kapuz, az fölötte marad (épült SPL + sikeres deploy). **Nem volt teljesen no-op:** egyetlen esetben hatott — ha mind a három teszt-job *elbukott* (nem skipped), a csoport hamis lett és a verifikáció némán kimaradt. Ez tudatos viselkedésváltozás: mostantól lefut, és NOT_VERIFIED verdikteket, statisztikát és reconcile-riportot hagy maga után. Promóció egyik esetben sem lett volna; a különbség az, hogy most van nyoma
- [x] **2.2** Egyetlen jobon sincs `timeout-minutes` (a self-hosted runner beragadhat, prodot is blokkolva) · **kész 2026-08-04:** mind a **13 job** kapott job-szintű `timeout-minutes`-t mindhárom workflow-ban, az értékek a scriptek saját timeoutjaiból számolt legrosszabb eset **fölé** állítva (a `splunk_verify` 120 perc, mert a 27 szabály lekérdezése önmagában ~81 perc legitim várakozást enged). Menet közben talált plusz hiba: az **emulation step-nek step-szintű timeoutja sem volt**, a másik két támadó-jobbal ellentétben — ez volt a pipeline egyetlen korlátlan támadás-végrehajtása, ráadásul a victim runneren osztozva az atomickal; kapott egy `timeout-minutes: 10`-et, a másik kettővel azonosan
- [ ] **2.3** `SPLUNK_VERIFY_WAIT_SECONDS` soha nincs beállítva → mindig fix 60s · `ci_dev_workflow.yml:636` · fix: poll
- [ ] **2.4** A prod futásnak nincs audit-nyoma (nincs step summary, nincs deploy-artifact)
- [x] **2.5** Deploy-script javítás nem jut ki prodba (paths filter) · `ci_prod_workflow.yml:6-9` · **kész 2026-08-04:** `workflow_dispatch` a prod workflow-ra. Input nélkül, mert a job `git ls-files`-ból dolgozik, nem diffből — egy manuális futás a `main` teljes aktuális könyvtárát deployolja, ami pontosan az „alkalmazd újra mindent a javított scripttel" jelentése. Ellenőrizve, hogy a job semmilyen push-specifikus kontextust nem használ (`github.event.before` stb.), tehát a manuális indítás nem tör el semmit. **Amit szándékosan nem tettem:** a `scripts/deploy/**` felvételét a `paths:` listára — az minden deploy-script merge-nél automatikusan újradeployolna prodba, ami nagyobb viselkedésváltozás, mint amit ez a tétel kér
- [ ] **2.6** A „már létezik" detektálás a hibaszöveget stringkeresi · `deploy_spl_to_splunk.py:160-163` · fix: upsert az objektum-endpointra
- [ ] **2.7** A pass-ablak globális (`--max-pass 10`) · `pass_fail_eval.py:167` · fix: `custom.testing.expected_events`
- [ ] **2.8** A `NOT_VERIFIED` kapu csak atomicra vonatkozik (8 emulation szabály kimarad) · `pass_fail_eval.py:244`
- [x] **2.9** Az index-prefix beszúrása elhasal pipe-pal kezdődő queryn · `sigma_to_spl.py:162-185` · **kész 2026-08-04:** a generáló paranccsal (`| tstats`, `| inputlookup`, …) kezdődő query mostantól **változatlanul** megy tovább, a korábbi `index=x | tstats …` helyett, ami érvénytelen SPL. **Nem hibával**, hanem érintetlenül: egyes generáló parancsok jogosan nem nyúlnak indexhez (`| inputlookup`), ezért a bukás helyes bemenetre találna ki hibát. Amiről viszont hangosan szól: ha a query **sem a sajátját nem hozza, sem a miénket nem tudja fogadni** — az csendben mindent átfésül. 10 új teszt; a 27 committolt `.spl`-en ellenőrizve, hogy egyetlen kimenet sem változott
- [ ] **2.10** Szabályonként két Python-process egy mező kiolvasásához · `ci_dev_workflow.yml:323-324` · fix: 3.1 manifest
- [ ] **2.11** Hiányzó repo-higiénia: requirements/pyproject/Makefile/pre-commit/CODEOWNERS/PR template/dependabot, actions csak major taggel pinelve
- [~] **2.12** Nulla teszt és nulla linter · fix: 4.10 · **részben kész 2026-08-03:** már nem nulla — 25 teszt a `tests/` alatt és ruff a CI-ban. A ruff viszont szűkre van állítva (`F` + `E9`), a teljes szabálykészlet bekapcsolása és a lefedettség bővítése ide tartozik
- [x] **2.13** A `rule_documentations/` üres könyvtár · **lezárva 2026-08-04, törléssel** (a két javasolt út közül; a könyvtár már nincs a repóban, csak a register mutatta nyitottként). A generálás mint lehetőség megmarad a **4.8** alatt — ha egyszer megvalósul, új könyvtárként jön létre, tartalommal. A `detection-content-reviewer` agent leírásából is kikerült a rá építő rész
- [ ] **2.14** A TLS-verifikáció csendben kikapcsol, ha a secret nincs beállítva · `ci_dev_workflow.yml:386`, `ci_prod_workflow.yml:69` · fix: fail-closed
- [ ] **2.15** A `fields:` metaadat halott (séma kötelezi, converter kidobja, SPL nem használja) · `sigma_to_spl.py:255` · fix: `| table` vagy kivenni a sémából
- [ ] **2.16** Nyers Splunk-eventek 90 napig publikusan letölthető artifactban · `ci_dev_workflow.yml:691-698` · fix: rövidebb retention vagy mezőszűrés
- [x] **2.17** Az `emulation` + `windows-dc` kombináció csendben kiesik · `ci_dev_workflow.yml:527`, `run_atomic.ps1:300` · **tágabb volt, mint ahogy itt szerepelt:** a séma `runner` enumja `linux-victim`-et is enged, amihez **egyetlen job sincs** — tehát nem csak az emulation+DC esett ki némán. A `linux-victim` **szándékos előretekintés** (a VM még nem létezik, de tervben van), ezért a megoldás nem a sémából való kivétel lett. · **kész 2026-08-04:** új `scripts/validate/check_test_routing.py`. A kiszolgált kombinációkat **a workflow-ból vezeti le** (minden step, ami `ATOMIC_TESTER_TYPE`-ot *és* `ATOMIC_RUNNER`-t is állít), nem egy beégetett listából — így a linux job későbbi hozzáadása nem igényel szerkesztést itt, és egy job törlése nem hagy maga után elavult allow-listát, ami továbbra is lefedettnek állítja a szabályait. Ha egyetlen job sem állítja a két env-et, `exit 2` a 27 találat helyett: az az állapot a checker hibája, nem a szabályoké. **Két helyen, két szigorúsággal:** a dev workflow-ban `::warning` + step summary tábla (a detekció akkor is deployolandó, ha a tesztje még nem futtatható), a pytest-suite-ban viszont kemény bukás, mert egy *committolt* szabály kiesése regresszió — job átnevezés vagy törlés. **Menet közben talált plusz hiba:** a hiányzó `runner` ugyanez a defekt — a converter csak nem-üresen írja ki a meta mezőt, a `run_atomic.ps1` pedig pontos egyezést vár, tehát a „nincs megadva" nem az alapértelmezettet jelenti, hanem egy olyan értéket, amit *minden* job szűrője eldob; a checker ezt is jelzi. Ma mind a 27 szabály valós jobra irányul (16 atomic/victim, 3 atomic/DC, 8 emulation/victim), tehát a rés lappangó volt. 25 új teszt. **Ami nyitva marad:** a nem-futtatott emulation szabály verdiktje ettől még nem lesz NOT_VERIFIED — az a **2.8**
- [ ] **2.18** A `SPLUNK_APP` secretként van kezelve, holott `vars`-ba tartozik
- [x] **2.19** A teljes újraépítés kiváltó feltétele könyvtárra illeszt, nem kimeneti hatásra · `ci_dev_workflow.yml:110` · **éles esetben derült ki:** a 2.17 `check_test_routing.py`-ja a `scripts/validate/` alá került, illeszkedett a `scripts/validate/*` globra, és ezzel `mode=all`-t váltott ki — teljes labor-futást indított (deploy + mind a három támadó job + verifikáció, 27 szabályra) egy scriptért, ami egyetlen `.spl`-t sem befolyásol. A futás beragadt egy offline runnerre várva és blokkolta a következő pusht is. · **kész 2026-08-04:** explicit fájllista (`sigma_schema.json`, `validate_sigma.py`, `validate_sigma.ps1`, `sigma_to_spl.py`, `rule_naming.py`) a glob helyett. A szándék változatlan — converter- vagy sémaváltozás után tényleg mindent újra kell építeni —, csak a kiváltó ok lett pontos. **Plusz hiba:** a `rule_naming.py` eddig nem volt a listán, holott a workflow `paths:`-ában igen; a saved search *nevét* határozza meg, tehát minden objektumot átnevez — ez volt az egyetlen eset, ami elindított egy futást, de csak a diffet dolgozta fel. 14 esetre ellenőrizve
- [x] **2.20** Kikapcsolt labor esetén a futás beragad és blokkolja a sávot · **kész 2026-08-04:** új `vars.LAB_ONLINE` (`false` → a laborhoz kötött jobok kimaradnak, a push viszont validál, konvertál, SPL-t committol). **Egyetlen kapun**, a `deploy_to_splunk`-on — az minden self-hosted runner belépési pontja —, és a függőségi gráf viszi tovább, ahelyett hogy öt helyen kéne ugyanaz a feltétel. A kaszkád levezetett: a támadó jobok függenek tőle és nincs `always()`-ük, a `splunk_verify` `deploy_to_splunk.result == 'success'`-ot vár, a promóció és a Pages pedig olyan `splunk_verify` eredményt, amit nem kap meg. A polaritás szándékos: csak a szó szerinti `'false'` tilt, tehát a beállítatlan változó = megy a labor, és egy elgépelt név a futás felé hibázik. **A visszaút is kellett:** a kapcsoló önmagában lyukat hagyott (a lekapcsolt laborban mergelt szabály sosem jut ki a Splunkba, mert a dev csak a diffet deployolja), ezért a dev workflow megkapta a `workflow_dispatch`-et — input nélkül, mert a dispatchnél üres `github.event.before` már `mode=all`-t jelent, tehát egy kézi indítás mindent újraépít és újramér. A kihagyásról `::warning` + step summary szól, mert a kihagyott job nem hiba, és a jobok listájában egy zöld futástól nem különbözne. **A prod workflow ugyanezt a változót nézi:** a `deploy_to_prod` ugyanazon a `de-lab` gépen fut, tehát pontosan ugyanazt örökölte — a kihagyás pedig szigorúan jobb, mint a sorban állás, mert mindkettő azt jelenti, hogy prod nem frissült, de az egyik egy percen belül meg is mondja, a másik meg egy napig foglaltnak látszik. A visszaút ott már készen volt: a 2.5-ös `workflow_dispatch` `git ls-files`-ból deployol, tehát egy kézi futás a `main` teljes aktuális könyvtárát kiteszi. Mivel prodnak egyetlen valódi jobja van, és épp az marad ki, mellé került egy `announce_lab_offline` job `ubuntu-latest`-en, **pontosan komplementer feltétellel** — nélküle nem maradna semmi, ami jelentse, hogy prod nem frissült, és a teljesen kihagyott futás megkülönböztethetetlen lenne egy egészségestől. **A változó repository szintű kell legyen, nem environment:** a job-szintű `if:` azelőtt értékelődik ki, hogy az `environment:` feloldódna, tehát egy environment-scope-os változót nem látna, és a kapu csendben nem működne

## 3 · Architektúra (8)

- [ ] **3.1** Egy manifest helyett négyszer parse-olt metaadat · `sigma_to_spl.py`, `run_atomic.ps1:26-43`, `deploy:46`, `verify:56` · fix: `manifest.json` a converterből, a workflow `jq`-val olvassa (≈60-80 sorral rövidebb dev workflow)
- [ ] **3.2** Artifact-promóció újraépítés helyett (a bundle legyen az artifact, digesttel) · fix: release asset / build provenance, a prod letölti és ellenőrzi
- [x] **3.3** Nincs desired-state ↔ actual-state rekonciliáció · **kész 2026-08-04:** a `--check` mellé `--apply` (átnevezés-árvák törlése, a dev CI-ban automatikusan) és `--apply-removals` (eltávolítás-árvák kikapcsolása + `[RETIRED …]` jelölés, kézi opt-in). Alább a 2026-08-03-i `--check` fele változatlanul: `scripts/state/reconcile.py` megvan, akkor még **csak `--check`** (kizárólag olvasó, nincs `--apply`). Öt vödör: in sync / missing / orphan_renamed / orphan_removed / unmanaged. Új `ci_managed` sidecar-mező **nem kellett** — a deploy leírás-prefixe már ma is CI-jelölő. CI-ban a `splunk_verify` végén, `always()` + `continue-on-error`. Hátra: `--apply` — és az **1.8** 2026-08-04-i lezárása óta ez viseli az ottani tünetet is, tehát a `orphan_renamed` takarítása állandó mechanizmus, nem egyszeri migráció
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
- [x] **4.10** Saját CI a pipeline-ra: ruff, pytest, actionlint, PSScriptAnalyzer, shellcheck, pip-audit · **kész 2026-08-04, mind a hat eszközzel.** 2026-08-03: `ci_code_checks.yml` ruff + pytest-tel (pinelve a `.github/requirements-dev.txt`-ben), az 1.6-ot lezárva; majd PSScriptAnalyzer külön `powershell_analysis` jobban (parse check + analyzer, pin 1.25.0). 2026-08-04: új `workflow_analysis` job **actionlint 1.7.12**-vel, checksum-ellenőrzött letöltéssel — és vele a **shellcheck** is, mert az actionlint maga futtatja minden `run:` blokkon (külön shellcheck-step nem tudná kinyerni a scripteket a YAML-ből); plusz `dependency_audit` job **pip-audit 2.10.1**-gyel, **`continue-on-error`-ral**, mert egy éjjel publikált CVE különben minden független PR-t pirosra váltana. A hatból négy eszköz **kapu**, a pip-audit riport
- [ ] **4.11** Az elévülés riportálási korrekció, nem kapu — a `splunk_verify` exit kódja és a promotion PR gate csak az adott futás szabályait látja, azok verdiktje pedig definíció szerint friss, így egy lejárt vagy felülírt verdiktű szabály **soha nem blokkolja a promóciót**, és mérés nélkül ülhet prodban akármeddig (ma 15 ilyen). A dashboard 2026-07-30 óta megmondja, a pipeline nem tesz vele semmit · fix: re-validation gate a promotion előtt, vagy ütemezett újramérés az elévült halmazra · a `docs-maintainer` észrevétele az 1.2 dokumentálása közben

---

## 5 · Amit ez az audit nem fedett

Nem munkatételek, hanem a lefedettség őszinte korlátai. Bármelyik külön kör lehet.

- **A 27 szabály detekciós logikájának tartalmi minősége.** Csak a `0019` lett végigolvasva.
  FP-kockázat, átfedések, ATT&CK-tag helyesség → `detection-content-reviewer`.
- **A `docs/index.html` 3287 sora front-endként.** Csak szerkezetileg; nem futott Playwright,
  nincs accessibility/perf audit. *Korrekció:* az első kiadásban itt az állt, hogy a korábbi
  „a Navigator elrejti a FAIL verdikteket" jegyzet nem igazolható — ez téves volt. A `.tc.fail`
  stílus létezett, de elérhetetlen volt; a megállapítás igaznak bizonyult → **1.12** tétel,
  ami 2026-08-03-ra lezárult.
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
  böngészőben, a `RULES`-ból számolódnak ugyanazzal az `isVerdictLapsed()`-del, amit a tábla használ
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
- **2026-08-03** — **1.3 kész.** Új `.github/requirements.txt` (nem a gyökérben: CI az egyetlen
  fogyasztója, és a telepítő workflow-k ugyanabban a könyvtárban vannak), `pyyaml==6.0.3`,
  `jsonschema==4.26.0`, `sigma-cli==3.1.0`, `pySigma==1.5.0`, `pysigma-backend-splunk==2.1.0`,
  `requests==2.34.2`. Mindkét workflow abból telepít, tehát a „dev és prod ugyanazt a konvertert
  futtatta" mostantól a repo állítása, nem a PyPI napi kedve. A `pySigma` azért van külön
  pinelve, mert csak tranzitív függőség, viszont **ő szerializálja ténylegesen a lekérdezést** —
  lebegve hagyva pont a másik két pin értelmét vinné el. A dev pip-cache kulcsa a workflow-fájl
  hash-éről a `.github/requirements.txt`-ére állt át (különben egy pin-módosítás nem ürítené a
  cache-t).
  Drift-gate új stepként a prod re-konverzió és a deploy **közé**: `git diff --exit-code --
  rules/splunk`. Izolált repóban négy esetre letesztelve: tiszta fa → átenged; módosított `.spl`
  → bukik és kiírja a diffet; törölt `.spl` → bukik; **új, untracked `.spl` → átenged**. Az
  utolsó szándékos és a step kommentjében is rögzítve: a gate a *felülírt* review-tartalmat őrzi,
  a *hiányzó* SPL az **1.1**/**3.3** hatóköre. A hamis „byte-identical" állítás nem csak a
  workflow kommentjében élt — a `pipeline_overview.md` mermaid-node-ja (`:40`) és a stage 9
  szövege is ezt ismételte; mindkettő átírva, a diagram külön node-ként mutatja a gate-et.
  Ez a tétel **tüneti kezelés**: a gyökér a **3.2** (a prod azért épít újra, mert nincs
  digest-címzett artifact). Ha a 3.2 megvalósul, a prod nem konvertál, és ez a gate törölhető —
  a pin akkor is kell. A `.github/requirements.txt` a **2.11** egy darabját is teljesíti, de *nem* teljes
  lock: a tranzitív függőségek lebegnek és hash sincs, a `pip-compile` / `--require-hashes` ott
  marad a 2.11 alatt.
  Kész súly: 9/86,5, projektált pontszám **6,8 / 10**.
  (Megjegyzés: a fenti bejegyzések 85, majd 88 összsúllyal számoltak, a `register.html` viszont
  ma 86,5-öt ad ki a `data-weight` mezők összegeként — a korábbi nevezők nem stimmelnek. A régi
  bejegyzéseket meghagytam, ahogy voltak; ez a sor a register tényleges számításából jön.)
- **2026-08-03** — **1.4 kész.** A verify-ablak mostantól a *valós* tesztfázishoz van horgonyozva.
  Mindhárom teszt-job (atomic victim, atomic DC, emulation) **első stepként** lebélyegzi a saját
  indulását epoch-másodpercben és job outputként adja tovább; a `splunk_verify` új
  `Compute verification time window` stepje ezek **minimumát** veszi, mínusz 60s óracsúszás-margó,
  és ez megy `--earliest`-ként. Miért három bélyeg és nem egy: a DC külön hoszton fut saját órával,
  az emulation pedig **osztozik a victim runneren** az atomickal, tehát sorosan futnak — pont ez
  növeli a tesztfázist a fix ablak fölé. Miért az első step: egy `timeout-minutes` által megölt
  job is meg tudja mondani, mikor kezdett.
  A `check_saved_search_hits.py` **érintetlen** — a Splunk `dispatch.earliest_time`-ja elfogadja
  az epochot, tehát csak az argumentum értéke változott, a script nem.
  **Az ablak szélesítése nem lett volna jó megoldás:** az a fordított hibát hozza be — egy pár
  perccel későbbi re-run az *előző* futás eventjeire ülne rá, és nem mért PASS-t adna. A valós
  kezdethez horgonyzás mindkét irányú hibát elkerüli.
  Fallback, ha egyik job sem adott timestampet: `-15m` + `::warning`, hogy a gyanús verdikt ne
  csendben keletkezzen. A bash-logikát öt határesetre leteszteltem, köztük arra, amikor az *első*
  érték a legkisebb: a kézenfekvő `(( a < b )) && x=y` forma ott `set -e` alatt megölte volna a
  stepet, ezért `if`-ben van.
  **Ami szándékosan nem változott:** a szabályok `custom.splunk.earliest: "-5m"` mezője mind a
  27-ben a *deployolt saved search ütemezési ablaka* prodban (`deploy_spl_to_splunk.py:111`),
  aminek semmi köze a verifikációhoz — azt a `dispatch.earliest_time` futásidőben felülírja.
  Két különböző `-5m`, csak az egyik volt hibás.
  Kész súly: 12/86,5, projektált pontszám **6,8 / 10**.
- **2026-08-03** — **1.5 kész**, és a javítás egy réteggel mélyebbre nyúlt, mint a terv szövege.
  A `check_saved_search_hits.py` mostantól explicit hibát ad, ha a keresés nem ér el `DONE`-t a
  120s alatt (eddig ilyenkor **mégis lekérte az eredményeket** és `error=None`-nal 0 eventet írt —
  megkülönböztethetetlenül attól, hogy „a detektálás nem tüzelt"), és a `FINALIZING` már nem
  szakítja meg a poll-ciklust. Ez utóbbi nem szigorítás, hanem pontosítás: a mockolt teszt szerint
  a „FINALIZING majd DONE" eset eddig **1 eventet** olvasott volna a valós **3** helyett.
  **Amiért a script javítása önmagában kevés lett volna:** az `evaluate()` *minden* hibát FAIL-re
  képezett le (`if error: return FAIL`), tehát a timeout explicitté tétele csak az indoklást tette
  volna őszintébbé — a verdikt ugyanaz maradt volna. Ezért a hibák mostantól **típussal**
  érkeznek: minden hibaág kap egy `error_kind`-ot, `unmeasured` (nem tudtuk megmérni: nincs
  `DONE`, hálózati hiba, értelmezhetetlen válasz, HTTP 5xx) vagy `rule_error` (tényleg baj van:
  nincs ilyen saved search, vagy a search job hibázott Splunk-oldalon). Az előbbi **NOT_VERIFIED**,
  az utóbbi marad **FAIL**. A szétválasztás azért kellett, mert a `NOT_VERIFIED`-be terelt
  *minden* hiba elrejtette volna a valódi defekteket (ki nem deployolt szabály, hibás SPL).
  **Konzervatív és visszafelé kompatibilis:** csak a pontosan `unmeasured` kind lágyít; a hiányzó
  vagy ismeretlen `error_kind` (a mező bevezetése előtt írt fájlok) a régi FAIL-viselkedést tartja.
  Tesztelve: 9 verdikt-eset + 8 poll-eset mockolt Splunkkal.
  **A legend átírva** — a felhasználó kérdése nyomán, aki jogosan vette észre, hogy a
  `NOT VERIFIED` leírása mintha már fedné ezt az esetet. A régi szöveg azt állította, hogy ez az
  állapot „only reaches rules tested by Atomic Red Team"; a mérés-oldali útvonallal ez **már nem
  igaz**, az minden szabályt elér. Az új szöveg a két útvonalat külön nevezi meg, a FAIL leírása
  megkapta a `rule_error` eseteket, és a `VERDICT_RANK` kommentje is pontosítva.
  Ezzel a *verdiktek megbízhatóságát* rontó kritikus hibák elfogytak.
  Kész súly: 15/86,5, projektált pontszám **6,9 / 10**.
- **2026-08-03** — **1.6 kész, 4.10 részben.** Új `ci_code_checks.yml`, a pipeline saját CI-ja.
  **Amiért nem a register javaslatát követtük:** a `scripts/docs/**` felvétele a `paths:` listára
  nem működött volna. A `changes` step (`ci_dev_workflow.yml:96-127`) csak akkor eszkalál
  `mode=all`-ra, ha a `sigma_schema.json`, a `scripts/validate/*` vagy a `sigma_to_spl.py`
  változott; egyébként a `rule_files` a változott `rules/sigma/` fájlokból áll, és ha az üres,
  `has_rules=false` → minden job kimarad. A run tehát elindult volna, azonnal átugrik mindent, és
  zölden végez — a stats sem generálódik újra.
  **A tétel két problémát takart, mindkettő rendezve:** (a) semmi nem ellenőrizte a pipeline saját
  kódját → `checks` job (ruff + pytest) `ubuntu-latest`-en, Splunk és éles támadás nélkül;
  (b) egy generátor-változás nem generálta újra a publikált oldalt → `regenerate_docs` job.
  **A (b)-hez kellett egy harmadik job is:** a Pages **artifactból** publikál, nem a branchről
  (`ci_dev_workflow.yml` `deploy_pages`), tehát a commit a repót frissítette volna, az élő oldalt
  nem. Az új `deploy_pages` ugyanazt a `pages` concurrency-csoportot használja, mint a devé, hogy
  a két publikálás sorba álljon.
  **Tartalom:** ruff `F` + `E9` szabályokkal (a teljes készlet egy sosem lintelt, ~6000 soros
  fájlon formázási véleményekbe fojtaná a valódi hibákat — a bővítés a **2.12** alatt marad; a
  szűk beállítás így is talált egy használatlan `sys` importot), 25 pytest teszt a mai 1.4-es és
  1.5-ös munkából (mockolt Splunk, ezredmásodpercek), `pyproject.toml` a gyökérben (ruff és pytest
  onnan találja meg magától), `__pycache__` a `.gitignore`-ba, a teszt-eszközök pinelve a
  `.github/requirements-dev.txt`-ben.
  **Hátra a 4.10-ből:** actionlint, shellcheck, PSScriptAnalyzer, pip-audit — ezért `[~]` és nem
  `[x]`, a registerben `részben kész` taggel, pipa nélkül.
  **Az „újragenerálva" ≠ „változott" csapda, menet közben javítva:** a generátor minden futásnál
  időbélyeget és HEAD-sha-t stempel a kimenetbe, tehát két azonos forrású futás sem byte-azonos.
  Egy sima `git diff --quiet` így soha nem adna igazat — minden dev-push után keletkezne egy
  „regenerálás" commit, és a `published` jelzés értelmét vesztené. A job ezért **normalizálja** az
  időbélyegeket és a sha-t, és csak akkor committol, ha ezeken túl is eltér valami. Szándékosan
  **nem** diff-sorok szűrésével: az `index.html` a `COVERAGE_HISTORY`-t és a `RULE_GROWTH_HISTORY`-t
  egy-egy hatalmas sorban tartalmazza, amiben a valódi adat *és* egy időbélyeg is ott van — egy
  sorszintű szűrő némán eldobná a valódi lefedettség-változást. Öt esetre letesztelve a workflow
  tényleges kódjával (byte-azonos / csak időbélyeg / `pass_rate` változás / a hosszú history-soron
  belüli érték-változás / új napi pont).
  **Új megfigyelés, ami nincs külön tételként:** a `paths:` lista és a `mode=all` eszkalációs lista
  nem fedi egymást — a nyolc trigger-útvonalból öt üres futást produkál (zöld pipa, nulla munka).
  Érdemes felvenni tételként.
  Kész súly: 18/86,5, projektált pontszám **7,0 / 10**.
- **2026-08-03** — **1.12 kész, de nem ebben a körben** — a tétel a következő elem kiválasztásakor
  derült ki késznek, ezért itt lezárás, nem javítás. A rule browser átdolgozása közben oldódott
  meg, csak nem került be a naplóba, így a register egy már nem létező hibát mutatott.
  **Ami él:** a cellák `has_fail` alapján `fail-flag` osztályt kapnak (`generate_stats.py:556,612`),
  amit piros sarok-háromszögként rajzol a CSS (`:2421-2428`); a már eleve FAIL cellák kihagyják,
  mert a saját bal oldali railjük ugyanezt mondja. A legend-szűrő pedig nem halott többé: a
  `tcHasFail()` / `failAny` páros (`:5497,5506,5601`) **keresztbe vág** a best-verdict
  csoportosításon, tehát a FAIL szűrő megtalálja azokat a cellákat is, amiket a roll-up zöldre
  színez. A cella színe szándékosan maradt best-verdict — a hőtérkép elsődleges kérdése továbbra
  is „van működő lefedettség?", a jelölés csak nem hagyja elveszni a másik választ.
  **Élesben igazolva a mai kimeneten**, nem csak kódolvasással: a `docs/index.html`-ben 5 cella
  visel `fail-flag`-et, köztük a `T1685.001` és a `T1059.001` a `DETECT-2026-0012` (AMSI Bypass,
  FAIL) miatt, és a szülő `T1685` / `T1059` is megkapja a
  `title="A sub-technique rule failed verification"` tooltipet. A `navigator_layer.json` exportban
  ugyanez `⚠ 1 of N covering rule(s) FAILED verification` megjegyzésként szerepel.
  **Tanulság a munkamenetre:** a register `dev @ 22799a5` (2026-07-26) állapotára készült, és a
  rule browser azóta jelentősen átalakult — a további tételeknél érdemes az aktuális kódon
  ellenőrizni, mielőtt nekiállunk. Ez az egy tétel 3 súlypont munka nélkül.
  Kész súly: 21/86,5, projektált pontszám **7,1 / 10**.
- **2026-08-03** — **1.11, 1.10, 1.9 kész**, egy blokkban, mert mindhárom a `run_atomic.ps1`-ben
  van, és a runner oldali teszt-higiéniáról szól.

  **1.11 — a Defender-visszaállítás.** Először is kiderült, hogy ez nem elméleti kitettség volt:
  az `ATOMIC_DISABLE_REALTIME_MONITORING` alapértelmezése **mindkét** atomic stepen `'true'`
  (`ci_dev_workflow.yml:461,533`), tehát a real-time monitoring *minden* futáskor ki volt
  kapcsolva, és minden `timeout-minutes: 10`-be futó step védtelenül hagyta a hostot.
  A `finally` blokk elvi okból nem tudta megoldani: a folyamatfa lebontásakor nem fut le. Ezért a
  garancia mostantól a folyamaton kívül él, egy `DetectionEngineering-RestoreDefenderRealtime`
  nevű scheduled taskban, ami SYSTEM-ként visszakapcsolja a monitoringot. **Két trigger**, mert
  kétféleképpen lehet beragadni: `Once` most + 20 percre (a folyamatot megölték, a gép megy
  tovább) és `AtStartup` (a gépet újraindították, amíg a védelem ki volt kapcsolva, így az
  egyszeri trigger sosem sült el). A 20 perc szándékosan jóval a step saját 10 perces timeoutja
  fölött van: így fogalmilag csak azután süthet el, hogy a script már halott — teszt közben soha,
  mert az visszakapcsolná a Defendert a mérés alatt, és pont hamis FAIL-eket gyártana.
  A task a kikapcsolás **előtt** kerül regisztrálásra, hogy ne legyen olyan pillanat, amikor a
  védelem már le van véve, de még semmi nem hozza vissza. **Fail-closed:** ha a task nem
  regisztrálható, a script nem kapcsolja ki a Defendert, hanem hibával megáll — felmentés
  `ATOMIC_ALLOW_UNPROTECTED_DISABLE=true`. Ez tudatos szigorítás: enélkül pont abba az állapotba
  kerülnénk, ami miatt a tétel egyáltalán létezik. Tiszta lefutásnál a `finally` visszakapcsol és
  leszedi a taskot; ha maga a visszakapcsolás hibázik, a task **szándékosan marad**, mert onnantól
  ő az egyetlen, ami visszahozza a védelmet. Induláskor egy ottfelejtett task `::warning`-ot kap:
  a puszta jelenléte bizonyíték arra, hogy az előző futás nem állt le rendesen, és a
  `Register-ScheduledTask -Force` különben némán felülírná ezt a nyomot.

  **1.10 — `-GetPrereqs` és `-Cleanup`.** Az `Invoke-AtomicTestCompat` kapott egy `-Mode`
  paramétert (`GetPrereqs` / `Run` / `Cleanup`). Azért mód és nem két új kapcsoló: ezek az
  `Invoke-AtomicTest`-en **egymást kizáró** kapcsolók, nem összeadódó flagek, tehát tesztenként
  három külön invokáció fut, nem egy bővebb. A cleanup `finally`-ben van, tehát akkor is lefut,
  ha a teszt dobott, és sem a prereq-, sem a cleanup-hiba nem növeli a `$failures`-t — a verdikt
  a detekcióról szól, nem a háztartásról. A meglévő compat-minta megtartva: ha a telepített modul
  nem ismeri a kapcsolót, warning és kihagyás, nem hiba. A `-ShowDetails` logika a `Run` módra
  szűkült, különben a prereq- és cleanup-passzok megháromszoroznák a logot információ nélkül.
  **A verifikációra gyakorolt hatást külön végiggondoltam:** a cleanup nem ronthatja el a mérést,
  mert a Splunk a forwarder által már kiküldött eventekből dolgozik, az artifact utólagos törlése
  nem szedi vissza őket. A valódi kompromisszum az, hogy egy cleanup-parancs maga is üthet
  szabályt (kulcstörlés, fájltörlés) — ez az Atomic Red Team cleanup-modelljéből következik, nem
  ebből a változtatásból, és `ATOMIC_SKIP_CLEANUP` a kiút, ha előjön.

  **1.9 — egy hibás szabály ne vigye el a batch-et.** Két rétegben. A sémában `allOf` + `if/then`
  köti a `custom.testing.type`-ot ahhoz a tömbhöz, amire szüksége van (`atomic` → `atomics`,
  `emulation` → `custom`), **`enabled: true`-ra szűkítve**, hogy egy leparkolt szabály ne
  kényszerüljön teszt-listát fenntartani. A `runner`-t a register javasolta kötelezőnek, de
  **szándékosan nem tettük azzá**: a script az üres runner-mezőt „minden runnerre érvényes"-ként
  kezeli, ez működő eset, nem hibaállapot.
  A scriptben mind a **négy** `throw` (hiányzó `.spl`, hiányzó meta sidecar, üres
  `atomics`/`custom`, hiányzó `technique`) `Write-Warning` + `continue` lett — a register kettőt
  nevezett meg, de a `Read-MetaFromSplFile` két dobása ugyanígy megölte a batch-et. `$malformed`
  számláló és `::warning` annotáció, hogy a degradálás ne legyen csendes. Az érintett szabály
  progress-marker nélkül marad, amit a `pass_fail_eval.py` már ma is „meg sem kíséreltük"-ként
  olvas: a verdikt őszinte marad, nem találunk ki helyette semmit.
  Új ág a végén: ha a batch **összes** szabálya hibás metaadatú, `exit 1`. A „nincs mit futtatni"
  és a „minden elromlott" egyaránt nulla teszt, de csak az egyik érdemel zöld pipát.

  **Tesztelés — és ami hiányzik belőle.** A séma oldala mérve: önmagában érvényes, mind a 27
  szabály átmegy rajta, és három szintetikus eset a várt módon viselkedik (`type: atomic` tömb
  nélkül → INVALID, `type: emulation` `custom` nélkül → INVALID, `enabled: false` tömb nélkül →
  OK). A PowerShell oldala **nincs gépi ellenőrzéssel megerősítve**: nincs `pwsh` ezen a gépen,
  úgyhogy csak struktúra-ellenőrzés futott (kiegyensúlyozott blokkok, `try`/`catch`/`finally`
  párok) plusz kézi átolvasás. A `PSScriptAnalyzer` a **4.10** hátralévő részének darabja, és
  pont ezt zárná le — érdemes előrevenni.
  Kész súly: 30/86,5, projektált pontszám **7,4 / 10**.
- **2026-08-03** — **PSScriptAnalyzer bekötve** (a **4.10** négy maradékából az első). Nem terv
  szerinti sorrend: az előző bejegyzés végén jelzett vakfolt zárása, mielőtt a 3.3-ra lépnénk.
  Az 1.9–1.11 blokk 326 sornyi PowerShellt módosított, amit semmi nem ellenőrzött — ruff és
  pytest Python-only, lokálisan nincs `pwsh` —, tehát a `run_atomic.ps1`-et először a Windows
  runner parse-olta volna egy élő atomic futás közben, a repo leglassabb visszacsatolási
  hurkában.
  **Külön `powershell_analysis` job, nem két új step a meglévőben:** a stepek sorban futnak, tehát
  egy ruff-hiba elfedné a PowerShell-hibát a következő pushig, és egy `.ps1` parse-hibának semmi
  keresnivalója egy Python-tesztekről elnevezett job alatt. Párhuzamosan fut, tehát nem kerül
  falióra-időbe; `ubuntu-latest`, Windows nem kell hozzá. A `regenerate_console` mostantól
  `needs: [static_analysis, powershell_analysis]`.
  **Két lépcső, szándékosan.** Előbb egy *parse check* a PowerShell saját parserével
  (`[System.Management.Automation.Language.Parser]::ParseFile`): ez független attól, hogy melyik
  analyzer-szabály van bekapcsolva, és pont az a hibaosztály a célpontja, amit egy `pwsh` nélküli
  gépen írt szerkesztés hoz be. Utána a `PSScriptAnalyzer`, **1.25.0-ra pinelve** — a Gallery API
  szerint ez a legfrissebb stabil (2026-03-20, nem prerelease), és ugyanaz a logika, mint az
  **1.3** Python-pinjeinél: egy lebegő linter más kiadási ütemterve szerint pirosít be egy nem
  kapcsolódó PR-t.
  **A kapu szűk, a ruff-precedenst követve:** `Error` és `ParseError` buktat, a `Warning` csak
  annotáció. Három szabály kizárva a `.github/PSScriptAnalyzerSettings.psd1`-ben, mindegyik
  indoklással a fájlban: `PSAvoidUsingWriteHost` (a scriptek szándékosan a CI-logba írnak, a
  `Write-Output` a pipeline-ra tenné a szöveget, ahol a hívók visszatérési értékként kapnák meg),
  `PSAvoidUsingInvokeExpression` (az emulation-executor lényege, hogy a szabály saját, sémával
  validált parancsát futtatja — állandó riasztás arra tanítana, hogy a szabályt hagyjuk figyelmen
  kívül), `PSUseShouldProcessForStateChangingFunctions` (belső, nem exportált, sosem interaktív
  függvényekre ceremónia lenne). Külön `.psd1` és nem inline `-ExcludeRule`, hogy a kizárások
  megtalálhatók és szerkeszthetők legyenek, ne a workflow közepén ülve.
  **Amit ez nem old meg:** a job maga sincs lefuttatva — a YAML szerkezete ellenőrizve
  (`yaml.safe_load`, 4 job, helyes `needs`-lánc, `shell: pwsh` a három stepen), de a `pwsh`-kód
  és a `.psd1` érvényessége csak az első CI-futáson derül ki. A `.psd1` szintaxisát sem tudtam
  lokálisan parse-olni, ugyanabból az okból, amiért az egész job létrejött.
  **Hátra a 4.10-ből:** actionlint, shellcheck, pip-audit.
- **2026-08-03** — **3.3 fele kész: a reconcile `--check`.** Új `scripts/state/reconcile.py`,
  **kizárólag olvasó** — nincs `--apply`, tudatosan. A törlés automatizálása külön döntés, külön
  hatósugárral, és úgy helyes meghozni, hogy ez a riport már a kézben van, nem egyszerre azzal,
  ami előállítja.
  **Desired state a `rules/sigma/*.yml`-ből**, nem a `.meta.json` sidecarokból: azok futás közben
  keletkeznek és gitignore-oltak (`.gitignore:1`), tehát CI-futáson kívül nem is léteznek. A
  `detect_id` és a `title` viszont top-level Sigma mező, és ugyanaz a `saved_search_name()` képzi
  a nevet, amit a deploy használ — így konverzió futtatása nélkül reprodukálja a deploy nevezéktanát.
  **Actual state** a `servicesNS/{owner}/{app}/saved/searches` endpointról, `count=0`-val. Ez utóbbi
  nem kozmetika: a Splunk alapértelmezésben 30 sort ad vissza, tehát enélkül a 27 szabály ma még
  átférne, de a 31. rögtön „hiányzónak" látszana.
  **Új `ci_managed` sidecar-mező nem kellett.** A terv eredetileg arra épített volna, de a deploy
  már ma minden leírásba beleírja, hogy „Managed by CI/CD (Detection-Engineering repo)"
  (`deploy_spl_to_splunk.py:260`) — ez de facto CI-jelölő. És a jelölőnek amúgy is a Splunk-objektumon
  a helye, nem a repóban: egy repo-oldali mező csak olyan szabályt tud leírni, ami még megvan,
  az árva viszont épp az, ami már nincs meg.
  **Öt vödör, nem három.** A tervben `missing`/`orphan`/`drifted` szerepelt; a tényleges bontás
  `in_sync`, `missing`, `orphan_renamed`, `orphan_removed`, `unmanaged`. A két árva-vödör
  szétválasztása a lényegi rész: ugyanaz a tünet, két különböző ok és két különböző teendő. Ha az
  árva objektum `detect_id`-ja **még megvan** a repóban, az egy *átnevezés* maradéka (**1.8**) — a
  szabály él és virul új néven, ez a régi héja, biztonsággal törölhető. Ha a `detect_id` **sincs**
  meg, az egy *eltávolítás* (**1.7**), ami ránézést érdemel, mert egy szabály eltűnése nem mindig
  szándékos. Az `unmanaged` (CI-jelölő nélküli, kézzel épített kereső) jelentve van, hogy a számok
  kijöjjenek, de sosem minősül driftnek — a pipeline nem hozta létre, nincs róla véleménye.
  **A query-drift szándékosan kimaradt.** Kézenfekvő lett volna összevetni a repo `.spl`-jét a
  Splunkban tárolt kereséssel, de a Splunk normalizálja a lekérdezést, tehát ez megbízhatóan hamis
  driftet gyártana — egy zajos ellenőrzés pedig rosszabb, mint a hiánya.
  **CI-integráció:** a `splunk_verify` job végén fut, `always()` + `continue-on-error`, és **nem**
  buktat (`--fail-on-drift` létezik, de nincs bekapcsolva). Ez szándékos: a riport a Splunk
  *meglévő* állapotáról szól, aminek semmi köze ahhoz, hogy az adott futás szabályai jók-e —
  kapuzni rajta annyit jelentene, hogy valaki más által okozott drift blokkol egy független munkát.
  A JSON kimenet `outputs/state/`-be megy és build artifactként utazik, **nem** commitolva:
  egy pillanatnyi Splunk-állapotról szól, nem a repóról, és futásonként egy tartalmatlan commitot
  termelne. Menet közben javított csapda: eredetileg `outputs/reports/`-ba írt volna, amit a
  következő step `git add outputs/reports/`-tal tömegesen stage-el — így némán bekerült volna.
  A publikálása a dashboardra a **4.7**, ott kell eldönteni.
  **Tesztelés:** 15 új teszt mockolt Splunkkal (osztályozás, `count=0`, a 401/403 mint végzetes
  hiba — mert egy elutasított kérés üres listája az egész könyvtárat „hiányzónak" mutatná —,
  nem-JSON válasz, és hogy egy parse-olhatatlan szabály inkább hibát dob, mint hogy némán
  zsugorítsa a desired state-et). Teljes suite 40 teszt, ruff tiszta. Plusz száraz futtatás a
  valós 27 szabályon, szimulált Splunkkal, mind az öt vödörre.
  **A pontszám nem mozdul: 30/86,5, 7,4 / 10.** A három érintett tétel (**1.7**, **1.8**, **3.3**)
  mind `[~]`, mert a register saját szabálya szerint félkész tétel nem kap súlyt — és ez itt
  pontos: a felderítés kész, a beavatkozás nem.
- **2026-08-04** — **1.8 lezárva, nem javítással: a javasolt fix elutasítva.** Felhasználói döntés a
  következő tétel kiválasztásakor: a Splunk objektumnév **nem** lehet csak a `detect_id`, maradjon
  beszédes (`detect_id + slug(title)`). A register indoklása — „az olvashatóság a description-ben
  megmarad" — a gyakorlatban nem áll meg: a Splunk keresőmezőjében, a saved-search listában és a
  riasztás-hivatkozásokban az analitikus a *nevet* látja, a leírást csak akkor, ha külön megnyitja.
  Az immutable identitás ára itt magasabb, mint a haszna.
  **Amit ez jelent:** a kiváltó ok tudatosan vállalt állapot lett, nem nyitott defekt — a title
  átírása továbbra is új objektumot hoz létre, és a régi ott marad. A tünet kezelése teljes egészében
  a **3.3**-ra kerül: az `orphan_renamed` vödör pontosan ezt az esetet azonosítja (a `detect_id`
  megvan a repóban, csak a slug mozdult), az `--apply` pedig törli a régi héjat. Az árvaság tehát nem
  megszűnik keletkezni, hanem **észlelt és takarított** állapottá válik.
  **Következmény az `--apply` tervezésére, amit külön ki kell mondani:** eredetileg a renamed-vödör
  törlése egyszeri migrációnak indult (a névséma-váltás után mind a 27 objektum árvává vált volna).
  A séma-váltás elmaradásával viszont a rename **normál üzemi esemény** — minden title-átfogalmazás
  termel egy árvát —, tehát a renamed-vödör takarításának rutinszerűen, a deploy után futtathatónak
  kell lennie, nem csak kézi `workflow_dispatch`-ként. Ez a `removed` vödörre **nem** vonatkozik: ott
  a `detect_id` is eltűnt a repóból, ami nem mindig szándékos, tehát az marad kézi döntés.
  Ezzel a 12 kritikus tételből 11 kész, egyedül az **1.7** maradt.
  Kész súly: 33/86,5, projektált pontszám **7,5 / 10**.
- **2026-08-04** — **3.3 kész: a reconcile `--apply`.** A tegnapi olvasó riport mellé megvan a
  beavatkozás, **két külön hatósugárral**, mert a két árva-vödör nem ugyanaz a kockázat.
  **`--apply` — átnevezés-árvák törlése, automatikusan a dev CI-ban.** Az 1.8 lezárása után a
  rename normál üzemi esemény: minden title-átfogalmazás termel egy árvát, tehát ennek felügyelet
  nélkül kell mennie, különben a Splunk lassan megtelik holt objektumokkal.
  **`--apply-removals` — eltávolítás-árvák kikapcsolása, kézzel.** Nem törlés: `disabled=1` plusz
  `[RETIRED <dátum>]` prefix a leírás elejére. A törlés a Splunk-oldali ütemezést és
  riasztás-konfigurációt is elvinné, a kikapcsolás viszont visszafordítható — és egy szabály
  eltűnése a repóból nem mindig szándékos. A CI **nem** kapja meg ezt a kapcsolót; `argparse`
  szinten is kikényszerítve, hogy `--apply` nélkül ne legyen használható.
  **Menet közben talált saját hiba, ami nélkül a tétel kárt okozott volna:** az „a szabály él az új
  néven" indoklás *feltevés* volt, nem ellenőrzés. Ha a deploy elhasal, az új nevű objektum sosem
  jön létre, a régi viszont árvaként azonosítható — az automatikus törlés így pont egy frissen
  szerkesztett szabályt hagyott volna **nulla saved search-csel**, csendben. A `reconcile()` ezért
  minden rename-árvához eltárolja az utódja nevét és azt, hogy az él-e (`replacement_live`), és az
  `--apply` élő utód nélkül nem töröl, hanem kiírja, miért nem.
  **Idempotencia és a riport hitelessége:** egy már kivezetett objektum újbóli látásakor nincs
  második írás (a `[RETIRED` prefix a jel), és `has_drift()` nem számítja driftnek — enélkül az
  első kivezetés után a riport örökre piros maradna, és három futás után senki nem nézné.
  **A `unmanaged` vödörhöz egyik kapcsoló sem nyúl:** amit nem a pipeline hozott létre, arról nincs
  véleménye.
  **CI-bekötés:** a meglévő `Reconcile Splunk state` step kapott egy `--apply`-t, plusz a step
  mostantól **továbbadja a script exit kódját** (`PIPESTATUS` + `exit "$rc"`). Enélkül a
  step utolsó parancsa a step-summary `echo` volt, tehát egy el nem szállt takarítás zöld pipát
  kapott volna. A `continue-on-error` marad, tehát a run nem bukik el rajta — csak látszik.
  **Tesztelés:** 13 új teszt (összesen 53), köztük külön eset arra, hogy élő utód nélkül nem törlünk,
  hogy a `removed` vödörhöz `--apply` egyedül nem nyúl, hogy a kivezetés POST-ja `disabled=1`-et
  küld és **megőrzi a CI-jelölőt** a leírásban (különben a következő futás már nem ismerné fel
  sajátjaként), és hogy a `--apply-removals` `--apply` nélkül `SystemExit`. Plusz egy végponttól
  végpontig száraz futtatás a valós 27 szabályon, szimulált Splunkkal, 7 forgatókönyvre.
  **Az 1.7 nincs kipipálva**, mert a Splunk-oldali kivezetés csak az egyik fele: a `deprecated`
  státusz kizárása a deployból és a törölt szabály repo-oldali `.spl`/result maradványai hátravannak.
  Kész súly: 35/86,5, projektált pontszám **7,5 / 10**.
- **2026-08-04** — **A kör lezárása: 2.13, és az architektúra-dokumentáció utolérése.**
  **2.13 lezárva, törléssel** — a `rule_documentations/` már nem volt a repóban, a tétel csak a
  registerben maradt nyitva. A repo teljes fájl-leltára közben derült ki, ahol az volt a kérdés, mire
  nincs valójában szükség. A generálás mint lehetőség a **4.8** alatt él tovább; a
  `detection-content-reviewer` agent leírásából kikerült a rá épülő rész, ami addig egy nem létező
  könyvtárba írt volna.
  **Az architektúra-dokumentáció utolérte a kódot.** A `pipeline_overview.md` és a `data_flow.md`
  egyáltalán nem említette sem a reconcile-t (2026-08-03 óta), sem a prune-t (ma) — a `docs/` a
  pipeline *előrefelé* menő útját írta le, a kivezetésről egy szó sem esett benne. Új **Retirement —
  the reverse path** szakasz az áttekintőben (az öt vödör, a két árva-típus eltérő kezelése és annak
  indoka, a `deprecated` szerepe), a job-táblában a két új step, a `data_flow.md`-ben pedig a
  reconcile-artifact, a harmadik `[skip ci]` commit és a CI-jelölő szerepe a Splunk-objektumokon.
  Szándékosan **nem** új számozott stage lett belőle: a kivezetés nem az 1–11-es lánc egy pontja,
  hanem két, a lánc két különböző pontjára akasztott takarítás.
  **Nem audit-tétel, de ide tartozik:** a `.claude/settings.json` doksi-szinkron hookja javítva. Három
  hibája volt — az `if` szűrője commit nélküli Bash-hívásokra is elsült, jogosultság híján blokkoló
  hibát dobott csendes kilépés helyett, és mindig a HEAD-et elemezte, tehát ugyanazt a régi commitot
  sürgette újra meg újra. Mostantól öt kapun megy át, és bármelyik bukása néma kilépés. A hook
  továbbra sem lát IDE-ből indított commitot — csak a Bash-en át futókat.
  Kész súly: 39/86,5, projektált pontszám **7,6 / 10**.
- **2026-08-04** — **1.7 kész. Ezzel mind a 12 kritikus tétel lezárult.** A délelőtti `--apply`
  után a maradék két repo-oldali darab is megvan.
  **(a) `status: deprecated` kizárása a deployból.** A séma kezdettől engedte, de egyetlen script
  sem olvasta — egy leparkolt szabály ugyanúgy kiment és futott, mint egy stable. A deploy
  mostantól kihagyja (`deploy_spl_to_splunk.py`), **prodban is**: a prod job regenerálja a
  `.meta.json` sidecarokat és ugyanezt a scriptet futtatja, tehát nem kellett külön prod-ág.
  A kihagyás **nem** töröl: egy már fent lévő objektumot csak akkor vezetünk ki, ha valaki
  szándékosan megteszi. Ehhez a `reconcile.py` desired state-jéből is kikerült a deprecated
  szabály — így az élő objektuma *eltávolítás-árvaként* jelenik meg, amit az `--apply-removals`
  kikapcsol. A kézenfekvő alternatíva (bent hagyni a desired state-ben) rosszabb lett volna:
  örökre „missing"-ként jelentené, és olyan deployt sürgetne, ami definíció szerint sosem jön.
  **(b) Repo-oldali maradványok.** Új `scripts/state/prune_orphans.py`: törli a `rules/splunk/*.spl`
  fájlokat és az `outputs/results/<detect_id>/` könyvtárakat, amikhez már nincs szabály. A kettő
  külön kulcsra megy — az `.spl` a *fájlnevet* tükrözi, a result könyvtár a *detect_id*-t —, ezért
  egy fájl-átnevezés csak az elsőt árvítja el; ez tesztként is rögzítve van.
  **Miért saját CI-step és saját commit:** a meglévő „Commit converted SPL outputs" step a
  `has_spl` → `has_rules` láncon lóg, ami a `--diff-filter=AMRC`-ból jön. Egy *tisztán törlő* push
  tehát nulla `rule_files`-t termel, minden job kimarad, és a takarítás sosem futna le — pont az az
  esemény hozza létre az árvát, amit a pipeline többi része nem lát. A step ezért nincs
  `has_rules`-ra kötve, és a Python-deps telepítése is meg van benne oldva külön (az `Install
  Python deps` szintén `has_rules`-gated).
  **Miért állapot-összevetés és nem diff:** a diff azt mondja meg, mit csinált egy commit; itt
  viszont az a kérdés, mi az, ami *most* gazdátlan. Így önjavító (a korábban elmaradt takarítást is
  behozza) és idempotens.
  **Fail-safe:** üres `rules/sigma/` esetén a script hibával megáll ahelyett, hogy az egész
  könyvtárat árvának minősítené — egy rossz útvonal vagy féloldalas checkout nem törölheti le a
  teljes szabálykönyvtárat. Egy értelmezhetetlen szabály szintén megállítja: az egy *létező*
  szabály, ami csak hibás, nem pedig egy törölt.
  **A deprecated szabály artefaktjai megmaradnak** — a szabály a repóban van, a mérési előzménye a
  sajátja; a deprecation azt változtatja meg, hogy a Splunkban ne fusson, nem azt, hogy a története
  eltűnjön.
  **Tesztelés:** 12 új teszt (összesen 65, mind zöld), köztük három a deploy-kihagyásra fake
  Splunkkal (deprecated → *nulla* HTTP-hívás; stable → változatlanul deployol; a kihagyás nem
  számít hibának), és a prune fail-safe ágai. Száraz futtatás a valós repón: nulla árva.
  Kész súly: 38/86,5, projektált pontszám **7,6 / 10**.
- **2026-08-04** — **4.10 kész: actionlint, shellcheck, pip-audit.** Ezzel a pipeline saját CI-ja
  mind a hat eszközt futtatja. Közvetlen indok: az elmúlt két tételben (2.2, 2.5) megint
  workflow-YAML-t és bash-t írtam, amit semmi nem ellenőrzött — a workflow-k a repo egyetlen
  jelentős kódrétege voltak, amit csak a GitHub Actions olvasott, futásidőben, a leglassabb
  visszacsatolási hurokban.
  **Az actionlint helyben lefuttatva, mielőtt CI-ba került.** Ez fogta meg, hogy a job különben
  azonnal pirosra váltott volna: **10 találat, mind ugyanaz a téves riasztás** — a self-hosted
  runnerek egyedi címkéit (`de-lab`, `victim`, `atomic`, `windows-victim`, `dc`, `windows-dc`) nem
  ismeri. Ezért új `.github/actionlint.yaml`; utána nulla találat. Mellékhaszon: ez az egyetlen hely
  a repóban, ahol a várt runner-címkék listaként le vannak írva, tehát egy elgépelt `runs-on:`
  (ami különben örökre sorban álló jobot eredményez) mostantól lint-hiba.
  **A shellcheck nem külön step:** az actionlint maga futtatja minden `run:` blokkon. Egy önálló
  shellcheck-stepnek előbb ki kellene bányásznia a scripteket a YAML-ből, hogy egyáltalán lássa
  őket. Cserébe a shellcheck jelenléte teherhordóvá vált — ha eltűnne a runner-image-ből, az
  actionlint továbbra is zölden futna, csak szigorúan kevesebbet ellenőrizve —, ezért külön step
  **állítja**, hogy ott van, nem feltételezi.
  **A pip-audit szándékosan nem kapu** (`continue-on-error`). Egy pinelt függőség ellen publikált
  sebezhetőség valós információ, de a világ ütemterve szerint érkezik, nem a repóé szerint: egy
  éjjel megjelent CVE különben másnap reggel minden független PR-t pirosra váltana, olyan
  problémáért, amit abban a PR-ben senki nem okozott és nem is tud megjavítani. A találat hangosan
  látszik (annotáció + step summary), a job failed-but-continued állapotban — ugyanaz a minta, amit
  a dev pipeline reconcile-stepje használ.
  **Ezt a döntést az első futás rögtön igazolta:** a pip-audit helyben lefuttatva **valós találatot
  ad ma is** — `diskcache 5.6.3`, PYSEC-2026-2447 (CVE-2025-69872), unsafe pickle deserialization,
  **javított verzió nincs**, mert a sérülékenység minden kiadást érint az 5.6.3-ig bezárólag, ami a
  legfrissebb. A lánc: `pySigma 1.5.0` → `diskcache>=5.6.3,<6.0.0`. Ha ez kapu lenne, a CI most
  azonnal piros volna, elérhető javítás nélkül. Amikor a diskcache kiad javítást, a `<6.0.0`
  tartomány miatt magától bejön — a tranzitív függőségek lebegése, amit a **2.11** hiányosságként
  tart nyilván, itt épp a javunkra dolgozik.
  **Gyakorlati kockázat ebben a repóban:** a támadáshoz írási jog kell a cache-könyvtárhoz. A
  `ubuntu-latest` runnereken a fájlrendszer futásonként eldobódik; a **prod self-hosted runner**
  viszont perzisztens lemezen futtat pySigmát a `deploy_to_prod` re-konverziójakor — ott egy korábbi,
  kompromittált futás elvileg mérgezett cache-bejegyzést hagyhatna. Szűk, de nem nulla.
  Kész súly: 42,5/86,5, projektált pontszám **7,7 / 10**.
- **2026-08-04** — **A doksi-hook agentből determinisztikus scriptté alakítva.** Nem audit-tétel,
  hanem elvi döntés a felhasználótól: *a repo működésében semmi nem függhet agenttől vagy LLM-től —
  az agentek a fejlesztéshez és a dokumentáláshoz vannak.* Ellenőrizve: a `.github/workflows/` és a
  `scripts/` **nulla** LLM- vagy agent-hivatkozást tartalmaz, tehát maga a pipeline eddig is
  agent-független volt; az egyetlen kivétel a `.claude/settings.json` `agent` típusú hookja volt.
  **Miért kellett lecserélni, a tegnapi javítás ellenére is:** a kapuk jól működtek — a hook minden
  alkalommal helyesen ismerte fel, hogy nincs commit —, de az `if` szűrő **nem szűrt**: a hook így is
  elindult minden Bash-hívásra, és a leállását a rendszer blokkoló hibaként jelenítette meg. Egyetlen
  munkamenetben négyszer, és minden alkalommal egy fölösleges modell-hívással.
  **Az új megoldás** `.claude/hooks/docs-drift-check.sh`: három git-parancs és egy útvonal-illesztés,
  LLM nélkül. Három kapu — (1) van-e egyáltalán `git commit` a parancsban, ez zárja le a hívások
  túlnyomó részét azonnal; (2) tényleg landolt-e friss commit (a HEAD kora), ami determinisztikusan
  váltja ki a korábbi „mindig ugyanazt a régi commitot sürgeti" hibát; (3) érintett-e a commit olyan
  útvonalat, amiről a doksi állít valamit. Mindig `exit 0`: emlékeztető, sosem kapu.
  **Menet közben talált hiba, amit a teszt fogott meg:** eredetileg `git diff-tree -r HEAD`-et
  használtam, ami **szülő nélküli commitra üres kimenetet ad** — egy repo legelső commitjánál a
  vizsgálat tartalomtól függetlenül némán átengedett volna. `git show --pretty=format: --name-only`
  erre is helyes.
  **7 teszt** a `.claude/hooks/test-docs-drift-check.sh`-ban, eldobható git-repóval, valós
  commitokon: a néma esetek, a pozitív eset, a csak-doksi commit, és a frissesség-kapu.
- **2026-08-04** — **A 4.10 első éles futása két hibát dobott, mindkettő az én munkámban.**
  Rögzítve, mert mindkettő tanulságos.
  **(1) Az actionlint elbukott három `SC2129` shellcheck-találaton.** Helyben nem láttam őket: a
  shellcheck nem volt telepítve a gépemen, tehát az actionlint **némán kihagyta az összes `run:`
  blokkot** — pontosan az a forgatókönyv, amiért a workflow-ba külön stepet tettem, ami *állítja* a
  shellcheck jelenlétét. A sajátomon nem futott le ugyanez. Azóta telepítve, a hiba helyben
  reprodukálva, majd javítva. **A találatok valósak voltak:** három helyen egymás utáni
  `echo ... >> "$GITHUB_OUTPUT"` sorok, miközben a fájl **két sorral lejjebb** már a javasolt
  `{ ...; } >> file` formát használja — tehát következetlenség, nem stílus-vita. Mindhárom
  összevonva; a két érintett kimenet-blokkot leteszteltem (üres és nem üres `rule_files` ág),
  byte-pontosan ugyanazt írja, mint előtte. **A kaput szándékosan nem lágyítottam:** a shellcheck
  minden súlyossága buktat, a `style` is. Ez szigorúbb, mint a ruff (`F`+`E9`) és a PSScriptAnalyzer
  (`Error`+`ParseError`) precedens — de azok azért szűkültek, mert több ezer sosem lintelt sorra
  néztek, ahol a valódi defektek elvesztek volna; a workflow-bash ennek töredéke és minden szinten
  tiszta. A knob dokumentálva a step kommentjében, ha mégis zajossá válna.
  **(2) A `dependency_audit` „Error: Process completed with exit code 1"-gyel végzett**, pedig
  szándékosan csak tájékoztató. A `continue-on-error` a *workflow* elbukását akadályozza meg, a
  step hibakódját és a piros jelölést nem — vagyis egy tanácsadó ellenőrzés pontosan úgy nézett ki,
  mint egy elromlott. Egy piros X-et „ez csak információ"-ként olvasni nem olyasmi, amit bárkinek
  fejben kellene tartania. Átírva: a `continue-on-error` **kivéve**, helyette a step maga fordítja
  le a pip-audit kimeneti kódját — **1 = talált sebezhetőséget** → `::warning::` és `exit 0`;
  **bármi más nem-nulla** = a pip-audit le sem futott (hálózat, resolver, rossz fájl) → `::error::`
  és `exit 1`. Ez a különbség a lényeg: egy meg nem történt audit nem látszhat tiszta auditnak.
  Mindhárom ág leteszteltve hamis `pip-audit`-tal (0 / 1 / 2 kimeneti kód) — **de nem a CI
  shell-kapcsolóival, és emiatt a javítás így is elbukott élesben; lásd a következő bejegyzést.**
  **Tanulság a munkamenetre:** egy lint-eszközt nem elég bekötni — le kell futtatni ugyanazzal a
  kiegészítő eszközkészlettel, amivel a CI futtatja, különben csendben kevesebbet ellenőriz.
- **2026-08-04** — **A `dependency_audit` élesben újra elbukott, és a valódi ok egy osztállyal
  mélyebb volt: a GitHub `-e`-t ad a `shell: bash`-hoz.** A log árulta el:
  `shell: /usr/bin/bash --noprofile --norc -e -o pipefail`. A step scriptje `set -uo pipefail`-lel
  indul — ez **nem kapcsolja ki** a kívülről kapott `-e`-t —, tehát a `pip-audit` 1-es kilépésekor a
  step azonnal meghalt, még a `status=$?` sor *előtt*. Az összes utána következő logika (osztályozás,
  step summary, `::warning::`) sosem futott le. Az előző napi tesztem azért engedte át, mert
  `bash -c`-vel futtatta, `-e` nélkül — **ugyanaz a hibaosztály, mint a shellchecknél: a helyi
  ellenőrzés nem a CI környezetét reprodukálta.**
  **A javítás nem `set +e`,** hanem `if`-be zárt hívás: egy `if` feltételében szereplő parancs
  definíció szerint mentes a `-e` alól, tehát a forma **helyes a kapcsolótól függetlenül** — és nem
  kapcsolja ki a hibakezelést a script többi részére sem (egy elhasalt `mktemp` továbbra is megbuktat).
  **Ugyanez a latens hiba megvolt a tegnapi reconcile-stepben is**, csak eddig nem sült el, mert a
  `reconcile.py` mindig 0-val tért vissza. Ott is javítva. Ironikus: pont azért tettem bele az
  `exit "$rc"`-t, hogy egy el nem szállt takarítás látható legyen — a `-e` viszont a *diagnosztikát*
  vitte volna el, a step summaryt és a warningot. A repo meglévő `Evaluate Pass/Fail` stepje egyébként
  már ma is helyesen csinálta (explicit `set +e`); az én két új stepem volt a kivétel.
  **Mostantól minden ellenőrzés a valódi kapcsolókkal fut:** mind a három ág újratesztelve
  `bash --noprofile --norc -e -o pipefail`-lel (a találat-eset most helyesen zöld + warning, az
  eszközhiba piros), a reconcile-minta külön három kilépési kódra, és mind a **29** `shell: bash`
  step szintaxisa átnézve ugyanezekkel a kapcsolókkal.
