# Repo-térkép (magyarul, döntéshez)

Ez a fájl **nem** referencia-dokumentáció — arra ott van a
[`scripts_reference.md`](scripts_reference.md), ami minden fájlt felsorol angolul, részletesen.
Ez itt egy **döntési segédlet**: mi mit csinál nagy vonalakban, milyen problémát old meg, és
megéri-e hosszú távon megtartani.

Készült: 2026-08-07. Struktúra-számok és a workflow-lista frissítve: 2026-08-29.

## Jelölések

| Jel | Jelentés |
|---|---|
| 🟢 | **Mag.** A szabály → bizonyíték hurok része. Ne nyúlj hozzá. |
| 🔵 | **Kirakat.** Ez az, amit interjún megmutatsz. |
| 🟡 | **Működik, de túlméretezett** a projekt jelenlegi léptékéhez. |
| 🔴 | **Hosszú távon is kérdéses.** Törlési jelölt. |
| ⚪ | **Nem a tiéd** vagy nincs is a repóban. Ne foglalkozz vele. |

---

## 0. Amit nem értettél — és amiért nem is kell aggódnod

| Amit látsz | Mi ez valójában | |
|---|---|---|
| `.git/hooks`, `.git/worktrees` | A **git saját belső** könyvtárai. Minden git repóban ott vannak, a git hozza létre. Soha ne nyúlj hozzájuk. | ⚪ |
| `.claude/hooks/` | 2 shell script, amit a Claude Code használ (dokumentáció-elcsúszás ellenőrzés). Nem a pipeline része. | ⚪ |
| `.claude/worktrees/` | Üres. A Claude Code agentek hozzák létre ideiglenesen, ha izolált másolatban dolgoznak. | ⚪ |
| `.claude/agents/` | A 10 egyedi specialista-agent definíciója (Yuki, Bjorn, Jamal, Chloe, Sienna, Kai, Yara, Masha, Priya, Kwame) + egy soha nem hívott referencia-fájl (Gaz). A tényleges delegálási szerződést a `CLAUDE.md` és a `TEAM.md` írja le. | ⚪ |
| `.ruff_cache/`, `.pytest_cache/` | A linter és a tesztfuttató **automatikus gyorsítótárai**. `.gitignore`-ban vannak, tehát nincsenek a repóban. Bármikor törölheted, maguktól újra létrejönnek. | ⚪ |
| `__pycache__/` mappák | Ugyanez: a Python fordított bájtkód-gyorsítótára. Gitignorálva. | ⚪ |
| `pyproject.toml` | **Egyetlen dolgot csinál:** beállítja a `ruff`-ot (kódstílus-ellenőrző) és a `pytest`-et (tesztfuttató). A repo *nem* Python csomag, nincs telepítve. Azért van a gyökérben, mert a két eszköz ott keresi. | 🟢 |
| `rule_documentations/` | **Már nincs a repóban** (se a gitben, se a lemezen). Régebbi jegyzetek még hivatkozzák egy per-szabály dokumentációs ötlet maradványaként — nincs. | 🔴 |
| `.vscode/` | Szerkesztő-beállítások. | ⚪ |

---

## 1. A hurok — ez a projekt lényege

Ez a hat lépés csinál egy szabályból bizonyítékot. Ha ebből bármit kiveszel, a projekt elveszti
az értelmét.

| Mappa / fájl | Mit csinál | Sor | |
|---|---|---:|---|
| `scripts/validate/validate_sigma.py` + `.ps1` | Megnézi, hogy a Sigma YAML megfelel-e a sémának (`docs/schemas/sigma_schema.json`). A `.ps1` csak egy burkoló, ami egy folyamatban adja át a fájllistát. | 310 | 🟢 |
| `scripts/convert/sigma_to_spl.py` | Sigma YAML → Splunk SPL lekérdezés + `.meta.json` melléklet (ebben van, melyik Atomic teszt tartozik hozzá). Ha `custom.splunk.raw_query` be van állítva, azt írja ki szó szerint konverzió helyett. | 564 | 🟢 |
| `scripts/deploy/deploy_spl_to_splunk.py` | Létrehozza vagy frissíti a Splunk saved search-öket. | 609 | 🟢 |
| `scripts/atomic/run_atomic.ps1` | **Végrehajtja a támadást**, aminek tüzelnie kell a szabályt. Ez a repo szíve. | 953 | 🟢 |
| `scripts/verify/wait_for_indexing.py` | Vár, amíg a Splunk beindexeli a támadás eseményeit (fix 1 perc alvás helyett). | 190 | 🟢 |
| `scripts/verify/check_saved_search_hits.py` | Megkérdezi a Splunkot, hány eseményt talált minden szabály. | 369 | 🟢 |
| `scripts/verify/pass_fail_eval.py` | A találatszámokból PASS / FAIL / NOT_VERIFIED ítéletet mond. | 482 | 🟢 |
| `scripts/lib/env.py` + `rule_naming.py` | 2 apró közös segédfüggvény: környezeti változók olvasása, és az egyetlen függvény, ami eldönti egy szabály Splunk-objektumnevét. | 109 | 🟢 |
| `config/backends.yml` | Melyik konverter-backendet használjuk, és melyik szabály milyen pipeline-t kap. | 53 | 🟢 |
| `docs/schemas/sigma_schema.json` | A séma, ami ellen a validáció fut. | 468 | 🟢 |
| `rules/sigma/` | **A termék.** 28 szabály. | — | 🟢 |
| `rules/splunk/` | A generált SPL. Nem kézzel írod, a pipeline commitolja vissza. | — | 🟢 |
| `outputs/results/` | Szabályonként egy `result.json`: mikor futott, mi lett az ítélet, melyik szabályverzió ellen. **Ez az auditálhatóság bizonyítéka.** | — | 🟢 |
| `outputs/reports/` | Aggregált adat a böngészőhöz: `stats.json`, MITRE technika-térkép, Navigator réteg, lefedettség-történet. | — | 🔵 |

---

## 2. A kirakat

| Fájl | Mit csinál | Sor | |
|---|---|---:|---|
| `scripts/docs/generate_stats.py` | Mindent összegyúr: `stats.json`, a README blokkja, és a szabályböngésző. | 2 281 | 🔵 |
| `scripts/docs/assets/page.js` | A böngésző működése (szűrés, keresés, Navigator nézet). | 2 998 | 🔵 |
| `scripts/docs/assets/page.css` | A kinézet. | 4 195 | 🔵 |
| `scripts/docs/assets/page.template.html` | A HTML váz. | 633 | 🔵 |
| `docs/index.html` | **A generált végeredmény.** Ezt látja, aki a GitHub Pages linket megnyitja. Ne ezt szerkeszd — a fenti négy fájlból jön. | 7 835 | 🔵 |

> **Fontos arány:** a négy forrásfájl együtt **~10 100 sor** — nagyságrendben a repo kódjának
> harmada-fele. Amikor azt érzed, hogy „nagyon sok felesleges funkció van", a legnagyobb
> egyetlen darab pont az, amire büszke vagy.

---

## 3. Workflow-k — mi fut a GitHubon

### `ci_dev_workflow.yml` — 2 623 sor, 11 job 🟢

Ez a fő pipeline. Akkor indul, ha szabály (vagy a szabályt érintő script) változik bármelyik
ágon a `main` kivételével. Kézzel is indítható (`workflow_dispatch`), és ilyenkor választhatsz,
hogy minden szabályt futtasson vagy csak azokat, amiknek hiányzik/elavult a verifikációja.

| # | Job (`name:`) | Hol fut (`runs-on:`) | Mit csinál | |
|---|---|---|---|---|
| 1 | **Prepare, Validate, Convert** | `ubuntu-latest` | Kideríti mely szabályok változtak → validál séma ellen → ellenőrzi a MITRE tageket → SPL-re konvertál → visszacommitolja az SPL-t a `dev`-re → **Sigstore build-provenance attesztációt készít minden `.spl`-re** (`actions/attest-build-provenance`) + `.bundle-provenance.json` mutatót → összecsomagolja a *pipeline bundle*-t a labor-gépeknek | 🟢 |
| 2 | **Deploy to Splunk** | `[self-hosted, linux, de-lab]` | A Splunk-oldali Linux runner: letölti a bundle-t, feltölti a saved search-öket a dev Splunk appba | 🟢 |
| 3 | **Atomic Red Team Test** | `[self-hosted, X64, Windows, victim, atomic, windows-victim]` | A Windows áldozat-host: lefuttatja az Atomic Red Team támadásokat, amiknek tüzelniük kell | 🟢 |
| 4 | **Atomic Red Team Test (DC)** | `[self-hosted, X64, Windows, dc, windows-dc]` | A tartományvezérlő-host: ugyanez, de ami csak DC-n értelmes (pl. DCSync) | 🟢 |
| 5 | **Script Emulation Test** | `[self-hosted, X64, Windows, victim, windows-victim]` | Az áldozat-host: szkript-alapú emuláció azokra, amikhez nincs Atomic teszt | 🟢 |
| 6 | **Splunk Verification** | `[self-hosted, linux, de-lab]` | A Splunk-oldali Linux runner: kiszámolja az időablakot → megvárja az indexelést → lekérdezi a találatokat → PASS/FAIL → **reconcile** a dev app ellen → commitolja az eredményeket (`outputs/results/`) | 🟢 |
| 7 | **Update Dashboard & Docs** | `ubuntu-latest` | Újragenerálja a `stats.json`-t, a szabályböngészőt és a README statisztika-blokkját, commitolja ha változott. `LAB_ONLINE`-tól és a verify eredményétől szándékosan függetlenül fut (saját `always()`), csak azt várja meg, hogy SPL készüljön | 🔵 |
| 8 | **Persist Verification Results (fallback)** | `ubuntu-latest` | Ha az előző job nem tudta commitolni az eredményeket, ez próbálja meg újra | 🟢 |
| 9 | **Open Promotion PR** | `ubuntu-latest` | Nyit egy PR-t `dev` → `main`, és „In review" állapotba teszi. Az `if:` explicit `always()`-t tartalmaz — implicit `success()` mellett minden kihagyott upstream job kihagyná ezt is | 🟡 |
| 10 | **Notify Pipeline Status (Slack)** | `ubuntu-latest` | Slack üzenet a `SLACK_WEBHOOK_URL`-re a futás végeredményével, a friss `stats.json` alapján | 🟢 |
| 11 | **Deploy GitHub Pages** | `ubuntu-latest` | Publikálja a `docs/index.html`-t. `needs: [update_dashboard]` — az a job regenerálja a lapot | 🔵 |

### `ci_prod_workflow.yml` — 563 sor, 4 job 🟡

Akkor fut, ha valami bekerül a `main`-be.

| # | Job (`name:`) | Hol fut (`runs-on:`) | Mit csinál | |
|---|---|---|---|---|
| 1 | **Lab Offline Notice** | `ubuntu-latest` | Ha a `LAB_ONLINE` változó `false`, csak kiír egy üzenetet, hogy a prod nem frissült | 🟢 |
| 2 | **Deploy to Prod Splunk** | `[self-hosted, linux, de-lab]` | Letölti a dev bundle attesztált `.meta.json` mellékleteit → **`gh attestation verify`-jal ellenőrzi minden telepítendő `.spl` build-provenance-attesztációját** (signer-pinned a `ci_dev_workflow.yml`-re) → csak akkor telepíti a prod Splunk appba → riportot tölt fel | 🟡 |
| 3 | **Update Dashboard (Prod)** | `ubuntu-latest` | Frissíti a deployment-leltárt a prod riportból, regenerálja a dashboardot, commitolja | 🔵 |
| 4 | **Deploy GitHub Pages (Prod)** | `ubuntu-latest` | Publikálja a konzolt a prod deploy után (a `github-pages` environmentbe) | 🔵 |

> A régi „drift gate" (`git diff --exit-code -- rules/splunk`) **már nincs** a prod CI-ban.
> Helyette egy **Sigstore / `gh attestation verify` provenance-kapu** áll (`ci_prod_workflow.yml:237`):
> minden prodba települő `.spl`-nek érvényes, egyező build-provenance-attesztációval kell rendelkeznie,
> amit a `ci_dev_workflow.yml` `actions/attest-build-provenance` lépése készített — vagyis nem
> „bájtra egyezik-e a commitolt SPL", hanem „bizonyíthatóan a dev workflow állította-e elő".
> Egy hand-editelt `.spl`, egy dev-en kívül futtatott konverter vagy egy soha újra nem attesztált
> szabály itt megállítja a prod deployt. A prod/dev kettőzés továbbra is **ugyanazon a Splunk
> szerveren** zajlik, csak másik appban — egyszemélyes laborban ez részben ceremónia, cserébe
> viszont ez a „profi, auditálható" sztori része.

### `ci_prod_audit.yml` — 356 sor, 2 job 🟡

Csak kézzel indítható (`workflow_dispatch`, nincs `schedule:` — a de-lab runner és a prod Splunk
általában offline). A register 4.7-es tétele: **semmi sem figyeli a prod Splunkot két deploy
között.** 2026-08-07-én kézzel töröltek egy szabályt a prod appból, és a pipeline sosem vette
észre. Ez a workflow **nem telepít és nem módosít semmit** — read-only módban futtatja a
reconcile-t a prod app ellen, kimondja mit talált, és a dashboard számára olvasható helyre írja.

| # | Job (`name:`) | Hol fut (`runs-on:`) | Mit csinál | |
|---|---|---|---|---|
| 1 | **Audit Prod Splunk** | `[self-hosted, linux, de-lab]` | A Splunk-oldali Linux runner: reconcile `--dry-run` a prod app és a `main` között → feljegyzi, miből lett utoljára telepítve → jelez, ha a prod elsodródott → riportot tölt fel | 🟡 |
| 2 | **Record Prod State on dev** | `ubuntu-latest` | Letölti a reconcile- és a deploy-riportot, frissíti a `dev`-en a deployment-leltárt | 🔵 |

Ugyanabban a `detection-pipeline-prod-*` concurrency-csoportban fut, mint a prod deploy, tehát
audit sosem olvashatja az appot félig-alkalmazott deploy közben.

### `ci_code_checks.yml` — 808 sor, 6 job

Ez a **pipeline saját CI-ja** — nem szabályokat ellenőriz, hanem a pipeline kódját. Azért van
külön, mert a fő workflow csak akkor csinál bármit, ha *szabály* változik; egy
`generate_stats.py` módosítást semmi nem ellenőrizne.

| # | Job | Mit csinál | |
|---|---|---|---|
| 1 | **Static analysis and tests** | `ruff` (kódstílus) + `pytest` (a `tests/` mappa) | 🟢 |
| 2 | **PowerShell analysis** | `PSScriptAnalyzer` a 2 darab `.ps1` fájlra | 🟡 |
| 3 | **Workflow analysis** | `actionlint` + `shellcheck` a workflow YAML-ekre | 🟢 |
| 4 | **Dependency audit** | `pip-audit` — ismert sérülékenységek a 7 rögzített csomagban | 🟡 |
| 5 | **Regenerate Console** | Újragenerálja a `docs/index.html`-t és commitolja, ha változott | 🔵 |
| 6 | **Publish Console** | Publikálja | 🔵 |

### Kiegészítő fájlok a `.github/`-ban

| Fájl | Mit csinál | |
|---|---|---|
| `.github/requirements.txt` | 7 rögzített verziójú csomag (pyyaml, jsonschema, sigma-cli, pySigma, pysigma-backend-splunk, requests, diskcache). **Azért rögzített**, hogy a dev Sigma→SPL konverziója önmagában reprodukálható legyen — a commitolt bájtok kerülnek atomic-tesztre és (attesztáció után) prodba. A prod deploy már **nem** telepíti ezt (nincs több újrakonverzió a prod oldalon). | 🟢 |
| `.github/requirements-deploy.txt` | Csak `requests` — a prod deploy lépés futtatókörnyezete. A prod nem konvertál, csak az attesztált `.spl`-t telepíti, tehát a teljes konverter-toolchain fölösleges lenne neki. | 🟢 |
| `.github/requirements-dev.txt` | `pytest` + `ruff` + `tzdata`, csak a code-checks workflow-nak | 🟢 |
| `actionlint.yaml` | Az actionlint beállítása (tudja, mik a saját runner-címkéid) | 🟢 |
| `PSScriptAnalyzerSettings.psd1` | A PowerShell-elemző beállítása | 🟡 |
| `dependabot.yml` | Hetente PR-t nyit a Python csomagok és a GitHub Actionök frissítésére, a `dev` ágra. **Ez a pinek ellensúlya:** a `requirements.txt` a dev konverziójának reprodukálhatósága miatt rögzít verziót — de pin frissítési mechanizmus nélkül ez azt jelentené, hogy örökre ráfagysz egy verzióra. Az action-ök SHA-ra vannak pinelve, egy SHA pedig sosem mozdul magától. | 🟢 |

---

## 4. `tests/` — mik ezek a .py fájlok

**Nem** a detekciós szabályokat tesztelik. A **pipeline saját kódját** tesztelik: ha átírsz egy
scriptet és elrontod, ezek pirosra váltanak. Összesen 9 779 sor, nagyjából scriptenként egy fájl.

> Az alábbi tábla **reprezentatív válogatás**, nem teljes lista — a suite mostanra ~40 fájl.
> A teljes, naprakész per-fájl leírás a [`scripts_reference.md`](scripts_reference.md)-ben van.

| Fájl | Mit ellenőriz | Sor | |
|---|---|---:|---|
| `conftest.py` | Közös pytest-beállítás: a `scripts/` mappát elérhetővé teszi, és megakadályozza, hogy a tesztek a valódi GitHub-runner fájlokba írjanak | 59 | 🟢 |
| `test_sigma_to_spl.py` | A konverter | 76 | 🟢 |
| `test_backend_config.py` | A backend-konfiguráció betöltése | 363 | 🟡 |
| `test_check_mitre_tags.py` | A MITRE tag-ellenőrző | 496 | 🟡 |
| `test_check_test_routing.py` | A teszt-útvonal ellenőrző | 379 | 🔴 |
| `test_deploy_upsert.py` | A telepítő: létrehoz vagy frissít? | 179 | 🟢 |
| `test_deploy_deprecated.py` | Elavult szabályok kezelése telepítéskor | 90 | 🟢 |
| `test_deploy_report.py` | A prod-telepítési riport | 233 | 🟡 |
| `test_tls_verification.py` | Hogy a TLS-ellenőrzést ne lehessen véletlenül kikapcsolni | 183 | 🟢 |
| `test_lib_env.py` | A közös env-segédfüggvények | 142 | 🟢 |
| `test_wait_for_indexing.py` | Az indexelésre várás | 196 | 🟢 |
| `test_check_saved_search_hits.py` | A találatlekérdezés | 149 | 🟢 |
| `test_pass_fail_eval.py` | A PASS/FAIL ítélet | 60 | 🟢 |
| `test_pass_fail_gate.py` | Hogy a FAIL tényleg megbuktassa a futást | 207 | 🟢 |
| `test_reconcile.py` | Az állapot-összehangolás | 444 | 🔴 |
| `test_prune_orphans.py` | Az árva artefaktumok takarítása | 153 | 🔴 |
| `test_select_unverified.py` | „Melyik szabálynak kell futás?" | 241 | 🟡 |
| `test_resolve_rule_selection.py` | Kézi futásnál a szabályválasztás | 155 | 🟡 |

---

## 5. Amit hosszú távon sem tartok indokoltnak

| Mi | Milyen problémát old meg | Miért kérdéses | Sor |
|---|---|---|---:|
| **`scripts/state/reconcile.py`** (640) + `prune_orphans.py` (170) + tesztjeik (712) | Ha a Splunkban van olyan saved search, ami már nincs a repóban (vagy fordítva), észreveszi és rendet rak | 28 szabálynál, ahol **egyetlen dolog telepít** (a pipeline), ez a driftelés gyakorlatilag nem tud létrejönni — csak kézi Splunk-babrálásból. Ez egy 500 szabályos, többfős csapat problémája. | **~1 520** |
| **`scripts/validate/check_test_routing.py`** (369) + tesztje (379) | Szól, ha egy szabály olyan teszt-futtatót kér, amihez nincs CI job | Valós, de pici probléma: rossz runner esetén a szabály egyszerűen `NOT_VERIFIED` lesz, ami amúgy is látszik. Csak azért létezik, mert **3 külön támadó job** van. | **~750** |
| **`scripts/convert/backend_config.py`** (192) + tesztje (363) | Konfigurációból dönti el, melyik konverter-backendet használd | Egyetlen backendet használsz, és nem fogsz másikat. Ez a 3.7-es register tétel eredménye: kivitt egy döntést konfigba, ami sosem változik. | **~555** |
| **`open_promotion_pr` job** + a prod/dev kettőzés | Külön „review" lépés a prodba kerülés előtt | Ugyanaz a Splunk, másik app, egy felhasználó. **De:** ez az auditálhatósági sztori része, itt kevésbé vagyok biztos. | ~250 |
| **`rule_documentations/`** | — | Már nincs a repóban. Maradék. | 0 |

**Összesen kb. 3 100 sor**, amit el lehetne engedni — a repo (mostanra jóval nagyobb) kódjának
nagyjából a tizede.

---

## 6. Javaslat

**Most ne törölj semmit a kódból.**

Nem azért, mert a fenti négy tétel jó. Hanem mert a `scripts/state/` kivágása nem 5 perc: hozzá
kell nyúlni a workflow-hoz, ki kell venni a teszteket, frissíteni a dokumentációt, átfuttatni a
pipeline-t. Az egy nap **pipeline-munka** — pontosan az a tevékenység, ami az elmúlt 15 napot
elvitte. A törlés ugyanúgy elhalasztja a szabályírást, mint a fejlesztés, csak közben az az
érzésed, hogy takarítasz.

Amit *most* megéri:

1. ~~`rule_documentations/` törlése~~ — már megtörtént, a könyvtár nincs a repóban.
2. Ez a fájl legyen meg, hogy legyen mihez visszanyúlni.
3. **Menj, írj szabályokat.** Egy hónap múlva pontosan tudni fogod, melyik scripthez nem nyúltál
   hozzá soha — *az* lesz a törlési lista, nem az, amit ma kitalálunk. A `scripts/state/`
   valószínűleg rajta lesz. De akkor már bizonyítékod is lesz rá, nem csak sejtésed.

### Számok, amiket érdemes fejben tartani

| | |
|---|---|
| Sigma szabály | 28 (2026 áprilistól augusztusig keletkeztek) |
| `version:` mező | logikai változáskor automatikusan bumpol (`.githooks/pre-commit`) |
| Python a `scripts/`-ben | 12 228 sor |
| Teszt | 9 779 sor |
| Workflow YAML | 4 350 sor (4 fájl) |
| Gépezet / szabály | **~940 sor** |
