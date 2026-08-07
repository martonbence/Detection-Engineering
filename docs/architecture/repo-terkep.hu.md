# Repo-térkép (magyarul, döntéshez)

Ez a fájl **nem** referencia-dokumentáció — arra ott van a
[`scripts_reference.md`](scripts_reference.md), ami minden fájlt felsorol angolul, részletesen.
Ez itt egy **döntési segédlet**: mi mit csinál nagy vonalakban, milyen problémát old meg, és
megéri-e hosszú távon megtartani.

Készült: 2026-08-07.

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
| `.claude/agents/` | A 6 egyedi agent definíciója (`docs-maintainer`, `frontend-engineer`, `devops-engineer`, `security-scanner`, `ideation`, `detection-content-reviewer`, `github-ops`). | ⚪ |
| `.ruff_cache/`, `.pytest_cache/` | A linter és a tesztfuttató **automatikus gyorsítótárai**. `.gitignore`-ban vannak, tehát nincsenek a repóban. Bármikor törölheted, maguktól újra létrejönnek. | ⚪ |
| `__pycache__/` mappák | Ugyanez: a Python fordított bájtkód-gyorsítótára. Gitignorálva. | ⚪ |
| `pyproject.toml` | **Egyetlen dolgot csinál:** beállítja a `ruff`-ot (kódstílus-ellenőrző) és a `pytest`-et (tesztfuttató). A repo *nem* Python csomag, nincs telepítve. Azért van a gyökérben, mert a két eszköz ott keresi. | 🟢 |
| `rule_documentations/` | Ott van a lemezen, de **nincs a gitben** — maradék egy korábbi ötletből. Törölhető. | 🔴 |
| `.vscode/` | Szerkesztő-beállítások. | ⚪ |

---

## 1. A hurok — ez a projekt lényege

Ez a hat lépés csinál egy szabályból bizonyítékot. Ha ebből bármit kiveszel, a projekt elveszti
az értelmét.

| Mappa / fájl | Mit csinál | Sor | |
|---|---|---:|---|
| `scripts/validate/validate_sigma.py` + `.ps1` | Megnézi, hogy a Sigma YAML megfelel-e a sémának (`docs/schemas/sigma_schema.json`). A `.ps1` csak egy burkoló, ami egy folyamatban adja át a fájllistát. | 310 | 🟢 |
| `scripts/convert/sigma_to_spl.py` | Sigma YAML → Splunk SPL lekérdezés + `.meta.json` melléklet (ebben van, melyik Atomic teszt tartozik hozzá). | 450 | 🟢 |
| `scripts/deploy/deploy_spl_to_splunk.py` | Létrehozza vagy frissíti a Splunk saved search-öket. | 489 | 🟢 |
| `scripts/atomic/run_atomic.ps1` | **Végrehajtja a támadást**, aminek tüzelnie kell a szabályt. Ez a repo szíve. | 854 | 🟢 |
| `scripts/verify/wait_for_indexing.py` | Vár, amíg a Splunk beindexeli a támadás eseményeit (fix 1 perc alvás helyett). | 189 | 🟢 |
| `scripts/verify/check_saved_search_hits.py` | Megkérdezi a Splunkot, hány eseményt talált minden szabály. | 327 | 🟢 |
| `scripts/verify/pass_fail_eval.py` | A találatszámokból PASS / FAIL / NOT_VERIFIED ítéletet mond. | 368 | 🟢 |
| `scripts/lib/env.py` + `rule_naming.py` | 2 apró közös segédfüggvény: környezeti változók olvasása, és az egyetlen függvény, ami eldönti egy szabály Splunk-objektumnevét. | 109 | 🟢 |
| `config/backends.yml` | Melyik konverter-backendet használjuk, és melyik szabály milyen pipeline-t kap. | 53 | 🟢 |
| `docs/schemas/sigma_schema.json` | A séma, ami ellen a validáció fut. | 462 | 🟢 |
| `rules/sigma/` | **A termék.** 27 szabály. | — | 🟢 |
| `rules/splunk/` | A generált SPL. Nem kézzel írod, a pipeline commitolja vissza. | — | 🟢 |
| `outputs/results/` | Szabályonként egy `result.json`: mikor futott, mi lett az ítélet, melyik szabályverzió ellen. **Ez az auditálhatóság bizonyítéka.** | — | 🟢 |
| `outputs/reports/` | Aggregált adat a böngészőhöz: `stats.json`, MITRE technika-térkép, Navigator réteg, lefedettség-történet. | — | 🔵 |

---

## 2. A kirakat

| Fájl | Mit csinál | Sor | |
|---|---|---:|---|
| `scripts/docs/generate_stats.py` | Mindent összegyúr: `stats.json`, a README blokkja, és a szabályböngésző. | 1 425 | 🔵 |
| `scripts/docs/assets/page.js` | A böngésző működése (szűrés, keresés, Navigator nézet). | 2 862 | 🔵 |
| `scripts/docs/assets/page.css` | A kinézet. | 1 416 | 🔵 |
| `scripts/docs/assets/page.template.html` | A HTML váz. | 432 | 🔵 |
| `docs/index.html` | **A generált végeredmény.** Ezt látja, aki a GitHub Pages linket megnyitja. Ne ezt szerkeszd — a fenti négy fájlból jön. | 4 708 | 🔵 |

> **Fontos arány:** ez **6 135 sor** — a repo kódjának több mint a fele. Amikor azt érzed, hogy
> „nagyon sok felesleges funkció van", a legnagyobb egyetlen darab pont az, amire büszke vagy.
> A tényleges pipeline-kód ehhez képest ~5 300 sor.

---

## 3. Workflow-k — mi fut a GitHubon

### `ci_dev_workflow.yml` — 1 695 sor, 8 job 🟢

Ez a fő pipeline. Akkor indul, ha szabály (vagy a szabályt érintő script) változik bármelyik
ágon a `main` kivételével. Kézzel is indítható (`workflow_dispatch`), és ilyenkor választhatsz,
hogy minden szabályt futtasson vagy csak azokat, amiknek hiányzik/elavult a verifikációja.

| # | Job | Hol fut | Mit csinál | |
|---|---|---|---|---|
| 1 | **Prepare, Validate, Convert** | GitHub gépe (`ubuntu-latest`) | Kideríti mely szabályok változtak → validál séma ellen → ellenőrzi a MITRE tageket → SPL-re konvertál → visszacommitolja az SPL-t a `dev`-re → összecsomagolja a *pipeline bundle*-t a labor-gépeknek | 🟢 |
| 2 | **Deploy to Splunk** | Saját géped (`de-lab`) | Letölti a bundle-t, feltölti a saved search-öket a Splunkba | 🟢 |
| 3 | **Atomic Red Team Test** | Windows áldozat-VM | Lefuttatja a támadásokat, amiknek tüzelniük kell | 🟢 |
| 4 | **Atomic Red Team Test (DC)** | Windows tartományvezérlő | Ugyanez, de ami csak DC-n értelmes (pl. DCSync) | 🟢 |
| 5 | **Script Emulation Test** | Windows áldozat-VM | Szkript-alapú emuláció azokra, amikhez nincs Atomic teszt | 🟢 |
| 6 | **Splunk Verification** | Saját géped (`de-lab`) | Kiszámolja az időablakot → megvárja az indexelést → lekérdezi a találatokat → PASS/FAIL → **reconcile** → statisztika + README frissítés → commitolja az eredményeket | 🟢 |
| 7 | **Open Promotion PR** | GitHub gépe | Nyit egy PR-t `dev` → `main`, és „In review" állapotba teszi | 🟡 |
| 8 | **Deploy GitHub Pages** | GitHub gépe | Publikálja a `docs/index.html`-t | 🔵 |

### `ci_prod_workflow.yml` — 232 sor, 2 job 🟡

Akkor fut, ha valami bekerül a `main`-be.

| # | Job | Mit csinál | |
|---|---|---|---|
| 1 | **Lab Offline Notice** | Ha a `LAB_ONLINE` változó `false`, csak kiír egy üzenetet, hogy a prod nem frissült | 🟢 |
| 2 | **Deploy to Prod Splunk** | Újragenerálja az SPL-t a Sigma forrásból → **ellenőrzi, hogy nem tér-e el attól, amit a dev tesztelt** → telepíti a prod Splunk appba → riportot tölt fel | 🟡 |

> A „drift gate" (2. lépés közepe) tényleg jó ötlet: azt garantálja, hogy amit prodba raksz, bájtra
> az, amit a dev leteszteltek. Viszont az egész prod/dev kettőzés **ugyanazon a Splunk szerveren**
> zajlik, csak másik appban. Egyszemélyes laborban ez inkább ceremónia — cserébe viszont ez a
> „profi, auditálható" sztori része interjún.

### `ci_code_checks.yml` — 559 sor, 6 job

Ez a **pipeline saját CI-ja** — nem szabályokat ellenőriz, hanem a pipeline kódját. Azért van
külön, mert a fő workflow csak akkor csinál bármit, ha *szabály* változik; egy
`generate_stats.py` módosítást semmi nem ellenőrizne.

| # | Job | Mit csinál | |
|---|---|---|---|
| 1 | **Static analysis and tests** | `ruff` (kódstílus) + `pytest` (a `tests/` mappa) | 🟢 |
| 2 | **PowerShell analysis** | `PSScriptAnalyzer` a 2 darab `.ps1` fájlra | 🟡 |
| 3 | **Workflow analysis** | `actionlint` + `shellcheck` a workflow YAML-ekre | 🟢 |
| 4 | **Dependency audit** | `pip-audit` — ismert sérülékenységek a 6 rögzített csomagban | 🟡 |
| 5 | **Regenerate Console** | Újragenerálja a `docs/index.html`-t és commitolja, ha változott | 🔵 |
| 6 | **Publish Console** | Publikálja | 🔵 |

### Kiegészítő fájlok a `.github/`-ban

| Fájl | Mit csinál | |
|---|---|---|
| `requirements.txt` | 6 rögzített verziójú csomag (pyyaml, jsonschema, sigma-cli, pySigma, splunk backend, requests). **Azért rögzített**, hogy a dev és a prod ugyanazzal a konverterrel dolgozzon — enélkül a drift gate értelmetlen lenne. | 🟢 |
| `requirements-dev.txt` | `pytest` + `ruff`, csak a code-checks workflow-nak | 🟢 |
| `actionlint.yaml` | Az actionlint beállítása (tudja, mik a saját runner-címkéid) | 🟢 |
| `PSScriptAnalyzerSettings.psd1` | A PowerShell-elemző beállítása | 🟡 |
| `dependabot.yml` | Hetente PR-t nyit a Python csomagok és a GitHub Actionök frissítésére, a `dev` ágra. **Ez a pinek ellensúlya:** a `requirements.txt` azért rögzít verziót, hogy a dev és a prod ugyanazzal a konverterrel fusson — de pin frissítési mechanizmus nélkül azt jelenti, hogy örökre ráfagysz egy verzióra. A nyolc action SHA-ra van pinelve, egy SHA pedig sosem mozdul magától. | 🟢 |

---

## 4. `tests/` — mik ezek a .py fájlok

**Nem** a detekciós szabályokat tesztelik. A **pipeline saját kódját** tesztelik: ha átírsz egy
scriptet és elrontod, ezek pirosra váltanak. 3 805 sor, nagyjából scriptenként egy fájl.

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
| **`scripts/state/reconcile.py`** (560) + `prune_orphans.py` (167) + tesztjeik (597) | Ha a Splunkban van olyan saved search, ami már nincs a repóban (vagy fordítva), észreveszi és rendet rak | 27 szabálynál, ahol **egyetlen dolog telepít** (a pipeline), ez a driftelés gyakorlatilag nem tud létrejönni — csak kézi Splunk-babrálásból. Ez egy 500 szabályos, többfős csapat problémája. | **~1 320** |
| **`scripts/validate/check_test_routing.py`** (361) + tesztje (379) | Szól, ha egy szabály olyan teszt-futtatót kér, amihez nincs CI job | Valós, de pici probléma: rossz runner esetén a szabály egyszerűen `NOT_VERIFIED` lesz, ami amúgy is látszik. Csak azért létezik, mert **3 külön támadó job** van. | **~740** |
| **`scripts/convert/backend_config.py`** (192) + tesztje (363) | Konfigurációból dönti el, melyik konverter-backendet használd | Egyetlen backendet használsz, és nem fogsz másikat. Ez a 3.7-es register tétel eredménye: kivitt egy döntést konfigba, ami sosem változik. | **~555** |
| **`open_promotion_pr` job** + a prod/dev kettőzés | Külön „review" lépés a prodba kerülés előtt | Ugyanaz a Splunk, másik app, egy felhasználó. **De:** ez az auditálhatósági sztori része, itt kevésbé vagyok biztos. | ~250 |
| **`rule_documentations/`** | — | Nincs is a gitben. Maradék. | 0 |

**Összesen kb. 2 900 sor**, amit el lehetne engedni. Ez a repo kódjának nagyjából a negyede.

---

## 6. Javaslat

**Most ne törölj semmit a kódból.**

Nem azért, mert a fenti négy tétel jó. Hanem mert a `scripts/state/` kivágása nem 5 perc: hozzá
kell nyúlni a workflow-hoz, ki kell venni a teszteket, frissíteni a dokumentációt, átfuttatni a
pipeline-t. Az egy nap **pipeline-munka** — pontosan az a tevékenység, ami az elmúlt 15 napot
elvitte. A törlés ugyanúgy elhalasztja a szabályírást, mint a fejlesztés, csak közben az az
érzésed, hogy takarítasz.

Amit *most* megéri:

1. `rule_documentations/` törlése — nincs is a gitben, ingyen van.
2. Ez a fájl legyen meg, hogy legyen mihez visszanyúlni.
3. **Menj, írj szabályokat.** Egy hónap múlva pontosan tudni fogod, melyik scripthez nem nyúltál
   hozzá soha — *az* lesz a törlési lista, nem az, amit ma kitalálunk. A `scripts/state/`
   valószínűleg rajta lesz. De akkor már bizonyítékod is lesz rá, nem csak sejtésed.

### Számok, amiket érdemes fejben tartani

| | |
|---|---|
| Sigma szabály | 27 (mind **2026-07-23-án** készült) |
| Detekciós logika változása azóta | 0 sor |
| Python a `scripts/`-ben | 5 721 sor |
| Teszt | 3 805 sor |
| Workflow YAML | 2 486 sor |
| Gépezet / szabály | **~445 sor** |
