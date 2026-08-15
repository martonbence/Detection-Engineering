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

Jelenlegi: **6,5 / 10** (kiindulás). Mai állás: **8,92 → 8,9 / 10**, kész súly **89,5 / 92,5**
(52 tétel az 54-ből) — 2026-08-15-én a **4.1** is elutasítással zárult (nincs háttérforgalom a
labor Splunkban, csak attack-teszt idején van adat — egy "csendes ablak" mérés értelmezhetetlen
lenne, lásd a Napló végét). Korábban: (51 tétel az 54-ből) — a **4.4** elutasítással zárult (nincs
Splunk ES a labor-ban, a throttling/drilldown fele sem indokolt a jelenlegi méretben). Még korábban:
(50 tétel az 54-ből) — 2026-08-15-én a **3.5** zárult le (a séma/fegyelem-fele: explicit `version:`
mező mind a 27 szabályban + `scripts/validate/check_version_bump.py` hard gate a bumpra a
`prepare_validate_convert` jobban; a duplikáció-fele már 2026-08-11-én lezárult, lásd a Napló
mindkét bejegyzését). 2026-08-12-én a **3.6** zárult le (a `scripts/lib/` maradék fele: közös
`build_session()` az öt Splunk-hívó scriptben, közös `read_meta_sidecar()` a három Python-olvasóban,
plusz a szintén ide tartozó `search/jobs` URL-ek átállítva a meglévő `namespace_url()`-re). 2026-08-11-én
öt tétel zárult: **4.2** (SPL szintaxis-validáció deploy
előtt, `search/v2/parser`), **4.5** (scaffolder + ütközésvédelem, a
Makefile és az atomic-lookup a felhasználó döntése alapján nem kell a repóba), **3.8**
(alkönyvtár-bontás elutasítva, az ID-kiosztás fele a 4.5 alatt megoldva), **2.22** (generátor-regex
a séma technika-mintájához igazítva) és **4.9** (érdemi promotion PR body, per-szabály tábla).
2026-08-10-én a
**4.11** (elévülés-riportálás, nem kapu) zárult le. A számláló akkor
el volt csúszva: a `register.html` DOM-ja csak 40/70,0-t mutatott, mert a **3.9** és a **4.7**
`[x]`-e a `remediation-plan.md`-ben (az egyetlen igazság-forrás) sosem került át a publikált oldal
checkbox-jaira — ez a 4.11 `checked`-jével együtt javítva, a két fájl azóta egyezik. 2026-08-09-én
a **3.2** (artifact-promóció, digest-alapú build-provenance) zárult le, élesben bizonyítva. Minden
tétel elvégzése után: **9,0 / 10**.
A register meterének súlyozása: kritikus ×3, architektúra ×2, feature ×1,5, kisebb ×1.
A teljes súly ma **92,5** = 12×3 + 22×1 + 9×2 + 11×1,5; a korábban itt szereplő **88** a 2.22
felvétele előtti állapot volt, és a szöveg nem követte.
Projektált pontszám = `6,5 + 2,5 × (kész súly / 92,5)`.
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

A **3.9** 2026-08-08-án lezárult, és a hipotézis-tesztelés eredménye nem sima „bejött": a `nobody`
névtér kell, de a `set_acl` nem eshet ki, csak a payloadja javul (`owner` = az autentikáló fiók).
A különbséget egyetlen mérés adta meg — a jogosultságok a `nobody` alatt az app `default.meta`-jából
öröklődnek —, és e nélkül a „kézenfekvő" fix csendben tágította volna az írásjogot. **Prodban is
igazolva ugyanaznap:** egy dispatchelt prod futás mind a 27 szabályt frissítette, utána nulla
árnyék és nulla 409 — tiszta kiindulásból, tehát a régi kóddal 27 árnyék keletkezett volna.

A következő kör újra szabadon választható. Az itt korábban felsorolt jelöltek egy része azóta
elkészült — a **2.2** és a **4.10** is kész, a bekezdés csak nem követte —, tehát a mai nyitott
halmaz 14 tétel: **2.22**, **3.2**, **3.5**, **3.6**, **3.8**, **4.1**, **4.2**, **4.4**–**4.9**,
**4.11**.

**A legerősebb jelölt a 4.7** (deployment inventory), mert kétszer bizonyította magát méréssel,
nem érveléssel. 2026-08-07: egy prodból kézzel törölt szabályról semmi nem szólt — sem a repo, sem
a reconcile (csak a dev appot nézi), sem a dashboard. 2026-08-08: a 3.9 javítása mergelődött
`main`-be, és **nem ért ki prodba**, mert a prod workflow `paths:` szűrője csak `rules/sigma/**`-ra
tüzel; ezt sem jelezte semmi, egy kézi `workflow_dispatch` kellett hozzá. A telepítési lánc
egyirányú: ami a végén történik (vagy nem történik), arról a rendszer elején semmi nem tud.
A **3.3** kimenete és a **2.4** deploy-riportja már megvan hozzá alapanyagnak.

Két másik, más jellegű jelölt: a **4.11** hitelességi rés (egy lejárt vagy felülírt verdiktű
szabály soha nem blokkolja a promóciót, ma 15 ilyen ül prodban) — ez ugyanabba a családba tartozik,
mint az 1.2, tehát a register fő témájába; és a **3.2** artifact-promóció, ami architektúra-lépés,
és a mellékhatásaként az 1.3 drift-gate-je törölhetővé válik.

**2026-08-09-én a 3.2 lezárult** (lásd a Napló végét) — pontosan a fenti melléktermékkel: az 1.3
drift-gate-je (a prod-oldali újrakonvertálás + diff) törölve, digest-alapú build-provenance
ellenőrzés váltotta. A mai nyitott halmaz ezzel 13 tételre csökkent: **2.22**, **3.5**, **3.6**,
**3.8**, **4.1**, **4.2**, **4.4**–**4.9**, **4.11**.

---

## 1 · Kritikus hibák (12) — a repo jelenlegi állapotán bizonyítva

- [x] **1.1** 13 szabály soha nem kerül ki prodba (27 sigma / 14 spl, `main`-en is) · `ci_prod_workflow.yml:76` · **lezárva 2026-07-30: nem kódhiba.** A 13 szabályra a teljes dev workflow még nem futott le, ezért nincs committolt `.spl`-jük; a `git ls-files`-alapú prod deploy pontosan a pipeline-on átment halmazt telepíti. Amint végigmennek a dev futáson, a prod magától kiviszi őket. A „semmi nem szól róla" rész a **3.3** + **4.7** alá kerül
- [x] **1.2** A PASS verdiktek elévülnek, a dashboard friss igazságként mutatja (12 → 15 elévült) · `generate_stats.py` · **kész 2026-07-30:** a `pass_rate_pct` már csak a friss verdiktekből számol (96% → **92%**, 11/12), mellé `verification_current_pct` (**44%**, 12/27) és `confirmed_working_pct` (41%); `Outdated` szegmens a Verification doughnutban, `n of m current` alsor az overlayben, kontúros verdikt-badge a táblában, Legend-bejegyzések. A `pass_fail_eval.py` szándékosan érintetlen — az elévülés render-időben származtatott
- [x] **1.3** A prod nem azt deployolja, amit jóváhagytak (re-konverzió + pin nélküli deps) · `ci_prod_workflow.yml:42-60,40`, `ci_dev_workflow.yml:154` · **kész 2026-08-03:** pinelt `.github/requirements.txt` (a `pySigma` külön is, mert ő szerializál) mindkét workflow-nak, drift-gate a re-konverzió és a deploy közé, dev pip-cache kulcs a `requirements.txt`-re állítva, a `pipeline_overview.md` hamis „byte-identical" állítása javítva. A **3.2** (artifact-promóció) a gyökér — az teszi majd feleslegessé a gate-et · **2026-08-09 utólag:** a 3.2 lezárult, a drift-gate (re-konverzió + `git diff`) és a hozzá tartozó pin-indoklás törölve `ci_prod_workflow.yml`-ből — lásd a Napló végét. A `.github/requirements.txt` pinje megmaradt, de már csak dev saját reprodukálhatósági ügye, nem a prodéval megosztott kettős állítás
- [x] **1.4** Az `-5m` verify-ablak rövidebb az atomic tesztek futásidejénél · `ci_dev_workflow.yml:428,670` · **kész 2026-08-03:** mindhárom teszt-job első stepként lebélyegzi az indulását (epoch), a `splunk_verify` a minimumukat veszi −60s margóval `--earliest`-nek; fallback `-15m` + warning. A `check_saved_search_hits.py` érintetlen (a Splunk elfogadja az epochot). A szabályok `custom.splunk.earliest` mezője más dolog — a prod saved search ütemezési ablaka —, nem változott
- [x] **1.5** A Splunk-lekérdezés timeoutja hamis FAIL-ként jelenik meg (+ `FINALIZING` részleges eredmény) · `check_saved_search_hits.py:120-164,138` · **kész 2026-08-03:** explicit timeout-error, olvasás csak `DONE`-nál, plusz a hibák `error_kind`-ot kapnak (`unmeasured` → NOT_VERIFIED, `rule_error` → FAIL) — a script javítása önmagában kevés lett volna, mert az `evaluate()` minden hibát FAIL-re képezett. A legend és a `VERDICT_RANK` komment is átírva
- [x] **1.6** A `scripts/docs/**` nincs a trigger-path-ok között · `ci_dev_workflow.yml:7-28` · **kész 2026-08-03:** a 4.10 útján, mert a path felvétele önmagában nem működött volna (a run elindulna, majd `has_rules=false` miatt mindent átugrana). Új `ci_code_checks.yml`: ruff + pytest minden kód-változásra, plusz `regenerate_docs` és `deploy_pages` job — a Pages ugyanis artifactból publikál, nem a branchről, tehát a commit önmagában nem frissítette volna az élő oldalt
- [x] **1.7** Nincs törlés/kivezetés: `--diff-filter=AMRC`, árva `.spl`, árva saved search, 3 árva result, holt `status: deprecated` · `ci_dev_workflow.yml:89` · **kész 2026-08-04, három rétegben:** (1) Splunk-oldal — a 3.3 `--apply` / `--apply-removals` kivezeti az árva objektumokat; (2) `status: deprecated` — a deploy kihagyja (dev és prod egyaránt, mert a prod is regenerálja a meta sidecarokat és ugyanezt a scriptet futtatja), a reconcile pedig nem-kívántként kezeli, tehát az élő objektuma eltávolítás-árvaként kivezethető; (3) repo-oldal — új `scripts/state/prune_orphans.py` takarítja a törölt szabály `.spl`-jét és result könyvtárát, **saját CI-steppel és saját committal**, mert a `--diff-filter=AMRC` miatt egy tisztán törlő push a többi jobot el sem indítja
- [x] **1.8** A title átírása árva saved search-öt hagy a Splunkban · `rule_naming.py:10` · **lezárva 2026-08-04: a javasolt javítást elutasítottuk.** A `detect_id`-only objektumnév nem elfogadható — az analitikus a Splunk keresőmezőjében és a riasztás-listákban a *nevet* látja, nem a description-t, tehát a beszédes név megmarad. A kiváltó ok ezzel tudatosan felárazott állapot, nem nyitott defekt. A tünetet a **3.3** `orphan_renamed` vödre + `--apply` kezeli: az árvaság nem szűnik meg keletkezni, hanem észlelt és takarított lesz
- [x] **1.9** Egy hibás szabály `throw`-ja megbuktatja az egész batch tesztelését · `run_atomic.ps1:313,338`, `sigma_schema.json` · **kész 2026-08-03:** séma `allOf`+`if/then` (`enabled: true`-ra szűkítve), és mind a négy `throw` → `Write-Warning` + `continue` `$malformed` számlálóval; új `exit 1` ág, ha a batch minden szabálya hibás
- [x] **1.10** Atomic higiénia: nincs `-GetPrereqs` és nincs `-Cleanup` · `run_atomic.ps1:178-242` · **kész 2026-08-03:** `Invoke-AtomicTestCompat -Mode GetPrereqs|Run|Cleanup` (egymást kizáró kapcsolók, tehát három invokáció), cleanup `finally`-ben, egyik segédfázis hibája sem számít `$failures`-nek; `ATOMIC_SKIP_PREREQS` / `ATOMIC_SKIP_CLEANUP`
- [x] **1.11** A Defender kikapcsolva maradhat, ha a stepet a timeout hard-kill-eli · `run_atomic.ps1:496-498` · **kész 2026-08-03:** scheduled task deadman (Once +20p **és** AtStartup), a kikapcsolás *előtt* regisztrálva, fail-closed (`ATOMIC_ALLOW_UNPROTECTED_DISABLE` a felmentés), leftover task `::warning`-gal jelezve
- [x] **1.12** A MITRE hőtérkép soha nem mutat FAIL-t: `best_verdict` a legjobb verdiktet választja, így a FAIL `DETECT-2026-0012` zöld cellák alá bújik (19 zöld / 0 vörös, a FAIL legend-szűrő halott) · `generate_stats.py:368-399,475-481` · **kész 2026-08-03 (a rule browser átdolgozásában, utólag beazonosítva):** `fail-flag` osztály a cellán (`:556,612`), piros sarok-háromszög (`:2421-2428`), és `tcHasFail()`/`failAny` (`:5497,5506,5601`), amitől a FAIL legend-szűrő keresztbe vág a best-verdict csoportosításon. A cella színe szándékosan maradt best-verdict

## 2 · Kisebb hibák és optimalizálás (22)

- [x] **2.1** A `splunk_verify` OR-lánca gyakorlatilag mindig igaz (nem kapu) · `ci_dev_workflow.yml:563-573` · **kész 2026-08-04:** az OR-blokk törölve; ami valóban kapuz, az fölötte marad (épült SPL + sikeres deploy). **Nem volt teljesen no-op:** egyetlen esetben hatott — ha mind a három teszt-job *elbukott* (nem skipped), a csoport hamis lett és a verifikáció némán kimaradt. Ez tudatos viselkedésváltozás: mostantól lefut, és NOT_VERIFIED verdikteket, statisztikát és reconcile-riportot hagy maga után. Promóció egyik esetben sem lett volna; a különbség az, hogy most van nyoma
- [x] **2.2** Egyetlen jobon sincs `timeout-minutes` (a self-hosted runner beragadhat, prodot is blokkolva) · **kész 2026-08-04:** mind a **13 job** kapott job-szintű `timeout-minutes`-t mindhárom workflow-ban, az értékek a scriptek saját timeoutjaiból számolt legrosszabb eset **fölé** állítva (a `splunk_verify` 120 perc, mert a 27 szabály lekérdezése önmagában ~81 perc legitim várakozást enged). Menet közben talált plusz hiba: az **emulation step-nek step-szintű timeoutja sem volt**, a másik két támadó-jobbal ellentétben — ez volt a pipeline egyetlen korlátlan támadás-végrehajtása, ráadásul a victim runneren osztozva az atomickal; kapott egy `timeout-minutes: 10`-et, a másik kettővel azonosan
- [x] **2.3** `SPLUNK_VERIFY_WAIT_SECONDS` soha nincs beállítva → mindig fix 60s · `ci_dev_workflow.yml:636` · **kész 2026-08-05:** új `scripts/verify/wait_for_indexing.py`, a `sleep 60` helyett. A fix várakozás **mindkét irányban rossz volt:** elvitt egy teljes percet akkor is, ha az indexer nyolc másodperc alatt kész lett, és **csendben feladta** hatvannál, ha kilencven kellett volna — nulla találat, és olyan verdikt, ami szerint a detekció bukott, holott csak senki nem várt eleget. Ugyanaz a hamis-verdikt osztály, mint az 1.4 és 1.5. **Amit kérdez, az nem az, hogy „land-elt-e a támadás"** — azt maga a verifikáció méri, és attól egy jogosan nulla eseményt hozó szabály végigvárná a teljes timeoutot. Azt kérdezi, hogy **utolérte-e az indexer a teszt-ablakot**, amire bármelyik esemény válasz a vizsgált indexekben. Az indexeket a bundle meta sidecarjaiból veszi, tehát egy csendes, ebben a körben nem használt index nem elégítheti ki a várakozást. 10 másodpercenként kérdez, legfeljebb 180 másodpercig. **Tanácsadó, nem kapu:** timeoutnál `::warning` és megy tovább — a blokkolás egy lassú indexerből pipeline-hibát csinálna, holott az őszinte kimenetel az, hogy a verifikáció jelentse, amit talál. A hibázó próba (HTTP-hiba, nem-JSON válasz, hálózati hiba) szándékosan megkülönböztethetetlen a „még nincs indexelve"-től: mindkettő azt jelenti, hogy várni kell. **A lépés a window-számítás mögé került**, mert a próbának tudnia kell, mikor kezdődött a teszt-fázis. 13 új teszt
- [x] **2.4** A prod futásnak nincs audit-nyoma (nincs step summary, nincs deploy-artifact) · **kész 2026-08-05:** a `deploy_spl_to_splunk.py` `--report` kapcsolót kapott, ami szabályonként rögzíti a kimenetelt — `created` / `updated` / `skipped_deprecated` / `failed`, hibaokkal és a szabály verziójával —, és ugyanezt a táblát a step summarybe is kirendereli. A prod feltölti artifactként, **90 napra**. **`always()`-szel**, mert egy *elbukott* deploynál számít a legtöbbet: az mondja meg, melyik szabály jutott ki prodba, mielőtt a futás megállt — amit a kilépési kód önmagában nem tud. **Amit szándékosan nem tartalmaz:** Splunk URL, app-név, fiók. Azok titkok vagy titok-közeliek, az artifact pedig egy publikus repóból letölthető — a riport csak olyan tényeket rögzít, amik magából a repóból is levezethetők: mit csináltunk, nem azt, hogy hol. Külön teszt őrzi, hogy egyik kapcsolódási adat sem szivárog bele. 11 új teszt; a `--report` opcionális, a dev hívása változatlan
- [x] **2.5** Deploy-script javítás nem jut ki prodba (paths filter) · `ci_prod_workflow.yml:6-9` · **kész 2026-08-04:** `workflow_dispatch` a prod workflow-ra. Input nélkül, mert a job `git ls-files`-ból dolgozik, nem diffből — egy manuális futás a `main` teljes aktuális könyvtárát deployolja, ami pontosan az „alkalmazd újra mindent a javított scripttel" jelentése. Ellenőrizve, hogy a job semmilyen push-specifikus kontextust nem használ (`github.event.before` stb.), tehát a manuális indítás nem tör el semmit. **Amit szándékosan nem tettem:** a `scripts/deploy/**` felvételét a `paths:` listára — az minden deploy-script merge-nél automatikusan újradeployolna prodba, ami nagyobb viselkedésváltozás, mint amit ez a tétel kér
- [x] **2.6** A „már létezik" detektálás a hibaszöveget stringkeresi · `deploy_spl_to_splunk.py:160-163` · **kész 2026-08-06, a javasolt úton: upsert az objektum-endpointra.** Az `is_already_exists()` törölve — az Splunk hibaszövegében keresett (`already exists` / `conflict` / `in use`), ami **egyetlen szerződésnek sem része**, verziónként változik, és amit három független hiba is tartalmazhat. A deploy most az *objektum*-endpointra POST-ol előbb: **200** = ott volt, frissítve; **404** = még nincs, létrehozás a kollekció-endpointon. Minden más valódi hiba — beleértve azt az 500-ast is, aminek a törzsében véletlenül ott van, hogy „already exists" —, és a státuszkóddal **plusz azzal együtt jelentjük, mit vártunk**, ahelyett hogy átgyanakodnánk rajta. **Kifejezetten nem esik át létrehozásba** váratlan válasznál: pont az volt a régi viselkedés. Mellékhatásként a gyakori eset — egy már korábban deployolt szabály — most **egy hívás kettő helyett**. A create utáni „scheduling újraalkalmazás" megmarad (a Splunk nem tartja meg megbízhatóan az `is_scheduled`/`cron_schedule` mezőket a létrehozó kérésen), az update-útnak viszont nem kell, mert az *maga* az a kérés. 16 új teszt, plusz a meglévő deploy-tesztek átállítva az új protokollra. **Éles Splunk ellen nem tesztelt** — a labor le van kapcsolva —, ezért a váratlan státuszkód üzenete szándékosan kimondja, mit várt, hogy az első valódi futás öndiagnosztizáló legyen
- [x] **2.7** A pass-ablak globális (`--max-pass 10`) · `pass_fail_eval.py:167` · **lezárva 2026-08-06: a fejlesztést elvetettük, a javasolt fix és az alternatívái is.** Bence indoka a `custom.testing.expected_events` ellen: a Sigma szabályban már így is túl sok a metaérték, és egy újabb csak a tünetet mozgatná a YAML-be. Az elemzés ezt megerősítette: **a felső korlát rossz eszköz.** A verdikt két kérdést mos össze — „elsült-e a detekció?" (`>= 1`, ez a verifikáció kérdése) és „pontos-e a szabály?" —, de a másodikra a *támadási ablak* adata elvből nem tud válaszolni: 40 esemény jelenthet túl tág szabályt és olyan technikát is, ami tényleg 40 process-eseményt generál. A zajt az bizonyítja, ha a szabály **támadás nélkül is** elsül. Így bármilyen szabályonkénti konstans — YAML-ben vagy CLI-n — eseményszámra tippel, ami OS-verzióval, naplózási beállítással és a teszt tartalmával együtt vándorol. Felajánlott alternatívák, mind Sigma-mező nélkül, mind elvetve: (1) a felső korlát kivétele a verdiktből, figyelmeztetésként megtartva; (2) csendes ablak referenciaként — ez a **4.1**; (3) a szabály saját eredmény-története mint kiugrás-detektor. **Amit tudatosan vállalunk:** a globális 1–10 ablak marad, és három szabály (`DETECT-2026-0027`, `DETECT-2026-0019`, `DETECT-2026-0014`) **pontosan 10 eseményen áll**, tehát egyetlen extra eseménytől hamis FAIL-t kapna. Ellenőrizve, hogy ez nem lekérdezési plafon: a `--max-events` alapértéke 100, a CI nem írja felül. A valódi megoldás a **4.1** (noise budget), nem egy újabb metaadat
- [x] **2.8** A `NOT_VERIFIED` kapu csak atomicra vonatkozik (8 emulation szabály kimarad) · `pass_fail_eval.py:244` · **kész 2026-08-06.** A kapu a pontszámítás *előtt* fut, mert más kérdésre válaszol: nem azt, hogy „elsült-e a detekció", hanem azt, hogy „megtámadtuk-e egyáltalán". Nélküle a le nem futott támadás nulla eseményt hagy, a nulla esemény pedig FAIL — megerősített negatívum abból, ami meg sem történt. **A javítás alulról felfelé ment, nem a feltétel kiszélesítésével** — az önmagában mind a 8 szabályt örökre NOT_VERIFIED-be tette volna, mert markert soha nem írt hozzájuk semmi: (1) a `run_atomic.ps1` mostantól átviszi a `detect_id`-t az emulation-gyűjtésen és ír markert — a `$collectedCustom` addig lapos parancslista volt, ami nem tudta, melyik szabályhoz tartozik, és *ezért* nem lehetett markert írni; a kulcs `detect_id|index`, nem a teszt neve, mert a név szabad szöveg és egy szabályon belül ismétlődhet; (2) a marker `finally`-ben íródik, tehát egy dobó parancs is *megkíséreltnek* számít — a marker azt rögzíti, hogy a támadás lefutott, nem azt, hogy sikerült; (3) az `emulation_verify` feltölti (eddig **egyáltalán nem volt** upload lépése, a két atomic jobbal ellentétben); (4) a `splunk_verify` letölti, ugyanabba a könyvtárba. **Menet közben talált plusz hiba:** a kapu most már `testing_enabled`-et is megkövetel — egy `type: atomic, enabled: false` szabályt semmi nem támad, tehát markert sem kap, és a régi feltétel örökre NOT_VERIFIED-ben tartotta volna. Ma egy szabály sincs ilyen állapotban. **És egy regresszió, amit én okoztam és javítottam:** a szintetizált összegzés (marker van, `hits.json` nincs) `testing_enabled` nélkül készült, tehát az új feltétellel FAIL-be esett volna; most `True`-t kap, és a **marker maga rögzíti a tester típusát**, mert a korábbi „ez csak atomic lehet" feltevés épp itt szűnt meg igaznak lenni. 16 új teszt — a marker-kapunak **eddig nulla lefedettsége volt**, a meglévő suite csak a tiszta `evaluate()` függvényt fogta. PowerShell parse OK, PSScriptAnalyzer tiszta (az egyetlen figyelmeztetés a committolt verzióban is megvan)
- [x] **2.9** Az index-prefix beszúrása elhasal pipe-pal kezdődő queryn · `sigma_to_spl.py:162-185` · **kész 2026-08-04:** a generáló paranccsal (`| tstats`, `| inputlookup`, …) kezdődő query mostantól **változatlanul** megy tovább, a korábbi `index=x | tstats …` helyett, ami érvénytelen SPL. **Nem hibával**, hanem érintetlenül: egyes generáló parancsok jogosan nem nyúlnak indexhez (`| inputlookup`), ezért a bukás helyes bemenetre találna ki hibát. Amiről viszont hangosan szól: ha a query **sem a sajátját nem hozza, sem a miénket nem tudja fogadni** — az csendben mindent átfésül. 10 új teszt; a 27 committolt `.spl`-en ellenőrizve, hogy egyetlen kimenet sem változott
- [x] **2.10** Szabályonként két Python-process egy mező kiolvasásához · `ci_dev_workflow.yml:323-324` · **kész 2026-08-06.** A „Detect test types" lépés bash-ciklusa szabályonként **két** `python3 -c` egysorost indított — 27 szabályra **54 processz** —, hogy ugyanabból a fájlból két mezőt kiolvasson. **Nem új scripttel javítottam:** az épp az lett volna, amit ez a tétel kifogásol, egy negyedik parser ugyanarra a metaadatra. A **2.17-es `check_test_routing.py`** már ma is beolvassa ezeket a szabályokat *és* tudja, melyik job szolgál ki melyik `(tester, runner)` párt — a flag tehát **keresés egy már felépített táblában**, nem második olvasás. Új `--job-flags` mód, `JOB_OUTPUT_FLAGS` táblával (job-név → workflow-output), mert az az egyetlen rész, ami nem vezethető le: a workflow saját elnevezése. **Menet közben javított rejtett hiba:** a régi egysorosok `2>/dev/null || true`-val zárultak, tehát egy hibás YAML csendben üres testerré vált és kiesett a routingból, szó nélkül. **Egy tudatos viselkedésváltozás:** egy nem kiszolgált runnert kérő szabály eddig `has_atomic_tests=true`-t állított és elindította a victim jobot, ami aztán kihagyta — most nem indul job olyan munkára, ami nincs. A flag-mód **néma** (nincs annotáció, nincs step summary): a dedikált routing-lépés ugyanabban a jobban már jelentette ezeket, egy bővebb szabályhalmazon, tehát a duplikálás csak zaj lenne. 7 új teszt. **A 3.1-et nem váltja ki**, de nem is akadályozza: a logika a YAML-ből egy tesztelhető scriptbe került, ami a manifest bevezetését inkább könnyíti
- [x] **2.11** Hiányzó repo-higiénia: requirements/pyproject/Makefile/pre-commit/CODEOWNERS/PR template/dependabot, actions csak major taggel pinelve · **részben kész 2026-08-06.** A `requirements.txt`, `requirements-dev.txt` és `pyproject.toml` már korábban megvolt. Új: **`.github/dependabot.yml`** — a pinelés bump-mechanizmus nélkül oda vezet, hogy a repó két éve nem nézett converteren ül, és így marad észrevétlen egy olyan CVE, mint amit a pip-audit a diskcache-re jelentett. **A kritikus beállítás a `target-branch: dev`:** a dependabot alapból az alapértelmezett ágra (`main`) nyit PR-t, az pedig **validálás, támadás és mérés nélkül deployol prod Splunkba**, mert a devben már bizonyítottban bízik — egy oda érkező bump megkerülné a teljes bizonyítási utat. A `dev`-re irányítva ugyanazon a körön megy át, mint egy szabályváltozás. Két külön csoport a pip alatt, mert eltérő a kockázatuk: egy `ruff` bump legfeljebb pirosra váltja a CI-t, egy `pySigma` bump viszont megváltoztathatja, mi kerül a Splunkba — együtt nézve az ember a másodikat átengedi az első mellett. **Action-ök SHA-ra pinelve:** mind a **39** `uses:` sor commit-SHA-ra, a pontos verzióval kommentben (`# v4.4.0`). Az indok pontosítás volt, nem elv: **major taggel a dependabot nem szól** a `v4 → v4.1` mozgásról, csak `v5` megjelenésekor — vagyis épp azt nem fogja el, hogy „a tag csendben elmozdult". SHA-val minden mozgás diff lesz, és a dependabot onnantól karban is tartja (a kommentet is frissíti). A tagek a GitHub API-ról feloldva, nem kézzel másolva. **Tudatosan elutasítva, indoklással:** *Makefile* — a `make` nincs a karbantartó gépén (ellenőrizve, Git Bash alatt nem elérhető), tehát egy futtathatatlan fájl lenne; a két parancs amúgy `ruff check .` és `pytest`. *pre-commit* — amit ellenőrizne, azt a CI már kapuzza, cserébe klónonként telepíteni kell és az IDE-ből committolást zavarhatja. *CODEOWNERS* — egyszemélyes repóban saját magától kérne review-t a saját PR-en. *PR-sablon* — a promóciós PR-eket a CI nyitja saját szöveggel, kézi PR alig van. Ezek nem elmaradtak, hanem checklist-ballasztként lettek elvetve
- [x] **2.12** Nulla teszt és nulla linter · fix: 4.10 · **részben kész 2026-08-03** (25 teszt + ruff a CI-ban), **lezárva 2026-08-06 a linter kiszélesítésével.** A válogatás **kurált, nem „minden"** — az első kör tanulsága áll: egy kapu, amit megtanulnak átugrani, kevesebbet ér egy szűknél, amiben megbíznak. Bekapcsolva: `F, E9, E7, B, I, UP, C4, SIM, RET, PIE, RUF`. **Minden kihagyást megmértem, nem feltételeztem:** `E501` (sorhossz) **181 találat**, és azok a *kommentek* — ez a repó szándékosan prózában indokolja magát a kód fölött, 120 oszlopra tördelni pont azt rontaná el, amitől olvasható; `ARG` (nem használt argumentum) 15 találat, gyakorlatilag mind tesztben, ahol egy fake szignatúrájának egyeznie *kell* a valódival — a nem használt paraméter maga a lényeg; `PTH` 6 találat olyan `open()`-ökre, amik a step summaryhez fűznek vagy egy fájlt olvasnak egyszer — a `Path.open()` nem tenné biztonságosabbá, csak mássá. A `RUF001-003` (kétértelmű Unicode) ignorálva: minden találat szándékos tipográfia a generált HTML-ben és az emberi kimenetben. **36 automatikus javítás** (importrendezés, `datetime.UTC`), **6 kézi** (kétértelmű `l` változónevek, felesleges értékadás return előtt, nem használt kicsomagolt változók, egy ternary). Ellenőrizve, hogy a `datetime.UTC` átírás biztonságos: mind a **hét** `python-version` pin `3.11`. A lefedettség másik fele közben magától lezárult: **25 tesztről 181-re** nőtt a suite ebben a munkában
- [x] **2.13** A `rule_documentations/` üres könyvtár · **lezárva 2026-08-04, törléssel** (a két javasolt út közül; a könyvtár már nincs a repóban, csak a register mutatta nyitottként). A generálás mint lehetőség megmarad a **4.8** alatt — ha egyszer megvalósul, új könyvtárként jön létre, tartalommal. A `detection-content-reviewer` agent leírásából is kikerült a rá építő rész
- [x] **2.14** A TLS-verifikáció csendben kikapcsol, ha a secret nincs beállítva · **kész 2026-08-06.** A hivatkozott sorszámok elavultak voltak (`386`/`69`): valójában **5** előfordulás van, `ci_dev_workflow.yml:686, 1139, 1171, 1272` és `ci_prod_workflow.yml:186`. **A defektus nem az volt, hogy a verifikáció kikapcsolható** — egy self-signed labortanúsítvány valós indok —, hanem a munkamegosztás, amit senki nem látott: mind a négy fogyasztó `env_bool("SPLUNK_VERIFY_TLS", default=True)`-t hív, tehát a biztonságos választ a kód **már meghozta**, a workflow pedig egy réteggel feljebb `|| 'false'`-szal felülírta az ellenkezőjére. A fallback nem „nincs preferencia" volt, hanem egy *hiányzó* secret lefordítása pozitív utasítássá. **A tétel másik fele a némaság**, és ez a fontosabb: egyetlen script sem írta ki, milyen módban dolgozik, tehát a leminősítés nyomtalan maradt a joblogban. Most `TLS certificate verification: on.`, kikapcsolva pedig `::warning` — a kikapcsolás továbbra is lehetséges, csak **ki kell mondani** a secretet `false`-ra állítva. **Ma viselkedés-semleges**, és ezt tudni kell a bevezetéshez: a GitHub `||` operátora csak üres értéknél lép működésbe, a secret pedig be van állítva (`true`), tehát a fallback **soha nem sült el** — a javítás arra az esetre szól, ha a secretet törlik, átnevezik, vagy egy új environmentben elmarad. **Tesztek: eddig nulla lefedettség** — a meglévő tesztek beállították a `SPLUNK_VERIFY_TLS: "false"`-t, de egyik sem állított róla semmit. Új `tests/test_tls_verification.py`: a **workflow-őr** a valódi YAML-eket parse-olja és megköveteli a `||`-mentes formát, plusz **őr az őrre** — ha nem talál pontosan 5 hozzárendelést, bukik ahelyett, hogy némán átmenne (a 2.17 `exit 2`-jének szellemében); a **script-oldal** mind a **négy** `env_bool` példányon (mert négy van — ez a **3.6**) üres, hiányzó *és felismerhetetlen* értékre is fail-closed, ez utóbbi azért, mert egy elgépelés nem döntés az ellenőrzés kihagyásáról; végül **végponttól végpontig**, hogy a `session.verify` tényleg megkapja az értéket. Az őrt **mutációval** ellenőriztem: a `|| 'false'` visszatétele a prod workflow-ba megbuktatta, majd visszaállítva zöld. **Menet közben javított saját hiba:** a teszt eredetileg `from tests.conftest import REPO_ROOT`-tal indult, ami csak `python -m pytest` alatt oldódik fel (az teszi a cwd-t a `sys.path`-ra); a `ci_code_checks.yml` **csupasz `pytest`**-et hív, ahol ez collection-hibát dob és **az egész suite-ot leállítja**, nem csak ezt a fájlt. **Amit nem csináltam meg:** a `SPLUNK_VERIFY_TLS` boolean kapcsoló, tehát a 2.18 érvelése szó szerint áll rá és `vars`-ba tartozna — a tulajdonos döntése, hogy egyelőre secretként marad
- [x] **2.15** A `fields:` metaadat halott (séma kötelezi, converter kidobja, SPL nem használja) · `sigma_to_spl.py:255` · **lezárva 2026-08-05: a tétel premisszája téves volt, teendő nincs.** A `fields:` **él**: a pySigma Splunk backendje olvassa és `| table ...` klauzulát generál belőle. A `sigma_to_spl.py:278` csak a **meta sidecarból** hagyja ki — ahol tényleg nem kell, mert a query már hordozza —, nem a query-generálásból. Ellenőrizve mind a 27 szabályra: mindegyik deklarál `fields:`-t, és mind a 26 meglévő `.spl` `| table` klauzulája **pontosan, sorrendhelyesen** egyezik vele (a 27. a `DETECT-2026-0008`, aminek a fájlját a végpontvédelem ismét karanténba tette). A felhasználó szúrta ki, a `DETECT-2026-0012` kimenetéből
- [x] **2.16** Nyers Splunk-eventek 90 napig publikusan letölthető artifactban · `ci_dev_workflow.yml:691-698` · **kész 2026-08-05: retention 90 → 14 nap.** A két javasolt út közül a rövidebb retention, **nem** a mezőszűrés: a nyers esemény *maga* a hibakeresési érték — ha egy találatszám gyanús, épp a parancssort akarod elolvasni. Nem a tartalom volt rossz, hanem az ablak: ezek egyetlen futás magyarázatára készülnek, és három hónapos futást senki nem debugol, tehát a 90 nap olyan megőrzés volt, amihez nem tartozott használati eset. A 14 átfog egy hosszú hétvégét és egy szabadságot is. **Ami valóban ki volt téve:** nem a szintetikus támadás-forgalom, hanem a **labor névtana** — gépnevek, domain, szolgáltatásfiókok —, aminek felderítési értéke van annyiban, amennyiben a labor a valós elnevezéseket tükrözi. A döntés Bencéé volt. A szomszédos artifactok érintetlenek: a bundle és a progress markerek 1 nap, a reconcile-riport 30, a prod deploy-riport (2.4) 90 — az utóbbi szándékosan, mert nyers Splunk-adatot nem tartalmaz
- [x] **2.17** Az `emulation` + `windows-dc` kombináció csendben kiesik · `ci_dev_workflow.yml:527`, `run_atomic.ps1:300` · **tágabb volt, mint ahogy itt szerepelt:** a séma `runner` enumja `linux-victim`-et is enged, amihez **egyetlen job sincs** — tehát nem csak az emulation+DC esett ki némán. A `linux-victim` **szándékos előretekintés** (a VM még nem létezik, de tervben van), ezért a megoldás nem a sémából való kivétel lett. · **kész 2026-08-04:** új `scripts/validate/check_test_routing.py`. A kiszolgált kombinációkat **a workflow-ból vezeti le** (minden step, ami `ATOMIC_TESTER_TYPE`-ot *és* `ATOMIC_RUNNER`-t is állít), nem egy beégetett listából — így a linux job későbbi hozzáadása nem igényel szerkesztést itt, és egy job törlése nem hagy maga után elavult allow-listát, ami továbbra is lefedettnek állítja a szabályait. Ha egyetlen job sem állítja a két env-et, `exit 2` a 27 találat helyett: az az állapot a checker hibája, nem a szabályoké. **Két helyen, két szigorúsággal:** a dev workflow-ban `::warning` + step summary tábla (a detekció akkor is deployolandó, ha a tesztje még nem futtatható), a pytest-suite-ban viszont kemény bukás, mert egy *committolt* szabály kiesése regresszió — job átnevezés vagy törlés. **Menet közben talált plusz hiba:** a hiányzó `runner` ugyanez a defekt — a converter csak nem-üresen írja ki a meta mezőt, a `run_atomic.ps1` pedig pontos egyezést vár, tehát a „nincs megadva" nem az alapértelmezettet jelenti, hanem egy olyan értéket, amit *minden* job szűrője eldob; a checker ezt is jelzi. Ma mind a 27 szabály valós jobra irányul (16 atomic/victim, 3 atomic/DC, 8 emulation/victim), tehát a rés lappangó volt. 25 új teszt. **Ami nyitva marad:** a nem-futtatott emulation szabály verdiktje ettől még nem lesz NOT_VERIFIED — az a **2.8**
- [x] **2.18** A `SPLUNK_APP` secretként van kezelve, holott `vars`-ba tartozik · **kész 2026-08-06:** mind az 5 hivatkozás `${{ secrets.SPLUNK_APP }}` → `${{ vars.SPLUNK_APP }}` (`ci_dev_workflow.yml:662, 1113, 1143, 1242` — `deploy_to_splunk` és a `splunk_verify` három lépése —, `ci_prod_workflow.yml:175`), a script-oldal **változatlan**, mert mind a négy fogyasztó `env_required("SPLUNK_APP")`-ot hív, azt pedig nem érdekli, honnan jön az env. **Az indok nem az, hogy „nem titok":** egy app-namespace routing-címke, nem hitelesítő — önmagában semmit nem ad —, a maszkolás viszont épp azt az egyetlen értéket tette olvashatatlanná, ami a dev/prod szétválasztást eldönti, *annak a jobnak a logjában, amelyiket célozza*. Ennél is fontosabb, hogy secretként a két environment értéke **egymással sem volt összevethető**, tehát a `threat_model.md:31` által hiányolt kereszt-ellenőrzés („semmi nem ellenőrzi, hogy a két environment különböző appra oldódik-e fel") nem volt *elvégezhető* sem — most legalább ember el tudja végezni. **A migráció közben derült ki a valódi csapda:** a Splunk „Manage Apps" listájában a dev app **labelje `dev`, a mappaneve viszont `detection_engineering`** (a prodnál a kettő véletlenül egyezik: `prod`/`prod`). Az URL-be a mappanév megy (`deploy_spl_to_splunk.py:184`, `/servicesNS/{owner}/{app}`, `quote(app, safe='')`-cal), tehát a listában látszó „Name" oszlop bemásolása egy nem létező namespace-re mutató 404-et adott volna — és mivel az aszimmetria **csak a dev oldalon áll fenn**, a prod értéke nem leplezte volna le a hibát. Az értékek visszamenőleg konzisztensek: `dev` mappanévvel egyetlen deploy sem futhatott volna le. **A scope nem mozdult, és nem is mozdulhat:** a `SPLUNK_APP` eddig is environment-scope-os volt, és annak is kell maradnia, mert egy repo szintű variable egyetlen értéket tárol, itt viszont a *lényeg* a két különböző érték azonos név alatt. Ez a **2.20** pontos ellentéte: a `LAB_ONLINE` azért kényszerült repository szintre, mert job-szintű `if:`-ben szerepel, ami az `environment:` feloldása *előtt* értékelődik ki — a `SPLUNK_APP` mind az öt helyen step-szintű `env:` blokkban van, ami a job indulása *után* fut, tehát az environment scope itt egyszerre lehetséges és kötelező. Ellenőrizve: mind a három érintett job deklarál `environment:`-et (`:634` dev, `:964` dev, prod `:89`), és nincs reusable workflow, composite action vagy `workflow_call` a repóban, tehát a `vars` eltérő öröklődése nem érint semmit. **Fail-closed marad:** beállítatlan változó esetén az `env_required()` a `.strip()` utáni üres értéket is elutasítja, még az első HTTP-hívás előtt (deploy exit 1, `wait_for_indexing` exit 2, `check_saved_search_hits` exit 1, `reconcile` exit 2) — prod tehát nem tud névtelen namespace-be deployolni. **Menet közben talált mellékhiba:** a reconcile lépés `continue-on-error: true`, tehát *ott* egy hiányzó változó csak warning, nem bukás — a rekonciliáció csendben kimaradhat, miközben a deploy hangosan elhasalna; ez nem ennek a tételnek a hibája, csak most vált relevánssá. **Empirikusan tisztázva egy állítás, ami mindkét irányban terjedt:** a GitHub **enged** azonos nevű secretet és variable-t ugyanazon az environment scope-on — a `vars.SPLUNK_APP` létrehozása szó nélkül lefutott úgy, hogy a secret a helyén volt. A dokumentáció ezt sehol nem mondja ki (sem a variables naming conventions, sem a REST-referencia, ami a variable-létrehozásnál a `201`-en kívül egyetlen hibakódot sem sorol), ezért mérésből dőlt el. Következmény: **nincs kényszerű „előbb töröld a secretet" lépés**, a migráció visszafordítható, a régi secretek inertek (semmi nem hivatkozik rájuk) és a **kimenő állapotban még léteznek** — az első sikeres éles futás után törlendők. Dokumentáció frissítve: `pipeline_overview.md:9, 392`, `threat_model.md` (az érvelés érintetlen, egy bekezdés pontosít), `README.md:109, 116, 131, 136`, és **plusz javításként** a `data_flow.md:122`, ami a 2.18-tól függetlenül is tévedett (a `SPLUNK_BASE_URL` és társai *repository* secretek, nem environment-scope-osak). `actionlint` 1.7.12 exit 0, teljes suite **204 passed** — és ez nem érintőleges, a `test_check_test_routing.py` ténylegesen parse-olja a `ci_dev_workflow.yml`-t. **Ami nyitva marad:** éles futással még nincs igazolva, mert a `LAB_ONLINE` jelenleg `false`, tehát a labor-jobok kimaradnak; a bizonyíték az első bekapcsolt laborral futó, szabályt módosító dev push lesz
- [x] **2.19** A teljes újraépítés kiváltó feltétele könyvtárra illeszt, nem kimeneti hatásra · `ci_dev_workflow.yml:110` · **éles esetben derült ki:** a 2.17 `check_test_routing.py`-ja a `scripts/validate/` alá került, illeszkedett a `scripts/validate/*` globra, és ezzel `mode=all`-t váltott ki — teljes labor-futást indított (deploy + mind a három támadó job + verifikáció, 27 szabályra) egy scriptért, ami egyetlen `.spl`-t sem befolyásol. A futás beragadt egy offline runnerre várva és blokkolta a következő pusht is. · **kész 2026-08-04:** explicit fájllista (`sigma_schema.json`, `validate_sigma.py`, `validate_sigma.ps1`, `sigma_to_spl.py`, `rule_naming.py`) a glob helyett. A szándék változatlan — converter- vagy sémaváltozás után tényleg mindent újra kell építeni —, csak a kiváltó ok lett pontos. **Plusz hiba:** a `rule_naming.py` eddig nem volt a listán, holott a workflow `paths:`-ában igen; a saved search *nevét* határozza meg, tehát minden objektumot átnevez — ez volt az egyetlen eset, ami elindított egy futást, de csak a diffet dolgozta fel. 14 esetre ellenőrizve
- [x] **2.20** Kikapcsolt labor esetén a futás beragad és blokkolja a sávot · **kész 2026-08-04:** új `vars.LAB_ONLINE` (`false` → a laborhoz kötött jobok kimaradnak, a push viszont validál, konvertál, SPL-t committol). **Egyetlen kapun**, a `deploy_to_splunk`-on — az minden self-hosted runner belépési pontja —, és a függőségi gráf viszi tovább, ahelyett hogy öt helyen kéne ugyanaz a feltétel. A kaszkád levezetett: a támadó jobok függenek tőle és nincs `always()`-ük, a `splunk_verify` `deploy_to_splunk.result == 'success'`-ot vár, a promóció és a Pages pedig olyan `splunk_verify` eredményt, amit nem kap meg. A polaritás szándékos: csak a szó szerinti `'false'` tilt, tehát a beállítatlan változó = megy a labor, és egy elgépelt név a futás felé hibázik. **A visszaút is kellett:** a kapcsoló önmagában lyukat hagyott (a lekapcsolt laborban mergelt szabály sosem jut ki a Splunkba, mert a dev csak a diffet deployolja), ezért a dev workflow megkapta a `workflow_dispatch`-et — input nélkül, mert a dispatchnél üres `github.event.before` már `mode=all`-t jelent, tehát egy kézi indítás mindent újraépít és újramér. A kihagyásról `::warning` + step summary szól, mert a kihagyott job nem hiba, és a jobok listájában egy zöld futástól nem különbözne. **A prod workflow ugyanezt a változót nézi:** a `deploy_to_prod` ugyanazon a `de-lab` gépen fut, tehát pontosan ugyanazt örökölte — a kihagyás pedig szigorúan jobb, mint a sorban állás, mert mindkettő azt jelenti, hogy prod nem frissült, de az egyik egy percen belül meg is mondja, a másik meg egy napig foglaltnak látszik. A visszaút ott már készen volt: a 2.5-ös `workflow_dispatch` `git ls-files`-ból deployol, tehát egy kézi futás a `main` teljes aktuális könyvtárát kiteszi. Mivel prodnak egyetlen valódi jobja van, és épp az marad ki, mellé került egy `announce_lab_offline` job `ubuntu-latest`-en, **pontosan komplementer feltétellel** — nélküle nem maradna semmi, ami jelentse, hogy prod nem frissült, és a teljesen kihagyott futás megkülönböztethetetlen lenne egy egészségestől. **A változó repository szintű kell legyen, nem environment:** a job-szintű `if:` azelőtt értékelődik ki, hogy az `environment:` feloldódna, tehát egy environment-scope-os változót nem látna, és a kapu csendben nem működne. **Utólag pontosítva a 2.21-ben:** a kézi indítás már nem input nélküli, hanem `scope` választós
- [x] **2.21** A kézi indítás mindig az összes szabályt futtatja · **kész 2026-08-04:** a `workflow_dispatch` `scope` inputot kapott — `unverified` (alapértelmezett) és `all`. A probléma az volt, hogy a dispatch *mellékhatásból* került `mode=all`-ba (üres `github.event.before`), tehát két utólag behozandó szabály miatt is mind a 27-et újratámadta a labor VM-jein. A push tudja, mi változott, a kézi indítás nem — **de a viszonyítási alap megvan a repóban:** minden `result.json` rögzíti, melyik `rule_version`-nel mértek, a szabály verziója pedig a commitszáma, tehát a „kell-e futtatni" diff nélkül is megválaszolható: nincs eredménye, vagy egy korábbi verziójához tartozik. Ugyanaz a drift, amit a rule browser már ma is mutat — csak eddig nem lehetett vele *indítani*. Új `scripts/state/select_unverified.py`, 17 teszt. **A válogatás felé hibázik:** ha a verzió egyáltalán nem állapítható meg (nincs git history, shallow clone, olvashatatlan szabály), a szabály bekerül — egy fölösleges újrafuttatás labor-idő, egy téves kihagyás viszont olyan szabály, amiről mindenki azt hiszi, ellenőrizve van. A deprecated szabályok kimaradnak (nincsenek deployolva), a FAIL viszont ellenőrzöttnek számít az adott verzión: ez munkát válogat, nem verdikteket bírál felül. **Az `all` megmarad**, mert converter- vagy sémaváltozás úgy érvényteleníti a korábbi SPL-t, hogy közben egyetlen szabály verziója sem változik — azt a staleness-vizsgálat nem látja. Ha semmi nem szorul mérésre, a futás ezt ki is mondja, ahelyett hogy értelmezendő üres futásnak látszana. **Bővítve 2026-08-06 (Bence kérésére):** harmadik út a `rules` input — vesszővel vagy szóközzel elválasztott `detect_id`-k, amiket **módosítás nélkül** újra lehet futtatni a teljes pipeline-on; felülírja a `scope`-ot, mert konkrét szabályokat megnevezni specifikusabb utasítás, mint bármelyik tömeges mód. **Miért szabad szöveg és nem legördülő:** a `workflow_dispatch` inputjai statikus YAML-ben élnek, a `type: choice` pedig **egyértékű** — többes kiválasztás nincs a platformon. Egy dropdown tehát egyszerre csak egy szabályt kínálhatna, és az `options:` listát a `rules/sigma/`-val szinkronban tartani azt jelentené, hogy a CI minden szabályváltozásnál **átírja a saját workflow-fájlját** — nagy hibafelület egy kényelmi funkcióért. A dropdown *biztonsága* helyette validációból jön: új `scripts/state/resolve_rule_selection.py` elbuktatja a futást ismeretlen azonosítóra és kilistázza az összes érvényeset, és **egyetlen rossz token az egész kiválasztást eldobja** — egy részleges futás úgy nézne ki, mintha teljesült volna a kérés. Elfogad `detect_id`-t, puszta fájlnevet és útvonalat is, kis-nagybetűtől függetlenül, és **egyetlen YAML-t sem parse-ol**: a fájlnevek `<detect_id>_<slug>.yml` alakúak, tehát a feloldás glob — a 2.10 szellemében nem ad ötödik metaadat-olvasót. 23 teszt

- [x] **2.22** A séma tag-validációja dekoratív, és a stats-generátor még nála is lazább · `sigma_schema.json`, `generate_stats.py` (`extract_techniques()`) · **a 4.3 munkája közben derült ki.** A séma `tags:` mintája (`^attack\.[Tt]\d{4}...$`) és az enum egy `anyOf` **harmadik ága** mellett áll, ami szabad szöveg — tehát együtt semmit nem zárnak ki, csak szerkesztő-javaslatok. Az `attack.t123` séma-érvényes. Rosszabb: a `generate_stats.py` `extract_techniques()`-e `attack\.t\d+`-re illeszt, ami **lazább a sémáénál**, tehát a hibás tag nem egyszerűen átcsúszik, hanem **badge-et és Navigator-cellát kap**, mintha valós lefedettség lenne. A 4.3 validátora ezt ma elkapja, de **tanácsadó módban** — a séma és a generátor közti eltérés maga megmarad. Fix: vagy a séma `anyOf`-ját szűkíteni (kockázat: a legitim `attack.g####`/`s####`/`cve.*` tageket is ki kell engednie), vagy a generátor regexét a sémáéhoz igazítani, hogy legalább a két oldal ugyanazt mondja · fix: a két minta összehangolása, a 4.3 `--strict` bekapcsolása külön döntés · **kész 2026-08-11:** a generátor oldalát igazítottam a sémához (a kockázatosabb irányt, a séma `anyOf`-jának szűkítését, szándékosan nem választottam — az a `g####`/`s####`/`cve.*` tageket is veszélybe sodorná). `extract_techniques()` új mintája `^attack\.(t\d{4}(?:\.\d{3})?)$`, anchorolva és számjegyre pontosan a sémáéval egyezően — egy `attack.t123`-féle álca-tag mostantól sem a sémán, sem a generátoron nem kap "ez technika" elbánást, tehát badge-et/Navigator-cellát sem. A séma `anyOf` harmadik ága (szabad szöveg) tudatosan, változatlanul megmarad — ez immár vállalt, nem hallgatott döntés. Ellenőrizve mind a 27 meglévő szabály tagjén (nulla eltérés a régi és az új regex között — ma egyik rule sem érintett), plusz szintetikus esetekkel (`t123`, `t1059.1`, `t1059.001.002` → mind kiesik). A generátor egy teljes futtatással is leellenőrizve: a `stats.json`/`navigator_layer.json`/`coverage_history.json` diffje kizárólag időbélyeg és az aznapi history-pont, semmilyen lefedettség-szám nem mozdult

## 3 · Architektúra (9)

- [x] **3.1** Egy manifest helyett négyszer parse-olt metaadat · `sigma_to_spl.py`, `run_atomic.ps1:26-43`, `deploy:46`, `verify:56` · **kész 2026-08-07, de nem úgy, ahogy a tétel leírta — a megfogalmazás elavult volt, és a felmérés ezt derítette ki először.** A javasolt fix (`manifest.json` a converterből, a workflow `jq`-val olvassa, ≈60-80 sorral rövidebb dev workflow) **ma nem kivitelezhető, mert nincs mit kivenni**: a dev workflow-ban a `jq` összesen kétszer szerepel, mindkettő a promotion-PR jobban (`gh pr list --jq`, `gh project item-add --jq`), semmi köze a szabály-metaadathoz. A workflow egyetlen dolgot csinál a sidecarokkal — ellenőrzi hogy léteznek és bemásolja őket a bundle-be (566-582. sor) —, és ezt egy manifest sem szüntetné meg. A nevesített négy olvasó valós, de vékony: két ~10 soros `extract_meta()` és egy `Read-MetaFromSplFile`, összesen ~30 sor, és tartalmilag **a 3.6-hoz tartozik**, ami szó szerint nevesíti is („meta IO … 2-2 példányban"). **A tényleges duplikáció eggyel feljebb volt, és nem négyszeres, hanem kilencszeres:** ennyi script nyitja meg maga a Sigma YAML-t, és ebből **hat maga dönti el, mely fájlok számítanak szabálynak** — négyféleképpen. `generate_stats`, `prune_orphans`, `reconcile`: `glob("*.yml")`, lapos; `check_mitre_tags`, `check_test_routing`: `rglob("*.yml")`, rekurzív; `select_unverified`: `rglob("*.yml") + rglob("*.yaml")`. Ma csak azért egyeznek, mert a `rules/sigma/` véletlenül lapos és minden fájl `.yml`. **A tétel súlya innen jön, és nem rendrakási:** a **3.8** alkönyvtárakat javasol, és azon a napon a felső három nem látná a bennük lévő szabályokat — a `prune_orphans` árvának minősítené és **törölné** az artefaktumaikat, a `reconcile` a Splunk-objektumaikat, az `--apply` pedig felügyelet nélkül fut minden dev futásban. **Reprodukálva:** egyetlen szabályt almappába téve a régi kód 26 szabályt lát és „would remove" a `DETECT-2026-0028` SPL-jét és eredménykönyvtárát; az új 27-et lát, nincs árva. Egy layout-változtatás ma **adatvesztéssel** járt volna, tehát ez a javítás a **3.8 előfeltétele**. Új `scripts/lib/rules.py`: `discover()` rekurzív és mindkét kiterjesztést elfogadja (a négy közül a legbővebb, hogy egyik script se veszítsen szem elől olyat, amit ma lát), plusz `load_rule()` és négy mezőolvasó. **A hibapolitika a hívónál maradt**, a 3.6 tanulsága szerint: a hat script hatféleképp bukik (csendben eldob / raise / futásra jelöl / warn+skip), és ezek szándékosak — `load_rule()` egyetlen kivételt dob, minden hívó megtartotta a saját `except`-jét, láthatóan a hívás helyén, nem callback mögé rejtve. **Egy tudatos szerződésváltozás:** a nem-mapping dokumentum (beleértve az üres fájlt, ahol a `safe_load` `None`-t ad) mostantól hiba, nem `{}` — ilyen fájl nincs a repóban, tehát kimenet nem mozdul, de ahol a viselkedés eltér, ott az új a biztonságosabb: a `prune` és a `reconcile` nem hajlandó olyan fájlra cselekedni, amit nem tudott elolvasni, ami pontosan az, amit a saját kommentjeik előírnak. **Három scriptben a lib-import a `main()`-be került**, nem modulszintre: a `lib.rules` importálja a pyyaml-t, egy felső import tehát a barátságos „install pyyaml" üzenet *előtt* szállna el, és a 2-es kilépési kódot („setup hibás") 1-esre cserélné, amit a CI úgy olvas, hogy „a script talált valamit a szabályokban". **Bizonyítás négy rétegben:** a converter a pinelt toolchainnel **módosítatlanul** reprodukálja a 27 committolt `.spl`-t (enélkül egy eltérést nem lehetne a változtatásra visszavezetni), és a refaktor után is, 27/27 sha256; a `generate_stats.py` kimenete (README, `docs/index.html`, 4 JSON) érdemben azonos a repo saját `normalize()`-ával, előtte és utána; a négy offline futtatható script és a `reconcile.load_desired()` bájtra ugyanazt adja stash-elt régi kóddal és az újjal; és a CI függetlenül megerősítette — a `Regenerate Console` job lefuttatta a módosított generátort és **nem commitolt**. **29 új teszt**, köztük egy mechanikus guard, ami minden fogyasztó forrásában keresi a kézzel írt yml/yaml globot (kipróbálva: visszatéve egy globot a `prune`-ba, elbukik) — ez az, ami észreveszi, ha valaki később visszacsempész egyet · **hátra:** a meta IO összevonása a 3.6-ban tartozik, nem itt; a **2.22** gyökere (a `generate_stats` saját `extract_techniques()` regexe, ami lazább a sémánál) külön lépés
- [x] **3.2** Artifact-promóció újraépítés helyett (a bundle legyen az artifact, digesttel) · fix: release asset / build provenance, a prod letölti és ellenőrzi · **kész 2026-08-09, három lépcsőben, élesben bizonyítva:** GitHub natív, Sigstore-alapú build-provenance attesztáció (`actions/attest-build-provenance`) — a dev workflow minden `.spl`-t aláír a saját OIDC-identitásával, a prod pedig (`gh attestation verify --signer-workflow ci_dev_workflow.yml`) ellenőrzi, hogy a deployolandó bájtok pontosan ettől a workflow-tól, ettől a repótól származnak, ahelyett hogy újrakonvertálná és összevetné a Sigma forrást. Ez erősebb, nem csak olcsóbb: a régi drift-gate azt bizonyította, hogy „ez a tartalom megegyezik egy újrakonverzióval" — amit egy elég motivált, commit-joggal rendelkező szereplő kézzel is tudna hamisítani —, az attesztáció azt bizonyítja, hogy „ezt a pontos bájtsort egy legitim CI-futás állította elő", amit *nem* lehet aláírás nélkül reprodukálni. Mindhárom biztonsági tulajdonságot (rossz signer-workflow, rossz signer-repo, kézzel módosított tartalom) direktben teszteltem — mind helyesen elutasítva — mielőtt élesbe került.
  **A.** Dev aláír, additív (`ci_dev_workflow.yml`, `id-token: write` + `attestations: write`), plusz egy kis git-tracked `.bundle-provenance.json` pointer, ami megjegyzi, melyik futás gyártotta a bundle-t (mert a promóciós PR merge/squash/rebase stratégiái közül csak a tartalom-alapú megoldás éli túl mindhármat).
  **B.** Prod ellenőriz, nem blokkolóan, a régi gate mellett — egy valós, teljes lefedettségű (27/27) deploy-on (run 31311925932) hamis pozitív/negatív nélkül bizonyítva.
  **C.** A régi újrakonvertálás+diff gate törölve; a prod már nem telepíti a Sigma-toolchaint (`requirements.txt` helyett `requirements-deploy.txt`, csak `requests`), a `.meta.json` sidecar-okat a dev bundle-ből tölti le, az ellenőrzés blokkolóvá vált.
  **Ugyanaznap talált és javított valós hiba:** a Stage C első éles futása (run 31314423690) elbukott, mert a `.bundle-provenance.json` mindig az *utolsó* dev-futás bundle-jére mutat, egy célzott, egy-szabályos dispatch bundle-je pedig csak azt az egy szabályt tartalmazta — a prod minden más szabálynál hiányzó `.meta.json`-on halt el (a Splunk-írás *előtt*, tehát éles kár nem történt). A felhasználó helyesen vetette fel, hogy a nyilvánvaló javítás (minden szabály újrakonvertálása minden futáson, ahogy a régi gate tette) nem skálázna 150–400 szabálynál. Megoldás: új `--meta-only` mód a konverterben — a metaadat-építés független a drága `sigma-cli` subprocess-hívástól, csak a már beolvasott YAML-t használja —, amivel a dev pipeline minden futáson olcsón frissíti a *nem érintett* szabályok sidecar-ját is, a drága teljes konverzió változatlanul csak a ténylegesen módosítottakra korlátozódik. Ugyanekkor a felhasználó azt is észrevette, hogy a `gh attestation verify` soros hívásai (~5mp/fájl, 27-nél ~140mp, 400-nál ~33 perc lenne) nem fenntarthatók — 8-utas párhuzamosításra váltva ugyanaz a 27 fájl ~20mp alatt fut le, élesben mérve. Mindkét javítás ugyanaznap, egy második valós prod-futáson (run 31315921964) hibamentesen bizonyította magát: 27/27 `.meta.json`, 27/27 attesztáció ~20mp alatt, sikeres deploy.
- [x] **3.3** Nincs desired-state ↔ actual-state rekonciliáció · **kész 2026-08-04:** a `--check` mellé `--apply` (átnevezés-árvák törlése, a dev CI-ban automatikusan) és `--apply-removals` (eltávolítás-árvák kikapcsolása + `[RETIRED …]` jelölés, kézi opt-in). Alább a 2026-08-03-i `--check` fele változatlanul: `scripts/state/reconcile.py` megvan, akkor még **csak `--check`** (kizárólag olvasó, nincs `--apply`). Öt vödör: in sync / missing / orphan_renamed / orphan_removed / unmanaged. Új `ci_managed` sidecar-mező **nem kellett** — a deploy leírás-prefixe már ma is CI-jelölő. CI-ban a `splunk_verify` végén, `always()` + `continue-on-error`. Hátra: `--apply` — és az **1.8** 2026-08-04-i lezárása óta ez viseli az ottani tünetet is, tehát a `orphan_renamed` takarítása állandó mechanizmus, nem egyszeri migráció
- [x] **3.4** A `generate_stats.py` 4392 soros monolit (~3300 sor inline HTML) · `generate_stats.py:986-4275` · **1. fázis kész 2026-08-06; a JSON-blokk hátravan (lásd a végén).** A tétel számai közben elavultak, és **rosszabb irányba**: a fájl **6079** sorra nőtt (+38% az audit óta), a `_PAGE_TEMPLATE` egyetlen literálja az 1221. sortól **4709 sor**, a fájl **77%-a** — önmagában nagyobb, mint amekkora az egész fájl volt, amikor a problémát felírtuk. A markerek száma 16-ról 20-ra ment. **A tényleges kár nem a sorszám, hanem a szerszám hiánya:** a literálban HTML és CSS mellett ~2800 sor **JavaScript** van (escape-elés, kulcs-normalizálás, CSV-export, hash-alapú útválasztás, táblázat-renderelés), és ezek közül **egyiket sem nézte semmi** — a `ruff` a körülötte lévő Pythont linteli, a stringet egyetlen átlátszatlan tokennek látja, egy JS-elgépelést tehát nem a CI talál meg, hanem a felhasználó a betöltött oldalon. **Eredmény:** `generate_stats.py` **6079 → 1425 sor**, az assetek a `scripts/docs/assets/` alá (`page.template.html` 432, `page.css` 1416, `page.js` 2862 sor), a behelyettesítés mechanizmusa (`@@MARKER@@` → `str.replace`) érintetlen. **A kiemelés nem szövegvágással történt**, hanem az eredeti modul **futásidejű `_PAGE_TEMPLATE` értékéből** — ami a memóriában volt, az került lemezre, így a raw-string szemantika (a beágyazott JS tele van regexekkel) elvileg sem tud elromlani; a régi literál és az új `load_page_template()` eredménye bájtra azonos, 231 106 karakter. **Az elfogadási feltétel a `docs/index.html` bájt-azonossága volt**, és ez a refaktor ritka szerencséje: a program egyetlen kimenete committolva van, tehát a bizonyíték maga a `git diff`. Egy csapdával, amit ki kellett kerülni: a generátor `datetime.now()`-ot és a HEAD sha-ját bélyegzi a lapba, tehát a naiv diff 3 sort mutat — **ugyanaz a 3 sor mozdul a módosítatlan generátornál is**, befagyasztott órával pedig a diff üres és a sha256 egyezik (576 906 bájt). **Az útvonal `__file__`-hoz oldódik fel, nem cwd-hez** (a workflow útvonal szerint hívja a scripteket), `/tmp`-ből futtatva igazolva; hiányzó asset esetén `exit 1` a hiányzó fájl megnevezésével — ez új, de helyes fail-closed viselkedés. **Ami hátravan (2. fázis):** egyetlen `<script id="page-data" type="application/json">` blokk, ami a 20 markerből **16-ot** elvisz és a `page.js`-t **placeholder-mentessé** teszi, azaz önmagában lintelhető és futtatható JavaScripté. Négy marker szándékosan szerver-oldali marad — `@@META_DESC@@` és `@@PAGE_URL@@` (link-preview, oda nem futhat JS), `@@MATRIX_HTML@@` (szerver-renderelt markup), és a `@@PASS_RATE@@`/`@@MITRE_PCT@@` az aria-labelekben és a gauge szövegében, mert azok a **JS nélküli fallback**. Buktató a payloadban: a szabálytörzs tartalmazhat `</script>`-et, tehát `json.dumps(...).replace("</", "<\\/")` kell. **Ez a lépés szükségszerűen megváltoztatja a generált HTML-t**, tehát ott a bájt-azonosság már nem lehet mérce, és **ott a böngészős ellenőrzés valóban indokolt** — az 1. fázisnál nem volt az, mert a böngésző definíció szerint ugyanazt a bájtsort kapja. Egy apróság szintén a 2. fázisra: a generált lap fejlécének kommentje még a `_PAGE_TEMPLATE`-re hivatkozik, de a javítása egy sorral elmozdítaná a kimenetet
- [x] **3.5** A verziózás a git history-hoz kötött · `sigma_to_spl.py`, `generate_stats.py` · **a duplikáció fele kész 2026-08-11:** a két azonos `compute_rule_version()` implementáció egy közös `scripts/lib/rule_version.py`-ba került. A séma maga — hogy a "verzió" git commit-számból származik, nem valaki tudatos döntéséből, tehát egy kozmetikai javítás ugyanúgy bumpol, mint egy logika-változás — akkor **szándékosan nyitva maradt**, önálló, nagyobb döntésként (explicit `version:` mező a YAML-ben + CI-gate a bumpra, minden rule-fájlt érintve). **Séma/fegyelem-fele kész 2026-08-15:** explicit `version:` mező (`"MAJOR.MINOR"`, séma-kötelező) mind a 27 meglévő szabályban, seedelve a szabály akkori, `compute_rule_version()`-nel mért verziójára (nem hardcode `"1.0"`); `scripts/new_rule.py` skeletonja is kapott `version: "1.0"`-t, hogy egy frissen scaffoldolt szabály is séma-valid maradjon. Új `scripts/validate/check_version_bump.py` — hard gate, `--strict` nélkül, ugyanaz a szerződés, mint a `check_detect_id_uniqueness.py`-é —, ami a push által változtatott szabályokra nézi, hogy a `detection:`/`logsource:`/`custom.splunk.raw_query` változott-e a diff alapjához (`base_sha`) képest anélkül, hogy a `version:` is változott volna; `description`/`references`/`falsepositives`/`tags`/`status`/`level`/`fields`/`custom.testing` önmagában nem kényszerít bumpot. Bekötve a `prepare_validate_convert` jobba, `has_base_diff == 'true'`-nál (2026-08-15 utókövetéssel pontosítva `mode == 'changed'`-ről — lásd a Napló utókövető bejegyzéseit): a `workflow_dispatch`-eredetű bulk módoknak (`all`/`unverified`/`selected`) és az adott ref első pusholásának nincs valódi diff-alapjuk, de egy normál push/PR, ami csak *technikailag* esik `mode=all`-ba (mert egy `rebuild_all_files`-trigger volt a diffben), igenis rendelkezik valódi `base_sha`-val, tehát nála is fut a check, `changed_rule_files`-re szűkítve. `scripts/lib/rule_version.py`, `sigma_to_spl.py` és `generate_stats.py` szándékosan érintetlen maradt: a git-commit-számból mért `rule_version` (a `.meta.json` sidecarban, a Superseded-ellenőrzéshez) és az új, ember által beállított `version:` két külön dolog, egymás mellett — ezt a 2026-08-11-es bejegyzés is így indokolta. Lásd a Napló 2026-08-15-i bejegyzését a bizonyításért.
- [x] **3.6** A `scripts/lib/` alulhasznált (meta IO és verzió 2-2 példányban, nincs `SplunkClient`) · **részben kész 2026-08-06 — a tétel címében megnevezett három dolog közül egyik sincs kész, ezért marad nyitva.** Amit elvégeztünk, az egy negyedik, a cím írásakor még nem létező duplikáció: az `env_bool` **négy** példányban élt (`deploy`, `reconcile`, és a két `verify` script), karakterre azonosan, és a **2.14** ehhez ma **négy további** példányt tett hozzá a TLS-bejelentő blokkból — a kódkommentek ezt nyíltan meg is vallották („Repeated verbatim at all four call sites because env_bool itself is duplicated four times"). Új `scripts/lib/env.py`; a `scripts/lib/` ezzel a `rule_naming.py` mellett **második** modult kapott, vagyis megszűnt egyfájlos könyvtárnak lenni. **A tanulságos rész az, amit *nem* vontunk össze.** Az `env_required` négy példánya csak *ránézésre* volt duplikátum: háromféle bukási móddal bírt — `exit 1` a deployban és a hit-checkben, `exit 2` az indexelés-várásban (mert egy el sem indult lépés setup-hiba, nem mérési eredmény), és `ReconcileError` a reconcile-ban, hogy a `main()` továbbra is el tudja választani a „nem megbízható összehasonlítást" a drift-találattól. Ezek a különbségek **hordozók**, nem véletlenek — a 2.14 bejegyzése maga hivatkozik rájuk. Ezért az **olvasás** került a lib-be, a **politika** a hívónál maradt, egyetlen soron keresztül bekötve (`env_reader(die)`, `env_reader(_fail)`). Egy naiv „vonjuk össze, hiszen ugyanaz" itt csendben elrontotta volna három lépés kilépési kódját. **Bizonyítás:** 35 új teszt (`tests/test_lib_env.py`), köztük egy, ami azt állítja, hogy mind a négy modul `env_bool`-ja **ugyanaz az objektum** — ez az, ami észreveszi, ha valaki visszacsempész egy lokális másolatot —, és három, ami a kilépési kódokat rögzíti; ezen felül valódi CLI-hívásokkal, üres környezettel is ellenőrizve (1 / 2 / 2). **Menet közben javított törékenység:** a `tests/conftest.py` a `scripts/` könyvtárat nem tette a `sys.path`-ra, csak az alkönyvtárait, tehát a `from lib.env import ...` egy *másik* modul importjának mellékhatásaként működött volna, és az importok átrendezésétől elszállt volna. **Egy apró viselkedésváltozás, tudatosan:** a `wait_for_indexing` hibaüzenete `missing required env var`-ról `Missing required env var`-ra váltott, mert a négy szöveg most egy helyről jön. **Hátra van a tétel eredeti tartalma:** a meta IO és a verziószámítás 2-2 példánya, és a `SplunkClient` — utóbbi mind a négy script HTTP-kezelését érinti, ezért érdemben nagyobb és kockázatosabb falat, amihez működő CI kell · **2026-08-11:** a verziószámítás 2-2 példánya a **3.5** alatt megszűnt (`scripts/lib/rule_version.py`) — hátra a meta IO és a `SplunkClient` · **kész 2026-08-12, a maradék két darab, és a hatókör közben nőtt, nem csak megmaradt.** A `SplunkClient` a felhasználóval egyeztetve **függvényre szűkült**, nem osztály lett: a session-építés a három bemenet (felhasználó, jelszó, TLS-mód) tiszta függvénye, nincs hívások közt megosztott állapot, tehát egy osztály fölösleges absztrakció lett volna — ugyanez az elv tartotta ki a retry-t is a hatókörön kívül, mert **ma egyik script sem retry-zik**, és annak bevezetése a tétel bizonyított duplikációja helyett egy nem kért, méréssel alá nem támasztott bővítés lett volna. Új `scripts/lib/splunk_client.py::build_session()`. **A tétel négy scriptet nevezett meg, de mára öt van:** a `check_spl_syntax.py` (item **4.2**) a tétel megírása *után* született, és pontosan ugyanazt a négysoros `requests.Session()`-blokkot másolta be, ami már a másik négyben megvolt — élő bizonyíték arra, hogy a duplikáció nem statikus adósság volt, hanem nőtt, amíg nem volt mit helyette újrahasználni. Mind az öt hívó (`deploy_spl_to_splunk`, `check_spl_syntax`, `check_saved_search_hits`, `wait_for_indexing`, `reconcile`) most ugyanazt a `build_session()`-t hívja. **Menet közben talált, a tétel eredeti szövege által nem nevesített második lelet:** a `search/jobs` végpontok URL-jét **három helyen** (`check_saved_search_hits.py` kétszer, `wait_for_indexing.py` egyszer) kézzel rakták össze — `f"{base_url}/servicesNS/{quote(owner)}/{quote(app)}/search/jobs..."` —, holott a **3.9** alatt megszületett `lib/splunk_ns.namespace_url()` pontosan erre a mintára való; eddig csak a `saved/searches` hívók (`deploy`, `reconcile`) használták. Mindhárom hely most `namespace_url()`-re épül, string-szinten bájtra azonos kimenettel (a meglévő `test_splunk_namespace.py` tesztjei — amik a pontos URL-t vizsgálják — módosítás nélkül zöldek maradtak, plusz egy új identitás-teszt, ami azt rögzíti, hogy a két modul ugyanazt a `namespace_url` függvényt hívja, nem csak véletlenül ugyanazt a stringet gyártja). **A meta IO oldalon a lecke megismétlődött, ezúttal a `env_required`-nál, nem az `env_bool`-nál:** a három Python-olvasó (`deploy`: `die()`, `check_saved_search_hits`: csendes `{}`, `wait_for_indexing`: átugrás) hibapolitikája **szándékosan eltér**, tehát csak a fájl-megtalálás + JSON-parse közös (`lib/meta_sidecar.py::read_meta_sidecar()`, `FileNotFoundError`/`JSONDecodeError`-t dob), mindhárom hívó megtartotta a saját except-ágát. A PowerShell-oldali negyedik olvasó (`run_atomic.ps1::Read-MetaFromSplFile`) **szándékosan nem lett közösítve** — más nyelv, nincs mit megosztani. **Bizonyítás:** 20 új teszt (`tests/test_splunk_client.py`, `tests/test_meta_sidecar.py`, plusz egy a `tests/test_splunk_namespace.py`-hoz), köztük egy-egy identitás-teszt mindkét modulra (`build_session`/`read_meta_sidecar`/`namespace_url` ugyanaz az objektum mind az öt, illetve három, illetve két hívóban) — ez veszi észre, ha valaki visszacsempész egy helyi másolatot —, és a policy-szétválás mindhárom meta-olvasó ágára külön eset (hiányzó/hibás sidecar → `die(1)` / `{}` / átugrás). Teljes `pytest` futtatva előtte és utána: a változtatás előtt is fennálló négy hiba (két, a helyi géptől független ok — hiányzó `Europe/Budapest` tzdata, illetve egy elavult darabszám-teszt a `check_spl_syntax` workflow-lépése miatt) változatlanul megvan, semmi új nem tört el. `ruff` tisztán az érintett és az új fájlokon
- [x] **3.7** Backend lock-in a converterben · `sigma_to_spl.py:14-15,41-47` · **kész 2026-08-06:** új `config/backends.yml` (az adat) és `scripts/convert/backend_config.py` (a loader). A `splunk` blokk értékei **karakterre** azok, amik eddig konstansként a kódban ültek, tehát a fájl a *döntést* mozgatja, nem a viselkedést. Egy második backend hozzáadása konfigurációs kérdés lett, nem kódmódosítás — a tesztek egy `elastic`/`esql` backendet vezetnek be pusztán configból, a `-t esql -p ecs_windows` parancssorig. **Nulla fallback:** nincs beégetett alapértelmezés, amire vissza lehetne esni, és az **ismeretlen kulcsokat is elutasítja** — a `by_services:` elgépelés YAML-ként érvényes, és csendben minden szabályt a default pipeline-ra terelne; a `pipelines.default` pedig kötelezően kiírandó, akár üresen is, mert a „nincs pipeline" **döntés**, nem hiányzó kulcs. A nem található és az olvashatatlan fájl külön hibaüzenet — a `DETECT-2026-0008`-nál tanult karantén-eset miatt: a „missing" félrevezetné azt, aki a logot olvassa. **A betöltés a konvertáló ciklus *elé* került, `exit 2`-vel:** egy félig konvertált `rules/splunk/`-ot a prod drift-kapuja bájtra hasonlít, tehát a setup-hibának az első fájl kiírása **előtt** kell buknia. **A bitre azonosság kétlépcsős bizonyítással:** előbb a `.github/requirements.txt` pinjeivel, **módosítatlan** converterrel reprodukálva a 27 committolt `.spl`-t — enélkül egy eltérést nem lehetett volna a változtatásra vagy a toolchainre visszavezetni —, majd a módosítottal `sha256sum` 27/27, `git status` tiszta. 45 új teszt, ebből 20 hangos-bukás eset. **Menet közben talált plusz hiba, itt javítva:** a dev workflow `paths:` szűrője és a **2.19**-es `rebuild_all_files` tömbje **fájlnév szerint** sorolta fel a `sigma_to_spl.py`-t, tehát sem a `backends.yml`, sem a `backend_config.py` nem szerepelt rajtuk — pedig a config szerkesztése **mind a 27 szabály SPL-jét megváltoztatja**, és ma sem futást nem indított volna, sem teljes újraépítést. Ez a 2.19 karbantartási ára: az explicit lista pontosabb a globnál, cserébe elavul, amint új fájl születik. **Két irányba javítva, szándékosan:** a `paths:` szűrő **globra** bővült (`scripts/convert/**`, `config/**`), mert ott egy téves találat ára *egy olcsó validate-and-convert futás*; a `rebuild_all_files` viszont **explicit lista maradt**, mert ott egy téves találat ára *mind a 27 szabály újratámadása a laboron* — pontosan ez volt a 2.19. **A prod workflow `paths:`-át tudatosan nem bővítettem:** az szándékosan szűk, és a **2.5** kifejezetten azért vezette be a `workflow_dispatch`-et, hogy a nem-szabály jellegű változások kézi újratelepítéssel jussanak prodba
- [x] **3.8** Flat rule-könyvtár — megvizsgálva, elvetve: a repo nem kap alkönyvtár-bontást · **lezárva 2026-08-11, elutasításként, nem megvalósításként.** A tétel két dolgot bundlézott: (1) "27 szabály egy könyvtárban még kezelhető, 150-nél nem" — ez a felhasználó rákérdezésére kiderült, hogy sosem volt tényleg alátámasztva; a rule-böngésző a YAML *tartalma* alapján kategorizál (tactic/technika/log-source szűrők), nem a könyvtárszerkezet alapján, a fájlnevek beszédesek, a fájlrendszer/grep/fuzzy-find több száz fájllal is elbír egy könyvtárban. Felmerült egy `logsource.product_category` szerinti bontás mint kíváncsiságból megbeszélt opció (séma szerint egyértékű, a SigmaHQ upstream mintája), tactic szerinti kifejezetten elvetve (egy szabály jellemzően több `attack.*` taget visel, egy elsődleges tactic-mappa mesterséges lenne) — de a felhasználó a funkciót magát nem kéri a repóba. (2) A "manuális ID-kiosztás" fele valós, konkrét kockázat volt (két párhuzamos branch ugyanazt a szabad ID-t választhatja, semmi nem veszi észre) — ez a **4.5** alatt megoldva, alkönyvtárak nélkül. Mivel mindkét fél eldőlt (az egyik elutasítva, a másik máshol megoldva), a tétel lezárt, nem függőben
- [x] **3.9** ⭐ **A deploy a szolgáltatásfiók privát névterébe ír, ezért minden frissítés árnyék-objektumot hagy** · `deploy_spl_to_splunk.py:387`, `reconcile.py:516`, `check_saved_search_hits.py:224`, `wait_for_indexing.py:141` · **kész 2026-08-08:** a hipotézis kiállta a próbát, de nem abban a formában, ahogy megfogalmaztuk. A `nobody` az **útvonalban** kell, a `set_acl` viszont **marad** — a payload `owner` mezőjében az autentikáló fiók nevével, mert `nobody`-val és a mező elhagyásával egyaránt 403 a válasz. Négy mérés a dev appon, eldobható objektumokon: (1) a fiók névterén create → 1 másolat, update → **2**; (2) `nobody` névtéren create → 1 másolat, **eleve `sharing=app`**, két update után is 1; (3) az ACL-POST háromféleképp: owner nélkül 403, `owner=nobody` 403, `owner=ci_splunk_deploy` **200**; (4) a teljes új sorrend lejátszva (create → ACL → update → ACL → update), minden lépés után wildcard-listázással: végig egy másolat. Ezért **nem** esett ki az ACL-hívás: a `nobody`-val született objektum az app `default.meta`-jából örököl (`write=admin,ci_deploy_savedsearches,power`), tehát a `set_acl` elhagyása csendben tágította volna az írásjogot. Új `scripts/lib/splunk_ns.py` tartja egy helyen a névtér-döntést és a mérést; a `reconcile.py` listázása a `servicesNS/-/<app>` wildcardra állt (ez az egyetlen nézet, ami mindkét réteget látja — a 2.19 duplikátum-észlelése így kap valódi bemenetet), az írásai a deploy névterébe mennek; a `check_saved_search_hits.py` kettévált (`dispatch` → `nobody`, `search/jobs` → a fiók); a `wait_for_indexing.py` **nem változott**, mert csak `search/jobs`-ot hív. Élesben igazolva: két egymást követő dev deploy ugyanarra a szabályra, utána reconcile — 27 név, nulla duplikátum. **Prodban is igazolva, ugyanaznap:** a merge után egy `workflow_dispatch`-elt prod futás mind a 27 szabályt **frissítette** (27 × `Updated:`, 0 × `Created:`) — tehát 27-szer futott le pontosan az a művelet, ami eddig árnyékot hagyott —, és utána a wildcard-listázás **nulla duplikátumot** talált. A kiindulás tiszta volt (a felhasználó a futás előtt törölte az utolsó árnyékot, a `0028`-ét), tehát a régi kóddal ez a futás 27 árnyékot gyártott volna. Ráadásul **egyetlen ACL-figyelmeztetés és egyetlen 409 sem** volt a logban, szemben a tegnapi 26-tal Mind a négy script `owner = SPLUNK_USERNAME`-mel építi a REST-útvonalat, tehát `servicesNS/ci_splunk_deploy/<app>/…`-ra ír. Egy **app-szintű** objektumra ezen az úton írva a Splunk nem azt módosítja, hanem **felhasználói szintű felülíró réteget** készít fölé. Ezért lesz szabályonként két sor a Splunk UI-ban: az élő app-szintű Alert, és egy privát, ütemezetlen Report, ami semmit nem csinál. **A bizonyíték három mérésből áll, egyetlen estéből.** (1) Egy prod futás mind a 27 szabályon: **26 × HTTP 409 frissítésnél, 0 × 409 az egyetlen frissen létrehozottnál** (`DETECT-2026-0003`, előtte kézzel törölve) — a 409 tökéletesen korrelál azzal, hogy az objektum már létezett-e. (2) Kontrollcsoport: ugyanaz a `DETECT-2026-0028` a dev appban (árnyék törölve → nincs 409, egy sor) és a prod appban (árnyék megvan → 409, két sor). (3) **A döntő:** a `0028` a 19:11-es prod futásban `Updated:`-elődött **409 nélkül** (tehát a `set_acl` nem is POST-olt, mert az ACL egyezett), a 19:16-osra viszont már **volt** árnyéka és 409-et kapott. A kettő között egyetlen dolog történt vele: egy frissítés. **Tehát nem a `set_acl` POST hozza létre az árnyékot, hanem a sima update POST.** Következmény: **a kézi takarítás hiábavaló** — az árnyék az első frissítéskor visszajön, és ezt élesben végig is néztük. **Amit ez NEM jelent:** semmi nincs elromolva. A detekciók app-szinten élnek, ütemezettek, tüzelnek, a verifikáció valósat mér; a kár kozmetikai (dupla sor a UI-ban) plusz futásonként 26 warning · **a kézenfekvő fix a `nobody` névtér**, amit a `deploy_spl_to_splunk.py:379-386` kommentje szerint **már megpróbáltak és elbukott** („every ACL update fail … the service account doesn't have `admin_all_objects`") — de az érv **nem feltétlenül áll**: `owner=nobody` mellett az objektum eleve app-szintű, tehát a sharing-promócióhoz a `set_acl` **nem is kell**. A tiltott művelet és a szükséges művelet nem ugyanaz, és a korábbi kísérlet vélhetően megtartotta az ACL-hívást. Ez a hipotézis, amit holnap tesztelni kell · **kockázat:** négy scriptet érint, éles detekciókat mozgat, és `403`-mal bukhat; a `search/jobs` végpontok **nem** kaphatnak `nobody`-t, mert azok futó jobot azonosítanak, nem objektumot (a `nobody` csak a `saved/searches` útvonalakra való) · **alternatíva, ha a `nobody` elbukik:** a `ci_splunk_deploy` fiók `edit_saved_search_owner` capabilityje, ami a Splunk doksija szerint pont az „owner beállítása nobody-ra" művelethez kell

## 4 · Profibb hatás, egyszerűbb folyamat (11) — hatás/ráfordítás szerint

- [x] **4.1** False-positive / noise budget mérése — megvizsgálva, elutasítva: nincs mihez mérni · **lezárva 2026-08-15, elutasításként, nem megvalósításként.** A tétel egy csendes, 24 órás, támadás nélküli ablakon mért `events/day` alapú noise score-t javasolt, séma-oldali `noise_budget` CI-gate-tel. Mielőtt bármit terveztem volna, felhívtam a figyelmet, hogy a mechanika technikailag megépíthető lenne a meglévő `check_saved_search_hits.py` dispatch+hit-count logikájára építve (más `earliest`/`latest` ablakkal, más céllal — nem pass/fail, hanem számlálás) — de a tétel értelme azon áll vagy bukik, hogy van-e a labor Splunkjában valódi, szervezetlen háttérforgalom egy "normál nap" méréséhez. **A felhasználó megerősítette: nincs** — a de-lab Splunk kizárólag attack-teszt futások idején kap adatot, tehát egy csendes 24h ablak mérése minden szabálynál gyakorlatilag nullát adna, ami nem noise-mérés, hanem hamis biztonságérzet lenne. Ugyanaz a minta, mint a **3.8** és a **4.4** elutasítása: a tétel egy éles, folyamatos forgalmú SOC-ra tervezett sablonból származott, és ennek a lab-nak a tényleges Splunk-adatprofilja nem teszi értelmezhetővé. Kód nem változott, csak a register
- [x] **4.2** SPL szintaxis-validáció deploy előtt a Splunk `search/v2/parser` endpointon · **kész 2026-08-11.** Új `scripts/deploy/check_spl_syntax.py`, bekötve a `ci_dev_workflow.yml` `splunk_deploy` jobjába, közvetlenül a deploy lépés elé (ugyanazok a Splunk-credentialok, ugyanaz a fájllista — csak az adott futásban ténylegesen deployolandó szabályok, nem az egész repo, mert ez élő Splunk-hívást jelent, nem helyi ellenőrzést). A tétel eredeti szövege a `search/parser` endpointot nevezte meg, ami a Splunk 9.0.1 óta **elavult** — a Context7-en át lekért aktuális dokumentáció szerint a `search/v2/parser`-t kell hívni helyette; ez derült ki, mielőtt bármit írtam volna, nem utólag. `parse_only=true`-val hívva (csak szintaxis, subsearch/lookup/eventtype/macro-kiterjesztés nélkül — azok környezettől függenek, egy hiányzó lookup miatti bukás hamis pozitív lenne egy tisztán szintaxis-kérdésre). Prodba szándékosan nem került be: a promotion PR csak azután nyílik, hogy a dev már sikeresen deployolt (tehát már átment ezen az ellenőrzésen), a prod pedig a **3.2** build-provenance attesztációjával pontosan ugyanazokat a byte-okat engedi be — egy prod-oldali duplikált ellenőrzés szembe menne a 3.2 "ne validáljunk kétszer" elvével. Lásd a Napló-bejegyzést
- [x] **4.3** MITRE tag-validáció a már cache-elt technique map ellen (nem létező/revoked technika, tactic-mismatch) · **kész 2026-08-06:** új `scripts/validate/check_mitre_tags.py`, bekötve a dev workflow validate jobjába a `check_test_routing.py` mellé. **Miért kellett egyáltalán:** a `docs/schemas/sigma_schema.json` tag-validációja **dekoratív** — a minta egy `anyOf` harmadik ágában ül, ami szabad szöveg, tehát az `attack.t123` átmegy —, a `generate_stats.py` `extract_techniques()` regexe pedig még **lazább a sémáénál** (`attack\.t\d+`), vagyis egy elgépelt technika ma badge-et és Navigator-cellát kap, mintha lefedett lenne. Ez önálló tételként a **2.22**. **Amit kiszűr:** `unknown_technique`, `revoked_technique`, `unknown_subtechnique`, `malformed_technique_tag`, `unknown_tactic`, `tactic_mismatch`; figyelmeztetésként `undeclared_tactic` és `redundant_parent`. Két kaszkád-elnyomással, mert **egy hiba egy találat**: feloldhatatlan technika mellett a taktika-egyeztetés hallgat (a lefedett halmaz hiányos), taktika-hiba mellett pedig a gyengébb állítás (`undeclared_tactic`) nem szólal meg — az első körben tényleg megtörtént, hogy egy elgépelés két találatot adott. **A visszavont/elgépelt szétválasztás őszinte a saját korlátaival:** a `generate_stats.py:328` a cache építésekor **eldobja** a `revoked`/`deprecated` objektumokat, tehát egy visszavont technika ugyanúgy *hiányzik*, mint egy elgépelés. Al-technikánál a sűrű számozás még elválasztja őket (a szülő kiosztott sávján belül = kiosztott és visszavont, fölötte = kitalált), **fő technikánál viszont a script nem állít semmit** — ott a 222 élő ID ritkasága mellett a tipp lenne találatnak öltöztetve. **Nulla hálózati hívás:** a committolt `outputs/reports/mitre_technique_map.json`-t olvassa (222 technika + 475 al-technika, 15 taktika), és egy teszt **a forráson** őrzi, hogy ne kerüljön bele `urllib`/`requests`/`socket` — a nap, amikor valaki fallback fetch-et tesz bele, az a nap, amikor a check rossz okból kezd zöldülni. Hiányzó vagy romlott cache esetén `exit 2`: **elutasítja a jelentést** ahelyett, hogy mind a 27 szabályt hibásnak mondaná. **Az `attack.stealth` nem kivételként érvényes:** a taktika-szótár **magából a cache-ből** épül (30 technika mondja magát Stealth-nek), nem egy beégetett upstream listából — az a szabályok harmadát hibásnak jelentené az első futáson; e fölé került egy explicit kivétel is, hogy egy csonka cache se tudja találattá tenni. **A CI-ban tanácsadó, `--strict` nélkül:** egy rossz tag rossz helyre teszi a detekciót a mátrixon, de nem rontja el, és a szabály deployolandó, miközben a tagjéről vitatkozunk; piros annotáció egy 0-val kilépő lépésen leszoktatna az annotációk olvasásáról. **Minden szabályt néz, nem csak a változottakat**, a routing-checkkel azonos okból: amit egy taget érvénytelenít, az rendszerint upstream történik, nem ebben a pushban. **A 27 valós szabály mind tiszta**, 0 hiba, 0 figyelmeztetés — és mivel a „megvan a script" nem eredmény, negatív kontrollal igazolva: kitalált `T9999`, elgépelt `T1003.099`, `Impact` mismatch és `attack.t123` mind pontosan egy találatot ad a saját osztályában, `--strict`-tel exit 1, az érintetlen szabály exit 0. 38 új teszt. **Nem való a 2.19-es újraépítés-listára**, mert egyetlen `.spl`-t sem befolyásol
- [x] **4.4** Splunk ES / RBA a deploy payloadban — megvizsgálva, elutasítva: nem indokolt · **lezárva 2026-08-15, elutasításként, nem megvalósításként.** A tétel eredetileg két, minőségileg eltérő dolgot bundlézott. **Az ES/RBA fele (risk score mapping, notable event action) hamis feltevésen alapult:** a repóban sehol semmi nyoma, hogy Splunk Enterprise Security egyáltalán telepítve lenne ebben a lab-környezetben (nincs `notable`/`risk_object`/`risk_score` index-hivatkozás sem a sémában, sem a deploy-scriptben, sem a docs-ban) — ES nélkül a risk-score/notable-event mezők egyszerűen hatástalanok lennének. **A throttling+drilldown fele (`alert.suppress`/`alert.suppress.period`, `alert.display_view`) technikailag valós, ES-független Splunk funkció lenne** — a Context7-en át lekért aktuális REST-dokumentáció szerint konkrétan megvalósítható —, de a felhasználó rákérdezésére kiderült: ebben az egyszemélyes lab-környezetben, ahol nincs SOC, ami a zajt kezelné, sem a throttling (nincs, aki a duplikált riasztásoktól szenvedne), sem a drilldown (a saved search már ma is a helyes app-namespace-be íródik, a Splunk Web natívan a helyes kontextusra visz) nem old meg valós problémát. Mindkét fél tudatosan lezárva, nem implementálva
- [x] **4.5** `new_rule.py` scaffolder + ütközésvédelem · **kész 2026-08-11.** A tétel eredeti szövege még egy `Makefile`-t (`make validate`/`convert`/`stats`/`check`) és egy ATT&CK-technikához tartozó atomic-teszt-szám kikeresést is felsorolt — a felhasználó ezt a két darabot kifejezetten nem kéri a repóba, tehát a tétel a ténylegesen kért hatókörrel (scaffolder + ütközésvédelem) zárva. Új `scripts/new_rule.py`: a következő szabad `DETECT-<év>-NNNN`-t a `lib.rules.discover()`/`load_rule()`/`detect_id()`-re építve számolja (soha nem tölt ki lyukat — egy visszavont ID újrahasznosítása régi verdikt-history-t/coverage-pontokat keverne össze), a szerzőt `git config user.name`-ből olvassa, és egy séma-konform TODO-skeletont ír ki. Új `scripts/validate/check_detect_id_uniqueness.py`, bekötve a `ci_dev_workflow.yml`-be (`check_test_routing.py` és `check_mitre_tags.py` közé) — ez a tényleges védőháló, mert a scaffolder csak a helyi checkoutot látja, két párhuzamos branch ugyanarról a base commitról ugyanazt a "következő szabad" ID-t számolhatja ki. Lásd a Napló-bejegyzést
- [ ] **4.6** Per-rule verdict history (append-only `history.jsonl`) a „flaky / mikor romlott el" kérdésekhez
- [x] **4.7** Deployment inventory a dashboardon (dev/prod hol él, milyen verzióval) — a 3.3 kimenetéből · **kész 2026-08-08:** az adat mindig megvolt, csak eldobtuk — a deploy riportja (2.4) és a reconcile kimenete (3.3) is `.gitignore`-olt könyvtárba írt és artifactként utazott, a dashboard viszont repo-fájlokból generálódik. **1. fázis:** új `scripts/state/deployment_inventory.py`, desztillált leltár (változatlan futáson bájtra azonos, tehát nem keletkezik commit), környezetenként **merge-el**, nem felülír; a dev deploy végre kap `--report`-ot, és a leltár a commit-lépésben, a `git reset --hard` **után** épül fel, mert a bemenetei `.gitignore`-oltak. **2. fázis:** új `ci_prod_audit.yml` — naponta 05:40 és kézre, reconcile a prod appra **csak olvasva** (se `--apply`, se `--apply-removals`: ütemezetten futó dolog nem szüntethet meg éles detekciót), sodródásra `::warning`, nem bukó futás. A workflow **két jobra vált**, és ez jogosultsági határ: a `dev` ág védett és az `enforce_admins` ki van kapcsolva, tehát a `GITHUB_TOKEN` nem tud rá írni, a PAT viszont a `dev` environmenthez kötött, amit egy `environment: prod` job nem lát — így a prod-oldali job olvas és sehova nem ír, a dev-oldali írja a repót és a Splunkhoz nem nyúl. **Dashboard:** szerver-oldalon renderelt panel (a `page.js`-hez nem nyúl), ami leltár nélkül meg sem jelenik, és külön sorban mondja meg, mit küldtünk és mi van ott. **Élesben igazolva, két futásban** — és az első kihozta, hogy a tétel fele nem működik: a prod „melyik commitból települt" adata csendben elveszett, mert a `last_deploy` csak deploy-riportból épült, a prodnál viszont az Actions API a forrás. Javítva; a második futás után a leltárban ott a prod commitja, időpontja és a CI-futás linkje, a prod pedig 27/27 in sync
- [ ] **4.8** A `rule_documentations/` generálása a `stats.json`-ból (runbook-oldal szabályonként)
- [x] **4.9** A promotion PR body-ja legyen érdemi: per-szabály breakdown · `ci_dev_workflow.yml:814` · **kész 2026-08-11:** az `open_promotion_pr` job `gh api compare/main...dev`-vel megnézi, mely szabály-fájlok változtak, a `detect_id`-ket a fájlnevekből szedi ki, és a már úgyis lekért `stats.json`-ból (4.11) kikeresi mindegyik cím/szint/verdiktjét — tábla a PR body-ban és a step summary-ban, csak a ténylegesen promotált szabályokra. Best-effort a `stale_count`-tal azonos mintán, helyi bash-teszttel ellenőrizve élesítés előtt (dedup, nem-szabály fájl kiszűrése, hiányzó `detect_id`, üres diff, üres `stats_json` — mind hibakód nélkül üres táblát ad)
- [x] **4.10** Saját CI a pipeline-ra: ruff, pytest, actionlint, PSScriptAnalyzer, shellcheck, pip-audit · **kész 2026-08-04, mind a hat eszközzel.** 2026-08-03: `ci_code_checks.yml` ruff + pytest-tel (pinelve a `.github/requirements-dev.txt`-ben), az 1.6-ot lezárva; majd PSScriptAnalyzer külön `powershell_analysis` jobban (parse check + analyzer, pin 1.25.0). 2026-08-04: új `workflow_analysis` job **actionlint 1.7.12**-vel, checksum-ellenőrzött letöltéssel — és vele a **shellcheck** is, mert az actionlint maga futtatja minden `run:` blokkon (külön shellcheck-step nem tudná kinyerni a scripteket a YAML-ből); plusz `dependency_audit` job **pip-audit 2.10.1**-gyel, **`continue-on-error`-ral**, mert egy éjjel publikált CVE különben minden független PR-t pirosra váltana. A hatból négy eszköz **kapu**, a pip-audit riport
- [x] **4.11** Az elévülés riportálási korrekció, nem kapu — a `splunk_verify` exit kódja és a promotion PR gate csak az adott futás szabályait látja, azok verdiktje pedig definíció szerint friss, így egy lejárt vagy felülírt verdiktű szabály **soha nem blokkolja a promóciót**, és mérés nélkül ülhet prodban akármeddig · **kész 2026-08-10:** riportálás, nem tömeges újramérés és nem gate — mindkettőt felvetettem, a felhasználó mindkettőt elutasította, mert 500+ szabálynál nem skálázna, és pont ezért létezik a dashboard Evidence-jelölése: a szelektív, kézi újrafuttatás legyen a mechanizmus, ne egy automatikus tömeges. A tényleges hiány nem a mérés hiánya volt — a `stats.json` `verified_expired`+`verified_superseded` számlálója már megvolt, csak a dashboardon élt, senki nem látta promóció pillanatában. Az `open_promotion_pr` job (`ci_dev_workflow.yml`) mostantól a Contents API-n (nem checkout-tal, hogy a job „egy maréknyi `gh` CLI hívás" jellege megmaradjon) kiolvassa a `splunk_verify` által ugyanabban a futásban frissen legenerált `stats.json`-t a `dev` HEAD-ről, összeadja a két számlálót, és ha `>0`, egy GFM `[!WARNING]` blockquote-ot told a PR body végére és a step summary-ba (a `scripts/lib/summary.py` `MARK_WARN`/`ALERT_WARN` konvencióját követve kézzel, mert bash nem importálja), plusz egy `::warning::` annotációt az Actions futás oldalára. Sem blokkol, sem újratesztel semmit. Best-effort: a Contents API hívás hibája (jogosultság, hálózat) csendben 0-ra esik vissza `set -e` alatt is, nem buktatja a PR nyitást — mockolt `gh`/`jq`-val három ágat (van elévült / nincs / API-hiba) ellenőrizve helyi bash-teszttel, a PR body/step-summary formázását (blockquote, sorvégek) is beleértve, mielőtt élesben futna

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
  fájlon formázási véleményekbe fojtaná a valódi hibákat — a bővítés a **2.12** alatt maradt, és
  ott 2026-08-06-án meg is történt; a szűk beállítás így is talált egy használatlan `sys` importot), 25 pytest teszt a mai 1.4-es és
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
- **2026-08-07** — **3.1 kész, de a tétel megfogalmazása elavult volt**, és ezt a felmérés derítette
  ki, mielőtt bármi épült volna. A leírt fix (`manifest.json` + `jq`, ≈60-80 sorral rövidebb dev
  workflow) ma nem kivitelezhető, mert nincs mit kivenni: a workflow semmilyen szabály-metaadatot
  nem parse-ol. A valódi duplikáció eggyel feljebb volt — **hat script négyféleképp** döntötte el,
  mely fájlok számítanak szabálynak, és ez ma csak azért egyezik, mert a `rules/sigma/` véletlenül
  lapos. A részletek a tételnél; a lényeg, hogy ez **a 3.8 előfeltétele** volt: egy almappa
  bevezetése a régi kóddal a `prune_orphans --apply` miatt **adatvesztéssel** járt volna, és ezt
  reprodukáltam is. Tanulság a registerre nézve: a 2026-07-26-i felvétel óta eltelt idő nem csak
  *lezárja* a tételeket, hanem **el is mozdítja őket** — a 3.1 esetében a cím maradt igaz, a
  diagnózis és a fix nem. Érdemes minden nagyobb tétel előtt újramérni, mielőtt a leírt fixet
  elkezdenénk építeni.
- **2026-08-07** — Nem audit-tétel, de ugyanezen a napon: **egységes summary-jelkészlet**
  (`scripts/lib/summary.py`), mert öt író használt saját címszintet, saját emojit és saját escape-
  szabályokat. Két hiba is kiderült közben: a deploy escape nélkül írta a Splunk hibaszövegét egy
  táblázatcellába (az JSON, a JSON tartalmazhat `|`-t, ami elcsúsztat minden utána jövő oszlopot),
  és a `pass_fail_eval.py` `write_text()`-tel **felülírta** a summary fájlt hozzáfűzés helyett.
  A NOT VERIFIED lábjegyzet feltételes lett — eddig minden tiszta futásban is kiíródott.
  **A jelekkel két kört futottunk:** először szöveg-glifák (`✓`/`✕`/`?`), mert a `✅` túl nehéz és
  szétcsúsztatja az oszlopot — élesben viszont kiderült, hogy túl halkak, a verdikt beleveszett a
  szomszédos mondatba. Végül színes körök (🟢/🔴/🟡/⚪): egyforma szélesek, tehát az oszlop egyenes
  marad, és megegyeznek azzal a három színnel, amit a `docs/index.html` már ma is használ ugyanerre
  a három verdiktre. Tanulság: ezt a döntést **rendereléssel kellett volna kezdeni**, nem érveléssel.
- **2026-08-07** — **Az ACL 409 megszűnt, és ami alatta volt, az fontosabb.** A `set_acl()` vakon
  POST-olt; a Splunk egyszer emeli app-scope-ba az objektumot, utána HTTP 409 „Cannot overwrite
  existing app object" — szabályonként és futásonként egy, teljes futáson 27, mind azt jelentve
  hogy „már jó". A zaj volt a kisebbik fele: ugyanaz a 409 jött vissza akkor is, ha az ACL jó volt,
  és akkor is, ha nem, tehát a deploy **sosem tudta korrigálni a valódi ACL-driftet** — egy
  `SPLUNK_PERMS_READ` átírás után a meglévő objektumok örökre a régi jogosultságokat tartanák, és az
  egyetlen jelzés ugyanaz a warning lenne, amit mindenki megtanult átgörgetni. Most előbb GET, aztán
  döntés; a 409 mostantól valódi találat, saját szöveggel. Az olvashatatlan ACL nem „már jó", hanem
  „nem tudom" — ott a régi viselkedés marad.
- **2026-08-07** — **A Splunk-oldali „duplikátumok" nyomozása, és amit közben a mérésről tanultunk.**
  A deploy minden futásban `ACL update failed HTTP 409: "Cannot overwrite existing app object"`-et írt
  szabályonként. A javítás nem a warning elnyomása lett, hanem hogy a `set_acl()` **olvasson írás
  előtt**: egyező ACL-nél nincs írás és nincs üzenet, eltérőnél megy a POST, és ha ott jön 409, az
  mostantól valódi találat, ami kimondja mi a jelenlegi és mi a kívánt állapot. Ez tette láthatóvá a
  tényleges helyzetet: `Current: sharing='user'`, nem az, amit a Splunk hibaszövege sugallt.
  **Három hipotézisem volt rá, kettő téves.** Először azt állítottam, hogy a privát objektumok az élő
  detekciók és az app-szintűek inert reportok — a felhasználó Splunk-listája ennek pont az
  ellenkezőjét mutatta. Aztán azt, hogy a `nobody` névtérre kell váltani — amire a
  `deploy_spl_to_splunk.py:379-386` **már ott lévő kommentje** válaszolt: azt megpróbálták, és a
  szolgáltatásfiók `admin_all_objects` hiányában minden ACL-frissítést elbukott vele. A tanulság
  nem az, hogy hipotézist felállítani hiba, hanem hogy **a repo már tartalmazta a cáfolatot**, és
  előbb kellett volna elolvasni, mint javasolni.
  A végén a felhasználó kísérlete döntött: egy objektumot törölve **a másik is eltűnt** — vagyis
  nem két objektum volt, hanem egy, két megjelenített konfigurációs réteggel. Friss telepítés után
  egyetlen sor jött vissza, 409 nélkül. **Bizonyítva nincs**: a döntő `Created:` sort a deploy
  logjában sosem láttuk, mindkét futás `Updated:`-et írt. A most bevezetett duplikátum-riport az,
  ami ezt legközelebb magától megválaszolja.
- **2026-08-07** — **A prod állapotáról a pipeline semmit nem tud — ez a 4.7 konkrét példája.**
  A `DETECT-2026-0003` kézzel törölve lett a prod Splunk appból. A dev futás lement, a promotion PR
  megnyílt és mergelődött — a prod deploy mégsem indult el, és a szabály nem került vissza. Ez
  **helyes viselkedés**: a prod workflow `paths:` szűrője szándékosan szűk (`rules/sigma/**` és a
  saját fájlja), a merge viszont csak `README.md`-t, `docs/index.html`-t és `outputs/**`-ot vitt át,
  mert a szabály maga nem változott, csak újra lett mérve. Pontosan az az eset, amiért a **2.5** a
  `workflow_dispatch`-et bevezette. **A tanulság nem a triggerről szól, hanem arról, hogy az eltérés
  láthatatlan volt.** A prod eggyel kevesebb szabályt tudott, és erről a repo nem tudott (semmi nem
  változott benne), a reconcile nem tudott (csak a dev appot nézi), a dashboard nem tudott (nincs
  deployment inventory). Egyedül az tudta, aki törölte. Ha egy telepítés csendben bukik el, vagy más
  töröl, ma semmi nem szól. A **4.7** eddig „jó lenne látni"-ként volt megfogalmazva; ez a nap
  megmutatta, hogy inkább hiányzó visszacsatolás egy egyirányú telepítési láncban.
- **2026-08-07** — **Az ACL-409 megoldva: egy önfenntartó hurok volt, és a lezárást három mérés adta,
  nem érvelés.** Egyetlen prod futás mind a 27 szabályt telepítette, és a minta tökéletes: **26 × 409
  frissítésnél, 0 × 409 az egyetlen frissen létrehozottnál** (`DETECT-2026-0003`, amit a felhasználó
  előtte kitörölt). Mellé egy kontrollcsoport: ugyanaz a `DETECT-2026-0028` a **dev** appban, ahol az
  árnyék egyszer törölve lett — ott azóta nincs 409 és egy sor van; a **prod** appban, ahol az árnyék
  megmaradt, két sor és 409. Ugyanaz a szabály, két app, ellentétes állapot, és a különbség egyetlen
  kézi törlés.
  A hurok: egy privát stanza ül az objektum fölött → a `read_acl` a `servicesNS/<user>/<app>` úton
  **azt** oldja fel, tehát `sharing='user'`-t lát → eltérést állapít meg → POST-ol → a Splunk
  elutasítja (409), és közben fenntartja a privát stanzát → vissza az elejére. Friss létrehozásnál
  nincs mit feloldani, a promóció sikerül, árnyék nem keletkezik.
  **Amiért ez lezárja az ügyet, és nem csak elnémítja:** a mai `set_acl` read-before-write javítás
  egyező ACL-nél **egyáltalán nem POST-ol**, tehát az árnyék egyszeri eltávolítása után a hurok 4.
  lépése soha nem következik be. A javítás eredetileg a zaj ellen készült; kiderült, hogy egyben ez
  akadályozza meg az árnyék visszaépülését is. Ez szerencse volt, nem tervezés.
  **Amit ez a nap a módszerről tanított:** négy hipotézisem volt (privát objektumok az élők; `nobody`
  névtér; konfigurációs réteg; önfenntartó hurok), és csak a negyedik állta ki a próbát. Mindegyiket
  a felhasználó Splunk-listája döntötte el, nem a kódolvasás — a `Created:` és a 409 együttállása
  egyetlen futásban többet ért, mint az összes addigi következtetés. A tanulság nem az, hogy ne
  legyen hipotézis, hanem hogy **a mérés olcsóbb volt, mint az érvelés**, és hamarabb kellett volna
  odafordulni.
- **2026-08-08** — **3.9 kész. A tegnapi tanulságot alkalmaztuk: előbb mérés, aztán kód.** A négy
  éles script átírása helyett először három eldobható próba ment a dev appra, `PROBE-` nevű
  objektumokon, mindegyik `finally`-ben takarítva. **(1)** Kontroll kar és hipotézis kar egymás
  mellett: a fiók névterén create → 1 másolat, update → **2**; a `nobody` névtéren create → 1
  másolat és **eleve `sharing=app`**, két update után is 1, 409 nélkül. A tegnapi mechanizmus tehát
  kontrollált körülmények között újra előállt, a fix pedig működik. **(2)** A B2 kar megmagyarázta,
  miért bukott el a korábbi `nobody`-kísérlet: a `set_acl` POST `owner=nobody`-val **403**, szó
  szerint az a mondat, amit a `deploy_spl_to_splunk.py:379-386` kommentje őrzött. A megfigyelés
  helyes volt, a következtetés nem — nem a névteret kellett elvetni, hanem az ACL-payloadot javítani.
  **(3)** A második próba ezt élezte ki: owner nélkül 403, `owner=nobody` 403, `owner=<fiók>`
  **200**, és a jogosultság tényleg átáll. **(4)** A harmadik próba a *megírandó* logikát játszotta
  le végig, minden lépés után wildcard-listázással: végig egy másolat.
  **Amit a mérés megmentett:** a tétel eredeti fixe („`set_acl` nélkül") elsőre helyesnek látszott,
  és csendben tágította volna az írásjogot. A `nobody`-val született objektum ugyanis az app
  `default.meta`-jából örököl — mérve `write=admin,ci_deploy_savedsearches,power`, szemben a
  konfigurált `admin,ci_deploy_savedsearches`-sel. Egy ACL-lazítás, amiről semmi nem szólt volna,
  egy kozmetikai hiba javítása közben.
  **A pontos megfogalmazás, ami eddig hiányzott:** a `nobody` az *útvonalban* kell, mert az útvonal
  dönti el, melyik konfigurációs rétegbe ír a POST; a *payloadban* viszont tilos, mert ott
  tulajdonosváltásnak olvassa a Splunk. A régi komment ezt a kettőt mosta össze, és a helyes
  megoldást vetette el a rossz okból. Ez az egy mondat az egész tétel.
  **Kód:** új `scripts/lib/splunk_ns.py` (a névtér-döntés és a mérés egy helyen, három script
  használja); `deploy_spl_to_splunk.py` create/update/ACL → `nobody`, ACL-payload → a fiók;
  `reconcile.py` listázása → `servicesNS/-/<app>` wildcard, írásai → a deploy névtere, az `owner`
  változó megszűnt; `check_saved_search_hits.py` kettévált (`dispatch` → `nobody`, `search/jobs` →
  a fiók); `wait_for_indexing.py` **érintetlen**. Új `tests/test_splunk_namespace.py` hat teszttel —
  köztük egy, ami azt rögzíti, hogy a `wait_for_indexing.py` szándékosan *nem* mozdul, mert az a
  legkézenfekvőbb fájl, amit valaki „szintén megjavítana". `ruff` tiszta, 443 teszt zöld.
  **Élesben:** ugyanaz a szabály kétszer telepítve a dev appba az új kóddal — a második az a
  frissítés, ami eddig árnyékot rakott le —, utána reconcile: 27 név, nulla duplikátum.
  **Prodban is lezárva, még aznap este.** A merge után a prod deploy **nem indult el magától** — a
  workflow `paths:` szűrője csak `rules/sigma/**`-ra tüzel, mi pedig scripteket módosítottunk. Ez
  pontosan az az eset, amire a **2.5** a `workflow_dispatch`-et bevezette, és a workflow saját
  kommentje szó szerint leírja („a javítás ott alszik, amíg valaki hozzá nem nyúl egy szabályhoz").
  Egy dispatchelt futás a teljes könyvtárat telepíti, tehát pont az kellett.
  A kísérlet közben **erősebb lett, mint ahogy terveztük**: a felhasználó a futás előtt törölte az
  utolsó megmaradt árnyékot (a `0028`-ét), tehát a kiindulás tiszta volt. Így nem azt mértük, hogy
  „a meglévő egy árnyék nem szaporodott", hanem azt, hogy **27 frissítés nulla árnyékot hagyott**:
  a futás 27 × `Updated:`-et írt, 0 × `Created:`-et — vagyis 27-szer futott le pontosan az a
  művelet, ami a defektust okozta —, a listázás pedig utána **nulla duplikátumot** talált. A régi
  kóddal ugyanez a futás 27 árnyékot gyártott volna.
  **Mellékbizonyíték a hurokra:** a logban **egyetlen ACL-figyelmeztetés és egyetlen 409 sem** volt,
  szemben a tegnapi 26-tal. Az ACL-olvasás a `nobody` úton az app-szintű ACL-t oldja fel, egyezést
  lát, és nem POST-ol — a zaj tehát nem elnémítva lett, hanem okafogyottá vált.
  **Mellékesen mért, de érdemes:** a privát árnyék `is_scheduled=false`, hiába van cron mezője —
  ezért látszik reportként és nem alertként, és ezért nem is csinál semmit. A prod 409-zaja
  ráadásul a takarítás *előtt* megszűnik: az ACL-olvasás a `nobody` úton az app-szintű ACL-t oldja
  fel, egyezést lát, és nem POST-ol.

- **2026-08-08 (este)** — **4.7 kész, két fázisban, és az éles futás kihozta, hogy a fele nem
  működik.** A tétel nem hiányzó feature volt, hanem egy **meghozott döntés**: a `.gitignore`
  kimondja, hogy a deploy riportja és a reconcile kimenete „egy pillanatnyi Splunk-állapot, nem a
  repóé", ezért artifactként utazik. Az indoklás jó, csak túl széles — egy per-futás dump tényleg
  semmit nem mond a kódról, egy **desztillált leltár** viszont mást mond, és változatlan futáson
  bájtra azonos, tehát commit sem keletkezik. Ezt a feszültséget oldottuk fel, nem kerültük meg.
  **A két fél, amit a tétel szövege összemosott:** az (a) leltár azt mondja meg, *mit küldtünk*, a
  (b) sodródás-figyelés azt, *mi van ott*. A 08-07-i kézi törlést csak a (b) fogta volna meg, a
  08-08-i „a merge nem ért ki prodba" esetet csak az (a). Mindkettő elkészült.
  **Amit a jogosultságok kikényszerítettek, és amire nem számítottam:** a prod audit eredetileg egy
  jobból állt volna. Ellenőrzés közben derült ki, hogy a `dev` ág védett, az `enforce_admins` ki van
  kapcsolva (ezért megy át az én pushom, adminként), és hogy a dev pipeline pont ezért használ
  `GH_PAT_DEV_PUSH`-t. A `GITHUB_TOKEN` nem admin — a commit-lépés **minden éjjel 05:40-kor
  elbukott volna, úgy hogy senki nem nézi.** A PAT viszont a `dev` environmenthez kötött, amit egy
  `environment: prod` job nem lát. Így a környezetek ott vágták ketté a munkát, ahol a jogok is: a
  prod-oldali job olvas és sehova nem ír, a dev-oldali írja a repót és a Splunkhoz nem nyúl. Ez a
  szerkezet nem tervezés volt, hanem egy ellenőrzés mellékterméke.
  **Az első éles futás verdiktje:** minden lépés zöld, a prod 27/27 in sync — és a leltárban
  `no deploy recorded` egy hónapok óta telepített környezetre. A workflow kikérte az API-tól a
  commitot, át is adta; a script viszont a `last_deploy` blokkot csak deploy-riportból építette.
  Pontosan az az adat veszett el, ami a 08-08-i néma rést láthatóvá tette volna. A második futás
  után rendben: commit, időpont, CI-link. **A tanulság ugyanaz, mint a 3.9-é volt, csak fordítva:
  ott a mérés olcsóbb volt az érvelésnél, itt a mérés az egyetlen, ami megmondta, hogy a saját
  javításom fele nem működik.** Egy „minden teszt zöld" ezt nem fogta volna meg, mert a hiányzó
  ágra nem volt teszt — most van, három is.
  **Ami még nyitva van, de nem hiba:** a leltár dev szekciója az első dev futáson jelenik meg, a
  napi 05:40-es audit pedig a `main`-re kerüléssel kapcsolt be (a `schedule:` csak a default ágról
  él). A panel addig is helyesen viselkedik: amiről nincs adat, arról nem állít semmit.

- **2026-08-09** — **4.7 dashboard: a per-szabály tábla csak a szabálynevet mutatta, méréssel
  javítva.** A felhasználó a 4.7 eredeti kérését tesztelte élesben (Detect ID + dev/prod verzió +
  vizuális jelzés a cellán belül), és azt találta, hogy a `repo`/`dev`/`prod` oszlopok nem
  látszanak — ugyanaz a tünet, amit két korábbi vak CSS-javítás nem oldott meg
  ([[project-deployment-table-layout]]). Böngésző-automatizálással megmért tényleges pixelértékek
  találták meg a valódi okot: egy oldal-szintű `table { table-layout: fixed; }` szabály (a fő
  szabály-böngésző rácsához írva) csendben felülírta a `.dep-rules` táblán a `width:1%`/
  `max-width:0` szélesség-trükköt, ami csak `table-layout: auto` alatt működik — fixed layout alatt
  a böngésző az első sor deklarált szélességei alapján osztja szét a helyet, a tartalomtól
  függetlenül, ezért az érték-oszlopok pár pixelre lapultak. Egysoros javítás: `table-layout:auto`
  a `.dep-rules`-on. Ezután kiderült, hogy a szélesség-trükk maga is felesleges volt — a
  `detect_id` fix formátumú, sosem kell törnie —, és helyette `width:fit-content`-tel a tábla a
  tartalmához igazodik, nem a kártya teljes szélességéhez, ami megszüntette a nagy üres helyet az
  ID és az értékek között.
  **Vizuális kérés, ugyanabban a menetben:** a felhasználó nagyobb és mozgó vonalat kért a statikus
  csík helyett. Egy tényleges kis EKG-hullám (`clip-path` szalag, `transform: translateX()`-szel
  csúsztatva) váltotta a korábbi szín-csíkot; élő = zöld normál pulzus, sodródik = borostyán
  gyorsabb pulzus, eltűnt = piros egyenes vonal mozogva a meglévő vaku-villogás alatt (szó szerint
  „leállt a szív"), hiányzik/nem ismert = szándékosan mozdulatlan (azok a tudásunkról szólnak, nem
  az élő állapotról). **Két zsákutca vezetett a végső megoldáshoz, mindkettő méréssel zárva:**
  `mask-image` egy SVG-csempével látható szakadást hagyott a periódusok között, de csak animáció
  közben — egy statikus, egymás mellé tett 5 példányos ellenőrzés mindkétszer hibátlannak tűnt.
  Sima ismétlődő `background-image` ugyanígy szakadt, csempeszélesség és doboz-szélesség minden
  kombinációjában. A `clip-path` + `transform` végleges, mert nincs kép, amit a renderelőnek
  csempéznie/összeillesztenie kellene — hat animációs fázisban, képpontról képpontra ellenőrizve,
  a vonal folytonos.
  **Amit ez a tétel nem old meg:** a dashboard `dev` oszlopa a publikált oldalon üres, mert a repóba
  committolt `deployment_inventory.json`-ban jelenleg csak `prod` szekció van — a `dev` szekciót a
  dev workflow saját deploy+reconcile futása tölti fel, amit a `paths:` szűrő csak
  szabály-/converter-/deploy-script-változásra indít el, dokumentáció- vagy CSS-változásra nem.
  Ez a mai commit nem indította el; a felhasználó saját maga intézi a dev workflow indítását.

- **2026-08-09 — 3.2 lezárva: digest-alapú build-provenance a re-konverzió helyett, három
  lépcsőben, ugyanaznap talált és javított hibával.** A tétel gyökere ugyanaz volt, amit az **1.3**
  már 2026-08-03-án névvel illetett, de tünetileg kezelt: a prod nem bízik a dev által már
  ellenőrzött `.spl`-ben, hanem újra legyártja a Sigma forrásból, és a kettőt összeveti. Ez csak
  *önkonzisztenciát* bizonyít („ez megegyezik egy újrakonverzióval"), nem *eredetet* („ezt tényleg a
  legitim pipeline gyártotta") — egy elég motivált, commit-joggal rendelkező szereplő kézzel is
  tudna egyező bájtokat gyártani, és a régi gate ezt észrevétlenül átengedte volna.
  **A megoldás GitHub natív, Sigstore-alapú build-provenance attesztációja**
  (`actions/attest-build-provenance`): a dev workflow a saját OIDC-identitásával aláírja minden
  `.spl` tartalmi hash-ét, a prod pedig (`gh attestation verify --signer-workflow
  ci_dev_workflow.yml`) ezt ellenőrzi újrakonverzió helyett. **Három biztonsági tulajdonságot
  direktben teszteltem, nem feltételeztem** — mielőtt élesbe került —: rossz signer-workflow-ra
  mutatás, rossz signer-repóra mutatás, és kézzel módosított fájltartalom mind helyesen
  elutasításra került.
  **Lépcsőzetes bevezetés, mindegyik ugyanaznap élesben bizonyítva.** *A szakasz* (dev aláír,
  additív, semmit nem érint prodban) — utólagos backfill-lel mind a 27 meglévő szabályra. *B
  szakasz* (prod ellenőriz, de nem blokkol, a régi gate mellett fut) — egy teljes lefedettségű
  (27/27) valós deployon (run 31311925932) nulla hamis pozitív/negatív. *C szakasz* (a régi
  újrakonvertálás+diff gate törölve, prod már nem telepíti a Sigma-toolchaint, az ellenőrzés
  blokkolóvá vált) — csak ez után derült ki, hogy a `.meta.json` sidecar-oknak *muszáj* valahonnan
  jönniük a prod runneren (gitignore-oltak, sosem committolva), amit korábban éppen a törölt
  újrakonvertálás állított elő mellékesen; a pótlás a dev bundle-jéből való letöltés lett.
  **Az első Stage C futás (run 31314423690) elbukott, és ez a mérés bizonyította, nem az érvelés:**
  a `.bundle-provenance.json` mindig az *utolsó* dev-futásra mutat, egy célzott,
  egy-szabályos (`DETECT-2026-0019`) dispatch bundle-je pedig csak azt az egy szabályt
  tartalmazta — a prod minden más szabálynál hiányzó sidecar-on halt el, a Splunk-írás *előtt*,
  tehát éles kár nem történt. **A felhasználó két, egymástól független, előremutató észrevétele
  ugyanabban a menetben:** (1) a nyilvánvaló javítás — minden szabály újrakonvertálása minden
  futáson, ahogy a törölt gate tette — nem skálázna 150–400 szabálynál; (2) a `gh attestation
  verify` soros hívásai (~5mp/fájl, mérve) szintén nem fenntarthatók nagyobb szabálykönyvtárnál.
  Mindkettőre kész megoldás, ugyanaznap: új `--meta-only` mód a konverterben (a metaadat-építés
  független a drága `sigma-cli` subprocess-hívástól, csak a már beolvasott YAML-t használja), amivel
  a dev pipeline minden futáson olcsón frissíti a *nem érintett* szabályok sidecar-ját is — a drága
  teljes konverzió változatlanul csak a ténylegesen módosítottakra korlátozódik, tehát a lefedettség
  garantált, a skálázhatóság nem sérül; és 8-utas párhuzamosítás a attesztáció-ellenőrzésre
  (~140mp → ~20mp, mérve, 27 fájlon). **A második Stage C futás (run 31315921964) hibamentes:**
  27/27 sidecar a bundle-ből, 27/27 attesztáció ~20mp alatt, sikeres deploy.
  Kész súly: 73,5/92,5, pontszám **8,5/10**.

- **2026-08-10 — 4.11 lezárva: riportálás, nem kapu és nem tömeges újramérés.** Két javaslatot
  tettem — re-validation gate a promóció előtt, illetve ütemezett újramérés az elévült halmazra —,
  a felhasználó mindkettőt elutasította: 500+ szabálynál egyik sem skálázna, és pont ezért létezik
  a dashboard Evidence-jelölése, hogy a szelektív, kézi újrafuttatás emberi döntés maradjon, ne
  automatikus tömeges. A tényleges hiány nem a mérés hiánya volt — a `stats.json`
  `verified_expired`+`verified_superseded` számlálója már megvolt (1.2 óta), csak a dashboardon
  élt, senki nem látta a promóció pillanatában.
  **A megoldás:** az `open_promotion_pr` job (`ci_dev_workflow.yml`) a Contents API-n (nem
  checkout-tal, hogy a job „egy maréknyi `gh` CLI hívás" jellege megmaradjon) kiolvassa a
  `splunk_verify` által *ugyanabban a futásban* frissen legenerált `stats.json`-t a `dev` HEAD-ről,
  összeadja a két számlálót, és ha `>0`, egy GFM `[!WARNING]` blockquote-ot told a PR body végére és
  a step summary-ba (a `scripts/lib/summary.py` `MARK_WARN`/`ALERT_WARN` konvencióját követve
  kézzel, mert bash nem importálja azt), plusz egy `::warning::` annotációt az Actions futás
  oldalára. Sem blokkol, sem újratesztel semmit — pontosan a tétel saját címe szerint.
  **Best-effort, szándékosan:** a Contents API hívás hibája (jogosultság, hálózat) csendben 0-ra
  esik vissza `set -e` alatt is, nem buktatja a PR nyitást — ez a kiegészítés maga sosem válhat a
  tényleges promóció blokkolójává. Mockolt `gh`/`jq`-val három ágat ellenőrizve helyi bash-teszttel
  élesítés előtt: van elévült szabály / nincs / a Contents API hívás elbukik — mindhárom helyesen
  viselkedett, a harmadik esetben `stale_count` némán 0-ra esett és a PR nyitása változatlanul
  lefutott. Egy első próbálkozás a blockquote szövegét a YAML `run:` blokk sortöréseivel próbálta
  tagolni, ami a bash-indentációt (10 szóköz) szó szerint a markdown-szövegbe szivárogtatta volna —
  ezt a helyi teszt fogta meg, mielőtt élesben futott volna; a végleges verzió `$'\n'`
  konkatenációval építi a többsoros stringet, indentáció-mentesen.
  **Melléktermékként két, ettől független drift is előkerült és javítva lett:** a publikált
  `audit/register.html` checkbox-ai nem követték a `remediation-plan.md` `[x]`-eit két korábban lezárt
  tételnél (**3.9**, **4.7**) — a DOM-ból számolt kész súly 70,0/92,5 volt a fájl tetején írt
  73,5/92,5 helyett. A register.html az egyetlen igazság-forrás (`remediation-plan.md`) szerint most
  szinkronban van, mindkét fájlból ugyanaz a szám jön ki: **43/54 tétel, kész súly 75,0/92,5,
  pontszám 8,53 → 8,5/10.**

- **2026-08-11 — 4.9 lezárva: a promotion PR body-ja most a tényleges diffet mutatja, nem egy
  fix mondatot.** A felhasználó a három, session elején "kisebb"-ként bemutatott nyitott tételt
  (2.22, 3.5, 4.9) kérte
  körbenézni, és a legalacsonyabb kockázatút választotta elsőnek. Az `open_promotion_pr` job
  (`ci_dev_workflow.yml`) eddig egy statikus sablon-mondatot írt a PR body-ba plusz a 4.11
  elévülés-figyelmeztetést; semmi nem mondta meg a reviewernek, *mely* szabályok promotálódnak és
  milyen verdikttel. A job szándékosan checkout nélküli marad (lásd a 4.11 bejegyzését ugyanerről
  az elvről) — a fix ezért egy további `gh api repos/.../compare/main...dev` hívással kéri le a
  változott fájlneveket, a `detect_id`-ket reguláris kifejezéssel szedi ki belőlük, és a
  `stale_count`-hoz már úgyis lekért `stats_json`-ból (Contents API, `dev` HEAD) `jq`-val
  kikeresi mindegyik cím/szint/verdiktjét. A tábla a PR body-ba *és* a step summary-ba is
  bekerül, a már meglévő "már nyitva van" ághoz is. **Tudatos hatókör-döntés:** a tábla csak a
  ténylegesen változott szabályokat listázza, nem mind a 27-et (majdan 150-400-at) — ellentétben
  a séma-szintű `by_level`/`by_status` aggregátumokkal, amik már léteznek a `stats.json`-ban, de
  semmit nem mondanak arról, *mi* van ebben a konkrét PR-ben. Verzió-diffet (dev-vs-prod
  régi/új szám) szándékosan nem mutat — az a **3.5**/**3.6** alatt még git-commit-számból
  számolt, konszolidálásra váró logika, erre a tételre nem akartam ráépíteni egy még
  duplikált forrást. Best-effort, a `stale_count` mintáját követve: a `compare` hívás vagy a
  `stats.json` hiánya csendben üres táblát ad `set -e` alatt is, sosem buktatja a PR nyitást; egy
  törölt szabály a diffben szó nélkül kimarad (nincs többé a `stats.json`-ban sem) — ismert,
  vállalt rés, mert a repo promotion PR-jai ma bővítésről/módosításról szólnak. Helyi
  bash-teszttel ellenőrizve mockolt `stats.json`-nal és `compare` diffel élesítés előtt: sigma+spl
  páros egy szabályra egy sorra dedupelve, nem-szabály fájl (pl. `docs/index.html`) kimarad, nem
  létező `detect_id` csendben kimarad, üres diff és üres `stats_json` egyaránt üres táblát ad
  hibakód nélkül. `register.html` ezzel egyszerre frissítve (checked + kész-jelölés), nem
  utólagos drift-javításként.
  Kész súly: 76,5/92,5 (a 4.9 valódi súlya 1,5, "feature" — nem 1, "kisebb", ahogy a session
  elején tévesen bemutattam), pontszám **8,57 → 8,6/10.**

- **2026-08-11 — 2.22 lezárva: a stats-generátor technika-regexe most a séma mintáját követi.**
  A `generate_stats.py` `extract_techniques()`-e eddig `attack\.t\d+(?:\.\d+)?`-re illesztett —
  lazábban, mint a séma saját `^attack\.[Tt]\d{4}(\.\d{3})?$` mintája —, tehát egy olyan tag, ami
  a séma `anyOf`-jának harmadik, szabad-szöveg ágán csúszott át (pl. `attack.t123`), a generátoron
  keresztül mégis valós technika-badge-et és Navigator-cellát kapott, mintha lefedettség volna.
  A **4.3** validátora (`check_mitre_tags.py`) ezt ma is elkapja, de tanácsadó módban — a séma és
  a generátor közti eltérés maga, ami a hamis badge-et okozza, megmaradt volna.
  **A tétel maga két utat ajánlott fel, direkt kockázat-elemzéssel:** a séma `anyOf`-jának
  szűkítését, vagy a generátor regexének a sémához igazítását. Az elsőt a tétel saját szövege
  szerint is kockázatosabbnak ítéltem — a legitim `attack.g####`/`s####`/`cve.*` tageket a séma
  free-form ágán engedjük át, egy elhamarkodott szűkítés ezeket is kizárná. A generátor oldala
  ezért kapott új, anchorolt mintát (`^attack\.(t\d{4}(?:\.\d{3})?)$`), szó szerint a séma
  mintájával egyező számjegyszámmal. A séma harmadik ága tudatosan, változatlanul maradt —
  ez most már vállalt döntés, nem hallgatott rés.
  **Ellenőrzés, nem feltételezés:** mind a 27 meglévő `rules/sigma/*.yml` tagjén lefuttatva a régi
  és az új regex, nulla eltérés (egyik élő szabály tagja sem esik ki) — a szigorítás ma
  garantáltan zéró-regressziós. Szintetikus esetekkel (`attack.t123`, `attack.t1059.1`,
  `attack.t1059.001.002`) igazolva, hogy pontosan azok esnek ki, amiket a tétel problémásnak
  jelölt. A generátort egy teljes futtatással is leellenőriztem: a `stats.json`,
  `navigator_layer.json`, `coverage_history.json` diffje kizárólag időbélyeg és az aznapi
  history-pont volt, semmilyen lefedettség-szám (`mitre_covered_techniques` stb.) nem mozdult —
  ezeket a generált fájlokat nem commitoltam, azok a CI `regenerate_docs` jobjának dolga.
  Kész súly: 77,5/92,5, pontszám **8,59 → 8,6/10.**

- **2026-08-11 — 3.5 részben kész: a verzió-duplikáció megszűnt, a séma-kérdés tudatosan nyitva
  maradt.** A felhasználó megkérdezte, melyik utat javaslom a 3.5-höz — csak a duplikáció
  megszüntetését, vagy a tétel saját, nagyobb ajánlott fixét (explicit `version:` mező a YAML-ben
  + CI-gate a bumpra) is. Ekkor derült ki egy saját hiba: a session elején a 3.5-öt (és a 4.9-et)
  tévesen "kisebb" (×1) súlyúként mutattam be — a `register.html` DOM-ja szerint a 3.5 valójában
  **architektúra (×2)**, a 4.9 **feature (×1,5)**, egyedül a 2.22 volt ténylegesen "kisebb" (×1). A
  dedup mellett így is érveltem, immár a helyes súlyra hivatkozva: a 3.5 saját ajánlott, nagyobb
  fixe (explicit `version:` mező minden rule-fájlban + CI-gate) érdemben a **3.6**-tal egy
  súlyosztályba (×2) tartozó munka volna — a register már ennek megfelelően, nem tévesen sorolja
  be —, miközben a dedup önmagában is arányos, alacsony kockázatú lépés, ami nem zárja ki a
  nagyobb fixet később, csak egy helyről, nem kettőből kellene majd átalakítani. A felhasználó rám
  bízta a döntést.
  **A dedup maga nem volt kockázatmentes copy-paste.** A két meglévő implementáció
  (`sigma_to_spl.py`, `generate_stats.py`) a `git log --follow` alapú számítást azonosan végezte,
  de már **eltért** abban, mit ad vissza, ha git nem elérhető vagy a számláló 0: a konverter
  `"1.0"`-t (a sidecar-ba úgyis ír valamit, egy placeholder a legkevésbé rossz válasz), a generátor
  `""`-t (a dashboard csak azt állíthatja, amit tényleg mért — egy hamis `"1.0"` téves
  egyezést/eltérést gyárthatna egy verdikt rögzített `rule_version`-jével szemben). Ez pontosan az
  a csapda, amit a **3.6** `env_required`-nál már egyszer dokumentált: ami olvasásra nézve
  azonosnak tűnik, hívóhelyenként mégis eltérő politikát hordozhat. Az új `scripts/lib/rule_version.py`
  ezért nem választott egyet a kettő közül, hanem `default` paraméterré tette — mindkét hívó a
  saját korábbi viselkedését kapja tovább, csak egy közös `commit_count()`-ra és
  `compute_rule_version()`-re épülve, plusz egy eddig hiányzó 60s timeout mindkét oldalon (egy
  beragadt git-hívás eddig egyik hívót sem korlátozta).
  **Ellenőrizve, nem feltételezve:** közvetlen függvényhívással mindkét oldal default-ját és a
  valós útvonalat (`DETECT-2026-0003_Test3.yml` → `"1.4"`, változatlan); a konvertert egy valós
  szabályon ténylegesen lefuttatva, a kimeneti `.meta.json` `rule_version`-je `"1.4"` maradt; a
  generátort is teljesen lefuttatva, a `stats.json` diffje **nulla** sor volt (a
  `navigator_layer.json`-é csak az időbélyeg) — ugyanaz a zéró-regressziós próba, mint a 2.22-nél.
  `pytest` nem elérhető ebben a helyi környezetben (nincs `pip`), tehát a `tests/` alatti
  automatizált suite-ot ez a session nem futtatta le — ez a CI dolga lesz a push-on.
  **Amit ez NEM zár le:** a `version:` mint git-commit-számból származtatott, senki által nem
  szándékosan beállított érték — ez a tétel saját szava szerinti nagyobb kérdés (explicit mező +
  CI-gate) —, ezért **3.5 pipa nélkül marad**, csak a duplikáció-fele lezárva. Pontszám nem
  változik, mert az item csak teljes lezáráskor számít bele a kész súlyba.

- **2026-08-11 — 3.8 alkönyvtár-fele elvetve, a 4.5 scaffolder+ütközésvédelem fele kész.** A
  felhasználó a 3.8-at kérte megbeszélni, de mielőtt bármit implementáltam volna, megkérdezte,
  miért is fájna a flat könyvtárszerkezet — jogosan. Átgondolva: a rule-böngésző dashboard a YAML
  *tartalma* alapján szűr (tactic, technika, log-source), nem a könyvtárszerkezet alapján; a
  fájlnevek beszédesek (`DETECT-2026-0019_LSASS-Memory-Access-...yml`); a fájlrendszer és a
  `grep`/editor fuzzy-find több száz fájllal egy könyvtárban is ugyanúgy működik, mint 27-cel. Az
  eredeti audit-tétel "27 még kezelhető, 150 már nem" állítása nem volt ténylegesen alátámasztva —
  átvett feltételezés volt a 2026-07-26-os statikus átvizsgálásból. A felhasználó kíváncsiságból
  megkérdezte, milyen bontást javasolnék — `logsource.product_category` szerintit mondtam (séma
  szerint kötelezően egyértékű, nincs kétértelműség, ez a SigmaHQ upstream mintája is), tactic
  szerintit kifejezetten nem (egy szabály tipikusan több `attack.*` taget visel, egy elsődleges
  tactic-mappa mesterséges volna) — de a felhasználó véglegesen elvetette az egész alkönyvtár-ötletet.
  **Amit viszont megtartott: az ID-kiosztás/ütközésvédelem valós probléma.** A felhasználó elmondta,
  hogy ma egy snippetből kézzel írja át az értékeket minden új szabálynál, és nyitott egy jobb
  megoldásra, ha az automatikus ID-kiosztást *és* ütközésvédelmet is tartalmaz — ez pontosan a 4.5
  saját szövege. Felajánlottam, hogy a 4.5 teljes köréből (scaffolder + Makefile +
  ATT&CK→atomic-teszt-lookup) csak a ténylegesen kért két darabot csináljuk meg most; a felhasználó
  ezt választotta.
  **`scripts/new_rule.py`** (új, önálló CLI, nem `scripts/validate/` vagy `scripts/convert/` alatt,
  mert nem CI-pipeline-lépés, hanem szerzői eszköz): a `lib.rules.discover()`/`load_rule()`/
  `detect_id()`-re építve (nem duplikálva) számolja ki a következő szabad `DETECT-<év>-NNNN`-t —
  **szándékosan sosem tölt ki lyukat** (a mai 0001/0002/0004/0017 is töltetlen marad), mert egy
  visszavont ID újrahasznosítása régi verdikt-history-t / `coverage_history.json`-pontokat /
  Splunk-audit-nyomokat keverne össze ugyanazzal az azonosítóval. A szerzőt `git config user.name`-ből
  olvassa (3 karakternél rövidebb vagy hiányzó esetén sémaérvényes `"TODO"`-ra esik vissza), és egy
  séma-konform TODO-skeletont ír ki — minden placeholder (leírás, referencia, `attack.t0000` tag,
  false positive) átmegy a `validate_sigma.py`-n változtatás nélkül is, **de** a `check_mitre_tags.py`
  (4.3) szándékosan `unknown_technique`-ként jelzi a placeholder tag-et — ez a látható nudge a
  cserére, tanácsadó módban, nem buktatja a validációt.
  **`scripts/validate/check_detect_id_uniqueness.py`** — a tényleges védőháló, bekötve a
  `ci_dev_workflow.yml`-be a `check_test_routing.py` és a `check_mitre_tags.py` közé, minden
  szabályra (nem csak a változottakra, ugyanazon indokkal, mint a másik két ellenőrzésnél). A
  scaffolder csak a helyi checkoutot látja — két branch ugyanarról a base commitról ugyanazt a
  "következő szabad" ID-t számolhatja ki egymástól függetlenül —, ez a check a **merge-elt fán**
  fut, ahol egy valódi ütközés a Splunk-oldalon egy némán felülírt saved search formájában jelenne
  meg (`rule_naming.saved_search_name` = `detect_id + slug(title)`). A **4.3**-tól eltérően (ami
  tanácsadó, mert egy rossz ATT&CK-tag félreteszi, nem töri el a detekciót) ennek nincs `--strict`
  kapcsolója — egy duplikált `detect_id` egyértelműen és mindig hiba, tehát alapból buktat, ugyanaz
  a szerződés, mint a `validate_sigma.py`-é. **Nem került be a `rebuild_all_files` listába**
  (`ci_dev_workflow.yml`) — ugyanazon az alapon, mint a `check_test_routing.py`/`check_mitre_tags.py`:
  nem befolyásolja, mivé konvertálódik vagy minek hívják a szabályt Splunkban, tehát egy teljes
  labor-újrafutást nem indokol.
  **Ellenőrizve, nem feltételezve:** a scaffoldert egy másolt `rules/sigma/`-n futtatva a valós
  27 szabály mellé — helyesen `DETECT-2026-0032`-t adott (max 0031 + 1); a kimenet átment a valódi
  `validate_sigma.py`-n hiba nélkül; a `check_mitre_tags.py` a placeholder tag-et helyesen
  `unknown_technique`-ként jelezte, `exit 0`-val (advisory, nem buktat); a felülírás-védelem külön
  tesztelve egy szándékosan ütköztetett fájlnévvel (`exit 2`); az egyediség-ellenőrző a valós
  repón `0` duplikátumot talált, egy szintetikus két-fájlos ütközésen pedig `exit 1`-et helyes
  hibaüzenettel. `pytest` itt sem elérhető (nincs `pip`), tehát az automatizált suite futtatása a
  CI dolga marad.
  **Amit ez NEM zár le:** a `Makefile` (`make validate`/`convert`/`stats`/`check`) és az
  ATT&CK-technikához tartozó atomic-teszt-számok automatikus kikeresése — mindkettő a 4.5 saját
  szövegének része, szándékosan kimaradt, ezért **4.5 pipa nélkül marad**. Pontszám nem változik.

- **2026-08-11 — 4.5 és 3.8 lezárva: a felhasználó megerősítette a hatókört, és rendezte a 3.8
  bundle-jét.** Miután megnézte, mit csinál a scaffolder + ütközésvédelem, a felhasználó
  kifejezetten kijelentette, hogy sem a `Makefile`, sem az ATT&CK→atomic-teszt-lookup nem kell a
  repóba — ezzel a **4.5** ténylegesen kért hatóköre (scaffolder + ütközésvédelem) lett a tétel
  teljes hatóköre, nem egy részhalmaza, tehát **pipát kapott**, nem marad félkész státuszban. Ez
  eltér a **3.5**-nél és a korábbi 4.5-verziónál alkalmazott szabálytól ("csak akkor pipa, ha a
  tétel *eredeti* teljes szövege lezárult") — a különbség az, hogy ott a hátralévő rész
  *elhalasztva* volt (később még megcsinálható), itt a felhasználó *véglegesen* kizárta a
  hátralévő részt a repo köréből, tehát a tétel ezzel nem félkész, hanem a saját, felülvizsgált
  hatókörén belül teljes.
  **Ugyanez a logika zárta le a 3.8-at is, más alakban.** A tétel két, nem összefüggő dolgot
  bundlézott egy sorszám alá: a flat könyvtárszerkezet állítólagos skálázási problémáját, és a
  manuális ID-kiosztás valós kockázatát. Az első felet a felhasználó rákérdezése nyomán
  megvizsgáltam és **elvetettük** (lásd a korábbi Napló-bejegyzést) — ez nem függőben lévő munka,
  hanem egy meghozott, indokolt döntés ("nem kell ez a funkció a repóba"), a második felét pedig a
  **4.5** oldotta meg. Mivel mindkét fél *eldőlt* (az egyik elutasítással, a másik megvalósítással),
  a tétel maga lezárt — a cím és a leírás átírva, hogy ez a szövegből is látszódjon, ne úgy
  fessen, mintha még várna valamire.
  Kész súly: 81,0/92,5 (45→47 tétel, +2 a 3.8-ért [architektúra], +1,5 a 4.5-ért [feature]),
  pontszám **8,69 → 8,7/10.**

- **2026-08-11 — 4.2 lezárva: SPL szintaxis-validáció deploy előtt, a `search/v2/parser`
  endpointtal.** A felhasználó a maradék tételek közül a 4.2-t választotta — előbb megkérdezte,
  mit adna hozzá a repóhoz, mielőtt belevágtunk volna. Kiderült: a `deploy_spl_to_splunk.py` a
  query szöveget minden szintaxis-ellenőrzés nélkül POST-olja a `saved/searches` endpointra —
  Splunk ott nem parse-ol mentéskor —, tehát egy hibás SPL élő saved search-ként jön létre, és
  csak akkor derül ki, amikor ténylegesen lefut (cron vagy attack+verify dispatch), és csak akkor,
  ha a szabály `testing.enabled` és ki lett választva egy adott futásra. A mai 27 szabályból
  mindegyiknek `enabled: true`, de egy — `DETECT-2026-0003_Test3`, `custom.splunk.raw_query`-vel —
  teljesen megkerüli a Sigma→SPL konvertert, tehát a query szövegét ma tényleg semmi nem nézi meg
  előre.
  **Első lépés, mielőtt bármit írtam volna: a Context7 MCP-n át friss Splunk-dokumentációt kértem
  a `search/parser` endpointról** (a felhasználói globális szabály erre kifejezetten előírja a
  Context7 használatát API-kérdéseknél, ahelyett hogy a tréning-adatra hagyatkoznék). Kiderült:
  a tétel saját szövege által megnevezett, verzió nélküli `search/parser` **elavult Splunk
  9.0.1 óta** — a jelenlegi REST API-referencia a `search/v2/parser`-t (POST, nem GET) ajánlja
  helyette. Ez egy konkrét, a session elején fel nem merült pontatlanság volt magában az
  audit-tételben, amit a friss dokumentáció-lekérés fogott meg, nem a saját tudásom.
  **Új `scripts/deploy/check_spl_syntax.py`**, a `scripts/deploy/deploy_spl_to_splunk.py`
  kapcsolódási mintáját követve (`lib.env`, `lib.summary`, `requests.Session`, form-encoded POST).
  `parse_only=true`-val hívva — ez kikapcsolja a subsearch/lookup/eventtype/macro-kiterjesztést,
  tehát a check *tisztán szintaxist* ellenőriz, nem szemantikát: egy hiányzó lookup-tábla miatti
  bukás hamis pozitív lenne egy olyan kérdésre, amit ez a check nem tesz fel. 401/403 auth-hiba
  `die()`-val azonnal megszakítja a futást (2-es kilépőkóddal, nem "ez a szabály bukott"-ként
  számolva) — ugyanaz a credential fog percek múlva a tényleges deployhoz is kelleni, tehát egy
  hitelesítési hiba minden hátralévő szabálynál ugyanúgy elbukna, nincs értelme végigmenni rajtuk.
  **Bekötve a `ci_dev_workflow.yml` `splunk_deploy` jobjába**, közvetlenül a deploy lépés elé,
  ugyanazzal a fájllistával (az adott futásban ténylegesen deployolandó szabályok, nem az egész
  repo — ez élő Splunk-hívást jelent szabályonként, nem helyi, ingyenes ellenőrzést, mint a
  `check_mitre_tags.py`/`check_detect_id_uniqueness.py`). A job `timeout-minutes`-ét 60-ról
  75-re emeltem, mert a meglévő kommentben dokumentált 40 perces legitim-várakozás becslés a
  deploy 3 hívása mellett most egy negyediket kap szabályonként (27 × 30s ≈ 13,5 perc), és a
  60 perc túl kevés margót hagyott volna.
  **Két hiba, amit a saját korábbi session-eim tanulsága mentett meg attól, hogy csendben
  visszatérjenek:** (1) a `paths:` szűrő mindkét blokkjában (`push`, `pull_request`) a
  `scripts/deploy/deploy_spl_to_splunk.py` **egyetlen fájlként** volt megnevezve, nem glob-bal —
  pontosan az a csapda, amit a `scripts/lib/**` és `scripts/convert/**` melletti kommentek már
  kétszer dokumentáltak ebben a fájlban ("egy kézzel írt lista elavul, amint egy második fájl
  megjelenik"). Az új `check_spl_syntax.py` enélkül nem indított volna futást, ha önmagában
  módosulna. Widen-elve `scripts/deploy/**`-re, ugyanazzal az indoklással, mint a testvér-globok.
  (2) A `rebuild_all_files` explicit lista (item 2.19) **szándékosan** nem kapta meg — ugyanúgy,
  ahogy maga a `deploy_spl_to_splunk.py` sincs rajta: egyik sem változtatja meg, mivé konvertálódik
  vagy minek hívják a szabályt, tehát egy teljes labor-újratámadást nem indokolnak.
  **Prodba szándékosan nem került be.** A promotion PR csak azután nyílik, hogy a dev már
  sikeresen deployolt — tehát a promotálható `.spl` már átment ezen az ellenőrzésen —, a prod
  pedig a **3.2** build-provenance attesztációjával pontosan ugyanazokat a byte-okat engedi be
  újraellenőrzés nélkül. Egy prod-oldali duplikált syntax-check szembe menne a 3.2 saját "ne
  validáljunk kétszer, bízzunk az attesztációban" elvével.
  **Ellenőrizve, nem feltételezve — mockolt Splunk-válaszokkal, mert nincs éles Splunk ehhez a
  helyi környezethez:** sikeres parse (200), elutasított query `messages` tömbbel (a hibaszöveg
  helyesen kinyerve), elutasított query nem-JSON törzzsel (nyers szöveg fallback), 401/403 →
  `die()` 2-es kóddal, hálózati hiba → `RequestException` felfelé propagálva. Végponttól-végpontig
  `main()`-en keresztül: csak jó fájl → exit 0; jó+hibás fájl → exit 1, a hibás helyesen jelezve;
  hiányzó fájl → exit 1 (szabály-szintű hiba, nem setup); üres fájllista → exit 0; hiányzó env var
  → exit 2. `pytest` itt sem elérhető, a CI-suite futtatása a push-ra marad.
  Kész súly: 82,5/92,5, pontszám **8,73 → 8,7/10.**

- **2026-08-12 — 3.6 lezárva: a `scripts/lib/` maradék fele, `SplunkClient` helyett
  `build_session()`.** A felhasználó ezt választotta a hat nyitott tétel közül, miután először
  felülvizsgálatot kért — mielőtt bármit írtam volna, végignéztem a mai kódot, nem csak a tétel
  szövegét, és két konkrét dolgot találtam, ami a szöveg megírása óta változott.
  **Első: a hatókör nőtt, nem csak megmaradt.** A tétel négy Splunk-hívó scriptet nevezett meg;
  azóta a **4.2** hozott egy ötödiket (`check_spl_syntax.py`), és az pontosan ugyanazt a
  négysoros `requests.Session()`/`.verify`/`.auth`/`.headers` blokkot másolta be, ami a másik
  négyben már megvolt — élő bizonyíték arra, hogy amíg nincs mit újrahasználni, minden új
  Splunk-hívó script újra lemásolja a mintát.
  **Második, a tétel eredeti szövege által nem nevesített lelet:** a `search/jobs` végpontok
  URL-jét **három helyen** kézzel rakták össze (`check_saved_search_hits.py` a dispatch utáni
  poll- és results-hívásban, `wait_for_indexing.py` a probe-hívásban) —
  `f"{base_url}/servicesNS/{quote(owner)}/{quote(app)}/search/jobs..."` —, holott a **3.9** alatt
  már megszületett `lib/splunk_ns.namespace_url()` pontosan erre a célra való; eddig csak a
  `saved/searches` hívók (`deploy`, `reconcile`) használták ki.
  **A hatókört a felhasználóval egyeztetve szűkítettem.** A `SplunkClient` a tétel saját szövege
  szerint osztály lett volna, retry-logikával együtt. Ez ellen két érv szólt: (1) a session-építés
  a három bemenet (felhasználó, jelszó, TLS-mód) tiszta függvénye, nincs hívások közt megosztott
  állapot, tehát egy osztály fölösleges absztrakció; (2) **ma egyik script sem retry-zik**, egy
  retry-mechanizmus bevezetése tehát nem a talált duplikáció javítása lett volna, hanem egy nem
  kért, méréssel alá nem támasztott bővítés — ha valaha kiderül, hogy kell (mért, nem feltételezett
  Splunk-instabilitás), az önálló tétel, nem ennek csendes melléktermeke.
  **Két új modul, a `lib/env.py` mintáját követve — a mechanika közösbe, a policy a hívónál marad:**
  `scripts/lib/splunk_client.py::build_session(username, password, verify_tls)`, bekötve mind az öt
  hívóba (`deploy_spl_to_splunk`, `check_spl_syntax`, `check_saved_search_hits`,
  `wait_for_indexing`, `reconcile`); és `scripts/lib/meta_sidecar.py::read_meta_sidecar(spl_path)`,
  ami a sidecar elérési útját számolja ki és parse-olja, `FileNotFoundError`/`JSONDecodeError`-t
  dobva. A három Python-olvasó (`deploy`: `die()` — setup-hiba; `check_saved_search_hits`: csendes
  `{}` — a szabály mérhetetlen, nem hibás; `wait_for_indexing`: átugrás — egy fájl a sok közül)
  **szándékosan eltérő** hibapolitikáját mindhárom megtartotta a saját except-ágában, ugyanazzal az
  indoklással, amit a 3.6 már egyszer leírt az `env_required`-nál. A PowerShell-oldali negyedik
  olvasó (`run_atomic.ps1::Read-MetaFromSplFile`) **szándékosan nem lett közösítve** — más nyelv,
  nincs mit megosztani rajta keresztül.
  A három hand-rolled `search/jobs` URL mindhárom helyen `namespace_url()`-re állt át, string-szinten
  bájtra azonos kimenettel — a meglévő `test_splunk_namespace.py` a pontos URL-t vizsgálja, és
  módosítás nélkül zöld maradt, ami önmagában a bájt-azonosságot igazolja.
  **Bizonyítás, nem feltételezés:** 20 új teszt (`tests/test_splunk_client.py`,
  `tests/test_meta_sidecar.py`, plusz egy `tests/test_splunk_namespace.py`-ban), köztük egy-egy
  identitás-teszt mindhárom megosztott függvényre — `build_session` ugyanaz az objektum mind az öt
  hívóban, `read_meta_sidecar` mind a háromban, `namespace_url` mindkettőben —, ami azt veszi észre,
  ha valaki később visszacsempész egy helyi másolatot, plusz külön eset mindhárom meta-olvasó
  policy-ágára (hiányzó/hibás sidecar → `die(1)` / `{}` / átugrás). Teljes `pytest` futtatva előtte
  és utána: a változtatás előtt is fennálló négy hiba (helyi gépfüggő `Europe/Budapest` tzdata-hiány,
  illetve egy elavult darabszám-teszt a `check_spl_syntax` workflow-lépése miatt — mindkettő a
  változtatás előtt is megvolt, ellenőrizve `git stash`-elt régi kóddal) változatlanul megvan,
  semmi új nem tört el. `ruff` tisztán az érintett és az új fájlokon.
  Kész súly: 84,5/92,5, pontszám **8,78 → 8,8/10.**

- **2026-08-15 — 3.5 lezárva: explicit `version:` mező a YAML-ben + CI-gate a bumpra, a tétel
  saját maga ajánlotta, nagyobb fix.** A duplikáció-fele (`scripts/lib/rule_version.py`) 2026-08-11-én
  zárult; a séma-kérdés akkor tudatosan nyitva maradt — lásd az akkori bejegyzést. Ez a bejegyzés a
  hátralévő részt zárja: a "verzió" ma git commit-számból származik (`git log --follow`), tehát egy
  kozmetikai leírás-átfogalmazás pontosan ugyanúgy bumpolja, mint egy logika-változás — a szám semmit
  nem árul el arról, *mi* változott.

  **Séma + 27 szabály.** `docs/schemas/sigma_schema.json` kapott egy `version` mezőt
  (`"^\d+\.\d+$"` minta, `MAJOR.MINOR`), felvéve a top-level `required` listára `modified` mögé.
  Mind a 27, git által követett `rules/sigma/*.yml` kapott egy `version:` sort közvetlenül a
  `modified:` után — nem `"1.0"`-ra hardcode-olva, hanem a fájl aznapi, `compute_rule_version()`-nel
  mért verziójára seedelve (`rule_version.py` importálva, futtatva minden fájlon, az eredmény
  beírva szöveges beillesztéssel, a YAML többi része byte-azonos maradt). A szórás valós volt:
  `1.0`-tól (`DETECT-2026-0032`, ami nem git-követett, kimaradt a körből) `1.19`-ig
  (`DETECT-2026-0007_PowerShell-Encoded-Command-Execution`). `scripts/new_rule.py` skeletonja is
  kapott egy `version: "1.0"` sort a `modified:` után, különben a mostantól kötelező mező miatt a
  scaffoldolt vázlat nem ment volna át a saját `validate_sigma.py`-n.

  **Egy repóban talált, a repo `git status`-ában nem szereplő 28. fájl** (`rules/sigma/DETECT-2026-0032_Pipeline-Test-Rule-Tasklist-Process-Discovery.yml`) — egy korábbi session `scripts/new_rule.py`-tesztjének maradványa, `git ls-files` szerint sosem volt trackelve — szándékosan kimaradt a 27-es körből és a `version:`-szeedelésből; nem ehhez a tételhez tartozik, és mivel untracked, sem a `check_version_bump.py` diffje, sem semelyik `discover()`-alapú script nem venné figyelembe a jelen módosítás nélkül sem.

  **Új `scripts/validate/check_version_bump.py`.** Azt nézi, hogy egy push által módosított
  szabályfájlban a `detection:`, a `logsource:`, vagy a `custom.splunk.raw_query` (a
  `DETECT-2026-0003_Test3` mintájú, a Sigma→SPL konvertert megkerülő szabályok tényleges logikája,
  amit a `detection:`/`logsource:`-only nézés kihagyott volna) változott-e a diff alapjához képest
  — és ha igen, változott-e a `version:` is. `description`/`references`/`falsepositives`/`tags`/
  `status`/`level`/`fields`/`custom.testing`-only szerkesztés nem vált ki találatot; ez volt a
  tétel saját eredeti panasza. **Hard gate, `--strict` nélkül**, ugyanaz a szerződés, mint a
  `check_detect_id_uniqueness.py`-é — a két *advisory* ellenőrzés (`check_test_routing.py`,
  `check_mitre_tags.py`) mellett tudatosan más súlycsoportba: azoknál a helyes válasz eldöntéséhez
  doménismeret kell (tényleg ez a helyes ATT&CK-technika? lesz-e majd futtató runner?), itt nem —
  hogy két git blob `version:` mezője eltér-e, nem mérlegelés kérdése, és a javítás mindig egy sor.
  A hatóköre is más, mint a két meglévő `validate/` scripté: nem a teljes repót nézi minden futáskor
  (`check_detect_id_uniqueness.py`/`check_mitre_tags.py` mintája), hanem csak az adott push által
  változtatott fájlokat — ez a kérdés eleve egy diffről szól ("mozdult-e a verzió"), tehát csak ott
  válaszolható meg, ahol tényleges előtte/utána van.

  **A "Determine changed Sigma files" lépés bővítve egy `base_sha` output-tal**
  (`ci_dev_workflow.yml`, `prepare_validate_convert` job), feltétel nélkül írva, mielőtt a lépés
  `mode`-ot vagy `rule_files`-t eldöntené — így minden útvonalon (a korai "nincs teendő" kilépésen
  is) elérhető. Az új `Check version bump discipline` lépés ezt a `base_sha`-t adja át a
  `--base-ref`-nek, ugyanazt az előtte/utána-t használva, amit a `changes` lépés már úgyis
  kiszámolt, nem egy második "mi változott" fogalmat feltalálva. A lépés csak
  `steps.changes.outputs.mode == 'changed'`-nél fut: a bulk módoknak (`all`/`unverified`/
  `selected`, és a `workflow_dispatch` általában) nincs valódi diff-alapjuk — a `base_sha` a
  `workflow_dispatch`-nál sosem áll be (`github.event.before` nem létezik arra az eseményre) —,
  tehát egy `all`/`unverified` futáson a kérdés maga nem értelmezhető, nem csak nehezen mérhető.

  **Amit ez a tétel szándékosan NEM zár le, és NEM is ehhez tartozik:** `scripts/lib/rule_version.py`,
  `sigma_to_spl.py` és `generate_stats.py` érintetlen maradt. A git-commit-számból mért
  `rule_version` (a `.meta.json` sidecarban, a dashboard Superseded-ellenőrzéséhez) és az új,
  emberi döntésből eredő `version:` két külön dolog, egymás mellett él — ezt a 2026-08-11-es
  bejegyzés is így indokolta ("verzió-diffet szándékosan nem mutat... erre a tételre nem akartam
  ráépíteni egy még duplikált forrást"), és ez a lezárás sem változtat rajta.

  **Ellenőrizve, nem feltételezve.** `validate_sigma.py` mind a 27 módosított szabályon: 27/27 OK
  az új, kötelező `version` mezővel. `scripts/new_rule.py` egy ideiglenes másolt könyvtárban
  lefuttatva: a generált váz `version: "1.0"`-t tartalmazott és hibátlanul átment a validáción.
  A `check_version_bump.py`-t **valódi git commitok ellen**, nem csak importált függvényhívásokkal
  teszteltem: egy eldobható `git clone` a repóból, benne egy "baseline" commit (séma + 27 szabály +
  az új script), majd rákövetkező commitok — (1) csak leírás-átfogalmazás, verzió-bump nélkül →
  `exit 0`; (2) egy `detection:` szűrő bővítése (`filter_legit_parent` egy új `explorer.exe`
  bejegyzéssel), verzió-bump nélkül → `exit 1`, `[MISSING-BUMP]` + `::error` annotáció a helyes
  fájlra és mezőre; (3) ugyanaz a logika-változás, verzió-bump *-mal* (1.8 → 1.9) → `exit 0`;
  (4) a `DETECT-2026-0003_Test3` `custom.splunk.raw_query`-jának bővítése, bump nélkül → `exit 1`,
  helyesen a `custom.splunk.raw_query`-t nevezve meg okként (nem a `detection:`-et, ami annál a
  szabálynál csak séma-kötelező placeholder). Vegyes köteg (2 tiszta + 1 hibás szabály) egy
  futásban: csak a valóban hibás sorolódott a step summary táblába, a többi `[OK]`-ként. Új
  `tests/test_check_version_bump.py` (24 assert: `raw_query`/`version_of`/`logic_diff` mezőnkénti
  viselkedése, `main()` végponttól-végpontig új/tiszta/hiányzó-bump/bumpolt/raw_query/vegyes-köteg/
  step-summary esetekre) — ez a repóban ma egyetlen ilyen teszt a négy `validate/` script közül,
  ami mellé egyáltalán van pytest fájl (a `check_detect_id_uniqueness.py`-nak jelenleg nincs, ez a
  jelen tétel hatókörén kívüli, meglévő rés). `pytest` ebben a helyi környezetben nem elérhető
  (nincs `pip`, ahogy a 3.5/3.6 korábbi bejegyzései is jelezték) — a 24 assertet ezért kézzel,
  `pytest` nélkül, közvetlen függvényhívásokkal és monkeypatch helyett attribútum-felülírással
  reprodukálva futtattam le (`manual_test_check_version_bump.py`, a scratchpadban, nem a repóban):
  24/24 zöld. Ez nem helyettesíti a valódi CI `pytest` futást, csak azt igazolja, hogy a tesztfájl
  állításai önmagukban helyesek. `ruff`/`actionlint`/`PSScriptAnalyzer` szintén nem elérhető ebben a
  környezetben (nincs pip); a sorhosszakat kézzel ellenőriztem a `pyproject.toml` 120 karakteres
  limitje ellen (`check_version_bump.py`, `test_check_version_bump.py`), és a workflow YAML-t
  `yaml.safe_load`-dal parseolva ellenőriztem, hogy a `ci_dev_workflow.yml` szintaktikailag ép
  maradt és az új `base_sha` job-output megjelenik.

  **A `sigma-rule-authoring` skill** (`.claude/skills/sigma-rule-authoring/SKILL.md`) kapott egy új
  szakaszt a `version:` mezőről és a bump-fegyelemről — mikor kell bumpolni, mikor nem, és hogy ez
  más szám, mint a `.meta.json` git-eredetű `rule_version`-je —, plusz a frontmatter leírása és a
  handoff-szakasz kiegészítve a `check_version_bump.py`-vel, hogy Yuki és Bjorn egyaránt lássa.

  Kész súly: 86,5/92,5 (49→50 tétel, +2 a 3.5-ért [architektúra, mint a 3.6]), pontszám
  **8,84 → 8,8/10.**

- **2026-08-15 — 3.5 utókövetés: két valós probléma a da3b4fa élő futásából (workflow run
  31893084025/31893084071), a pipa és a pontszám érintetlen.** A 2026-08-15-i lezáró bejegyzés
  helyi környezetében sem `pip`, sem `ruff`, sem `pytest` nem volt elérhető — az akkor leírt
  "24/24 zöld" a tesztfájl állításainak kézi, `pytest` nélküli reprodukciója volt, nem valódi CI.
  Az élő push volt az első alkalom, hogy ez a kód tényleges `ruff`/`pytest` elé került, és két
  önálló hibát talált.

  **1) `ruff` piros volt a "CI - Code Checks" futáson ("Static analysis and tests" job), 3
  fixelhető hibával, mind az új fájlokban.** `check_version_bump.py:191` — `I001`, az `import
  yaml` / `from lib.rules import ...` blokk nem volt rendezve (a valódi ok egy fölösleges üres
  sor a két import között — a `ruff` egy összefüggő blokknak várta őket, nem kettőnek).
  `test_check_version_bump.py:18` — `F401`, a `json` import sosem lett használva. Ugyanott
  `:112` — `RUF100`, egy `# noqa: ARG001` egy nem engedélyezett szabályra hivatkozott ebben a
  repóban, tehát önmagában hatástalan megjegyzés volt. Mivel a `ruff` lépés elbukott, a rá épülő
  `pytest` lépés a futáson `skipped`-ként jelent meg — a 24 új teszt és a teljes meglévő suite
  emiatt még nem volt valódi CI-vel megerősítve. Ebben a follow-up környezetben `pip` már sincs,
  de a `pipx run ruff==0.16.1 check .` (ugyanaz a pin, mint a `.github/requirements-dev.txt`-ben)
  elérhető volt és pontosan ezt a 3 hibát találta, semmi mást a teljes repóban. Mindhármat
  `--fix`-szel javítottam (a `check_version_bump.py`-nál ez ténylegesen csak az üres sor
  törlését jelentette, nem sorrendcserét), utána `ruff check .` tisztán fut. `python3 -m venv` +
  a pinnelt `.github/requirements.txt` + `requirements-dev.txt` telepítésével teljes `pytest`
  futás is lehetségessé vált most: **535 passed**, a 24 új `test_check_version_bump.py` teszttel
  együtt — ez az első valódi (nem kézzel reprodukált) megerősítés, bár még helyi, nem CI-beli.

  **2) A `Check version bump discipline` lépés le se futott ezen a pusholáson, és ez valódi rés
  volt, nem csak látszat.** A da3b4fa maga módosította a `docs/schemas/sigma_schema.json`-t (az
  új `version` séma-mező felvételéhez), ami a `rebuild_all_files` triggerlistán szerepel — a
  push emiatt `mode=all`-ban futott, a lépés feltétele pedig `mode == 'changed'` volt, tehát a
  saját maga bevezette kapu a saját bevezető commitján kimaradt. Az eredeti indoklás ("a bulk
  módoknak nincs valódi diff-alapjuk") *részben* volt igaz: a `workflow_dispatch`-eredetű bulk
  módoknál (`all`/`unverified`/`selected` operátor-választásból) tényleg nincs `base_sha`
  (`github.event.before` nem létezik arra az eseményre) — de egy normál push/PR-eredetű
  `mode=all`-nál (mert egy `rebuild_all_files`-trigger volt a diffben) igenis van valódi
  `base_sha`, csak a régi feltétel ezt nem különböztette meg a módtól. Ez nem csak egy futásra
  szóló mulasztás: a következő push alapja már ez a commit lesz, tehát egy ilyen pusholásban
  rejtőző, bump nélküli logika-változás *soha* nem kerülne szembesítésre a valódi előző
  állapotával, semelyik későbbi futáson sem — nem egyszeri vakfolt, hanem tartósan eltűnő eset.
  **Ezért ez valódi rés volt, nem szándékos és dokumentálandó viselkedés** — a kérdés (mozdult-e
  a `version:` egy adott szabályfájlban a diff alapjához képest) ugyanúgy megválaszolható marad
  akkor is, ha a futás emellett minden szabályt újrakonvertál egy nem kapcsolódó okból.

  Javítás: a `Determine changed Sigma files` lépés kapott egy `has_base_diff` outputot,
  amely a `mode`-tól függetlenül azt méri, hogy van-e egyáltalán valódi előző commit
  diffelésre — `false` pontosan a két olyan esetben, ahol a `base_sha` nem megbízható
  (`workflow_dispatch`, ahol `github.event.before` nincs beállítva, illetve az adott ref első
  pusholása, ahol a `base_sha` a csupa-nulla sha), és `true` minden rendes push/PR-nél, azt is
  beleértve, amelyik utóbb `mode=all`-ra vált egy `rebuild_all_files`-trigger miatt. Emellett egy
  új, mód-független `changed_rule_files` output is bekerült — az adott diff `rules/sigma/*.yml|
  yaml` részhalmaza, egyszer kiszámolva, feltétel nélkül írva (ugyanúgy, ahogy a `base_sha` is) —,
  amit a `mode == 'changed'` ág is újrahasznál a korábbi, a diffet külön újraszámoló saját
  ciklusa helyett. A `Check version bump discipline` lépés feltétele `mode == 'changed'`-ről
  `has_base_diff == 'true'`-ra változott, bemenete pedig `rule_files`-ről (ami `all` módban a
  repó *összes* szabálya, nem a push diffje) `changed_rule_files`-re.

  **Ellenőrizve, nem feltételezve.** `actionlint` (`pipx run --spec actionlint-py actionlint`)
  tisztán fut a módosított `ci_dev_workflow.yml`-en; `yaml.safe_load` szintaktikailag épnek
  találja. A tényleges hibát egy eldobható lokális git repóban reprodukáltam: egy base commit
  (séma + egy teszt-szabály `version: "1.0"`-val), majd egy második commit, ami *egyszerre*
  módosítja a sémafájlt és a szabály `detection:`-jét bump nélkül — pontosan a da3b4fa mintája.
  A workflow bash-logikáját lefuttatva erre a repóra: `mode=all`, de `has_base_diff=true` és a
  `changed_rule_files` helyesen tartalmazza a szabályfájlt — a régi feltétel (`mode == 'changed'`)
  itt kihagyta volna, az új (`has_base_diff`) helyesen belépteti. A valódi `check_version_bump.py`-t
  lefuttatva a szimulált `base_ref` ellen: `exit 1`, `[MISSING-BUMP]`, a helyes okkal
  (`detection`) — a javítás ténylegesen elkapja azt az esetet, ami a da3b4fa-n átcsúszott.

  **Amit ez a bejegyzés nem tud igazolni, mert nem tudja: a következő valódi push CI-futása.**
  A helyi `ruff`/`pytest`/`actionlint` és a szimulált git repó erős jelzés, de nem helyettesíti a
  tényleges GitHub Actions futást. A megbízónak kell pusholnia egy normál, `changed`-módú
  commitot (lehetőleg olyat, ami *nem* nyúl a `docs/schemas/sigma_schema.json`-hoz, hogy a mostani
  javítás pontosan a célzott, `mode == 'changed'` úton is lefusson, ne csak az `all`-ág
  reprodukciójában) ahhoz, hogy (a) a `ruff`/`pytest` lépés valódi CI-n is zöld legyen, és
  (b) a `Check version bump discipline` lépés ténylegesen lefusson és helyesen viselkedjen egy
  élő futáson — ez a kettő még nincs valódi CI-vel megerősítve.

- **2026-08-15 — 3.5 végleges, élő fail/pass bizonyíték (3 további push, mind a felhasználó
  pusholta).** A 2ec3a28 (ruff/gate-javítás) pusholása után a "CI - Code Checks" és a "CI - Dev
  Pipeline" is zöld lett — de ez a push egyetlen szabályfájlt sem érintett, tehát `has_rules=false`
  lett, és maga a `Check version bump discipline` lépés is kimaradt (`-` a jobban). Ez megerősítette
  a ruff/pytest-javítást élesben, de a gate-et magát még nem tesztelte.
  Ezért egy szándékos, kontrollált fail/pass párt hoztunk létre a `DETECT-2026-0032` eldobható
  teszt-szabályon: **(1) `ef0d1b4`** — a `detection.selection.Image|endswith`-t kibővítettük
  `qwinsta.exe`-vel, a `version:`-t szándékosan `"1.0"`-n hagyva. Lokálisan előbb igazolva
  (`check_version_bump.py --base-ref HEAD` → `exit 1`, `[MISSING-BUMP]`), majd pusholva: a
  workflow run 31894090587-ön a `Check version bump discipline` lépés ténylegesen **elbukott**,
  a GitHub-annotáció szó szerint `"DETECT-2026-0032 changed detection without bumping version:
  (still '1.0')"`. **(2) `48a7619`** — `version: "1.1"`-re bumpolva, ugyanaz a logika-változás.
  Lokálisan `exit 0` (`version bumped: '1.0' -> '1.1'`), pusholva a workflow run 31894287108-on:
  a `Check version bump discipline` lépés **zölden átment**, a teljes szabály-pipeline (validate →
  convert → SPL commit → dashboard) is végigfutott.
  Ezzel mindhárom nyitott kérdés lezárva élő GitHub Actions futással, nem csak lokális/szimulált
  bizonyítékkal: a ruff/pytest-javítás (2ec3a28), a gate helyes bukása bump nélküli
  logika-változásnál, és a gate helyes átengedése bumpolt logika-változásnál. **A 3.5 innentől
  ténylegesen, élesben igazoltan kész.**

- **2026-08-15 — 4.4 lezárva elutasításként, mielőtt bármit implementáltunk volna.** A felhasználó
  megkérdezte, pontosan mit jelentene a tétel — mielőtt válaszoltam volna, végignéztem a repót,
  hátha van benne Splunk ES-re utaló nyom (`notable`/`risk_object`/`risk_score` index, séma-mező,
  bármi), és nem találtam semmit. A tétel eredeti szövege ("risk score mapping vagy notable event
  action") ES-specifikus fogalom, tehát valószínűleg egy generikus "éles SOC pipeline" sablonból
  került az audit-tervbe anélkül, hogy megnézte volna, van-e itt egyáltalán ES.
  A throttling/drilldown felét a Context7 MCP-n át lekért friss Splunk REST-dokumentációval
  (`/websites/help_splunk_en_splunk-enterprise`) pontosítottam — ez a fele **nem** ES-specifikus,
  ténylegesen megvalósítható lenne (`alert.suppress`/`alert.suppress.period`/`alert.suppress.fields`,
  `alert.display_view`), és ezt is részleteztem a felhasználónak (a `suppress.fields` csak
  `digest_mode=0` mellett kötelező, enélkül a szüneteltetés a teljes szabályra globális, nem
  host/user-szintű; a drilldown a mai `namespace_url()`-alapú app-scope miatt valószínűleg már ma
  is helyesen működik natívan, kód nélkül).
  **A felhasználó ezután mindkét felet elutasította, indoklás: a jelenlegi, egyszemélyes lab-méret
  mellett egyik sem old meg valós problémát** — nincs SOC, amit egy zajos, throttling nélküli
  riasztás megterhelne, nincs csapat, akinek a drilldown-linkre szüksége lenne a saját
  kontextusán túl. Ez egy tudatos, méret-arányos döntés, nem egy elmaradt implementáció — ugyanaz
  a minta, mint a **3.8** elutasítása: a tétel egy nagyobb, éles SOC-ra tervezett sablonból
  származott, és nem minden sablon-tétel érvényes egy egyszemélyes lab-ra. Kód nem változott,
  csak a register.

- **2026-08-15 — 4.1 lezárva elutasításként, mielőtt bármit implementáltunk volna.** A felhasználó
  megkérdezte, mi a probléma és mi a javasolt megoldás — mielőtt válaszoltam volna, végignéztem a
  meglévő verify-oldalt (`scripts/verify/check_saved_search_hits.py`), és rájöttem, hogy a
  mechanika (dispatch + hit-count egy `earliest`/`latest` ablakra) már megvan, csak más ablakkal és
  céllal kellene újrahasználni. Ezt is részleteztem, majd rákérdeztem a tétel valódi
  előfeltételére: van-e a labor Splunkjában folyamatos, nem-attack háttérforgalom, amihez egy
  "csendes 24h" mérés egyáltalán viszonyítani tudna.
  **A felhasználó megerősítette: nincs — a de-lab Splunk kizárólag attack-teszt futások idején kap
  adatot.** Ez nem egy megkerülhető technikai részlet, hanem a tétel egészének alapfeltevését
  dönti meg: egy csendes ablak mérése ebben a környezetben szisztematikusan nullát adna minden
  szabálynál, ami nem noise-mérés lenne, hanem hamis biztonságérzet — rosszabb, mint a tétel
  hiánya. Ugyanaz a minta harmadszor: a **3.8** (alkönyvtár-bontás), a **4.4** (Splunk ES/RBA) és
  most a **4.1** is egy nagyobb, folyamatos-forgalmú éles SOC-ra tervezett sablonból származott,
  aminek egyes elemei ennek a konkrét, egyszemélyes, csak attack-teszt idején aktív lab-nak nem
  érvényesek. Kód nem változott, csak a register.
