---
mitre_id: Txxxx.yyy
mitre_type: subtechnique
name: <angol név>
aliases:
  - Txxxx.yyy
  - <angol név>
url: https://attack.mitre.org/techniques/Txxxx/yyy/
parent_technique: "[[Txxxx - <technika>]]"
platforms:
  - Windows
data_sources:
  - <pl. Sysmon EID 10 (ProcessAccess)>
de_priority: <kritikus | magas | közepes | alacsony>
coverage: <teljes | részleges | nincs | hatókörön kívül>
rules:
  - <DETECT-2026-XXXX>
---
# Txxxx.yyy — <angol név>

## Lényeg

<2-4 mondat: mit csinál a támadó és miért. Ez az a bekezdés, amit a technika-jegyzet "Altechnikák" listájában egy mondatban idézni tudsz.>

> [!quote] MITRE definíció
> <Az attack.mitre.org egymondatos definíciója.>

## Hogyan csinálják a gyakorlatban

<A jegyzet leggyakorlatiasabb része, és detection engineering szempontból a legfontosabb: KONKRÉT eszközök és KONKRÉT parancsok. Ez az, amiből a szabály selection-je születik — ha itt csak általánosság van, a szabály is általános lesz.>

<**Ha a technika egynél több szereplőt/gépet érint** (pl. támadó gép + áldozat + egy harmadik célgép, mint T1557.001-nél), először nevezd meg őket röviden — A/B/C betűkkel vagy szerepnévvel —, EGY bekezdésben, mielőtt a konkrét parancsokra térnél. Ez teszi lehetővé, hogy utána csak "B-n" vagy "C felé" hivatkozz rájuk, ahelyett hogy minden mondatban újra körülírnád, ki kicsoda. Egygépes technikáknál (pl. T1003.001, ahol minden ugyanazon a végponton történik) ez a bekezdés felesleges — hagyd ki.>

<**Ha a technikának több, névvel elkülöníthető végrehajtási módja van** (pl. Capture vs. Relay), mindegyiknek adj saját `### Alcímet` — ne csak félkövér bekezdés-kezdő szöveget —, hogy Obsidianban a vázlat-panelen is külön navigálható pont legyen. Minden alcím alatt: a konkrét eszköz neve, a valódi parancs kódblokkban, és egy záró mondat arról, hogy ez melyik logmezőben milyen értékkel látszik.>

### <Módszer neve>

<egy mondat, mi történik, kire/mire hat (a fenti A/B/C jelölést használva, ha van)>

```powershell
<a tényleges parancs>
```

<Mi az, ami ebből a logban látszik: melyik mező, milyen értékkel.>

<Ha egynél több módszer van, ismételd a fenti `### Módszer neve` blokkot a többire is.>

**Mi váltja ki a gyakorlatban:** <milyen hétköznapi, nem-rosszindulatú helyzet vezet oda, hogy a technika előfeltétele — pl. egy sikertelen névfeloldás, egy elgépelt útvonal — egyáltalán bekövetkezzen. Ez teteszi a technikát valóságossá, nem csak elméletivé; ez marad félkövér bekezdés-kezdő szöveg, nem külön alcím, mert lezárás, nem újabb párhuzamos módszer.>

## Mitigáció

<Ez egy DE-repo, nem hardening-repo — a mitigáció itt nem compliance-lista, hanem a detekció hatókörének indoklása. Ne írj le kontrollt csak a teljesség kedvéért; minden kontrollnál mondd ki, mit jelent a SZABÁLY szempontjából:

- **Ha egy kontroll megszünteti az előfeltételt** (pl. LLMNR letiltása → nincs mire válaszolnia a Respondernek), ez azt magyarázza, MELYIK környezetben egyáltalán releváns a szabály.
- **Ha egy kontroll csak megnehezíti/korlátozza a hatást** (pl. SMB Signing → a relay sikertelen lesz azokon a gépeken, ahol be van kapcsolva), ez közvetlenül a szabály FALSE POSITIVE / hatókör-listájába tartozó infó — innen tudod, mely célgépek ellen "üres találat" a szabály akkor is, ha a poisoning megtörtént.
- **Ha egy kontroll nem alkalmazható** (legacy-függőség, üzleti korlát), mondd ki explicit — ez indokolja, hogy MIÉRT KELL egyáltalán a szabály: a mitigáció hiánya teszi a detekciót az egyetlen védelmi vonallá.

Amit NE tegyél ide: általános biztonságtudatossági képzés, compliance-keretrendszer hivatkozás (NIST/CIS kontrollszám) — ezek nem kötnek vissza a detekcióhoz, kimaradhatnak.>

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés |
| ---------- | ----- | ---------- |
|            |       |            |

### Detekciós logika

<Mit kell keresni, mezőszinten. Nem Sigma YAML — az a szabályfájlban van —, hanem a gondolatmenet: melyik mező, milyen értékre, és miért pont arra. Ide tartozik az is, ha egy módszert szándékosan NEM detektálunk, és miért.>

### False positive források

<Mi generálja ugyanezt legitim módon, és hogyan lehet elkülöníteni. Ha ez a lista üres, a szabály még nincs kész.>

## Kapcsolódó szabályok

<A repo szabályai, amelyek ezt az altechnikát fedik. A `rules:` frontmatter mező ugyanezt a listát tartalmazza gépi formában — a kettőt együtt kell frissíteni, amikor új szabály készül. A `detect_id` oszlop mindig a szabály GitHub-beli linkje: `[DETECT-2026-XXXX](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/<fájlnév>.yml)` — kattintásra egyből a valódi Sigma-fájlra visz.>

| detect_id | Szabály | Telemetria | Szint | Mit fed le |
| --------- | ------- | ---------- | ----- | ---------- |
|           |         |            |       |            |

## Kapcsolódó jegyzetek

Csak azok a fogalom-jegyzetek, amik a technika megértéséhez vagy sikeres kihasználásához tényleges háttértudást adnak — nem navigáció. A szülő technikára a `parent_technique:` frontmatter mutat; a testvér altechnikákat a technika-jegyzet "Altechnikák" / "Összehasonlítás" szekciója sorolja fel és hasonlítja össze.

- **Fogalmak:** [[<Alapfogalom>]] — <mit ad hozzá: pl. a kihasznált protokoll működése, a megkerült bizalmi feltevés, egy előfeltétel-jogosultság>
- **MITRE:** <url>

## Saját feljegyzések

<Saját tapasztalat, nyitott kérdés.>
