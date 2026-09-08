---
mitre_id: Txxxx
mitre_type: technique
name: <angol név>
aliases:
  - Txxxx
  - <angol név>
url: https://attack.mitre.org/techniques/Txxxx/
tactic:
  - "[[TAxxxx - <taktika>]]"
subtechnique_count: <db>
platforms:
  - Windows
de_priority: <kritikus | magas | közepes | alacsony>
coverage: <teljes | részleges | nincs | hatókörön kívül>
---
# Txxxx — <angol név>

## Lényeg

<3-5 mondat: mi a technika közös nevezője, és mi az, ami az altechnikákat egyáltalán egy technikává teszi. Ha ezt nem lehet megfogalmazni, akkor az altechnika-jegyzetekben van a tartalom, és ez a fájl csak elosztó.>

> [!quote] MITRE definíció
> <Az attack.mitre.org egymondatos definíciója.>

## Mihez vezet

Mit kezd a támadó a technika sikeres végrehajtásával — melyik taktika felé lép tovább, és annak mi a célja. (A taktika-hivatkozás szándékosan egykapcsos, hogy a gráfban ne kösse össze a taktikákat.)

A technika eredményét a támadó tipikusan a [TAxxxx - <következő taktika>] felé viszi: <egy mondat, mi annak a taktikának a célja>.

## Altechnikák

<Altechnikánként EGY mondat arról, ami megkülönbözteti a többitől — nem összefoglaló, hanem a különbség. A részletek az altechnika-jegyzetben vannak.>

- [[Txxxx.001 - <név>]] — <mi különbözteti meg>
- [[Txxxx.002 - <név>]] — <mi különbözteti meg>

## Összehasonlítás

<Ez a technika-szintű jegyzet legfontosabb táblázata: itt látszik egyben, hogy ugyanazt a célt hány úton lehet elérni, és melyik út hol hagy nyomot. A sorok technikánként változhatnak, de a "Cél" és a "Detekció helye" mindig maradjon benne.>

|                    | [[Txxxx.001 - <név>\|.001]] | [[Txxxx.002 - <név>\|.002]] |
| ------------------ | --------------------------- | --------------------------- |
| **Cél**            |                             |                             |
| **Mit szerez meg** |                             |                             |
| **Eszközök**       |                             |                             |
| **Telemetria**     |                             |                             |
| **Detekció helye** |                             |                             |
| **DE prioritás**   |                             |                             |

## Mitigáció

<Ez egy DE-repo, nem hardening-repo — technika-szinten csak azt írd le, ami a detekció hatókörét vagy prioritását befolyásolja: mely altechnikát teszi egy kontroll gyakorlatilag lehetetlenné (→ arra nem érdemes szabályt építeni), és melyik marad emiatt az elsődleges detekciós felelet (→ oda kell a szabály). Az egyes altechnikák saját, részletes mitigációja az altechnika-jegyzetekbe tartozik — ne duplikáld itt. Ha a MITRE azt mondja "nem mitigálható", írd le, mi az, ami a felületet mégis csökkenti, DE csak ha ez befolyásolja, hova kell fókuszálni a detekciót.>

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés | Érintett altechnika |
| ---------- | ----- | ---------- | ------------------- |
|            |       |            |                     |

### Detekciós lehetőség

<Technika-szinten: melyik altechnikára hol van a legjobb detekciós esély, mi a közös zajforrás, és mi az, amit nem SIEM oldalon kell megoldani. A konkrét mezők és értékek az altechnika-jegyzetbe tartoznak.>

## Kapcsolódó szabályok

<Az ezen technika alá tartozó ÖSSZES repo-szabály egyben — altechnikánként csoportosítva. Ez a "hol tartok" nézet. A `detect_id` oszlop mindig a szabály GitHub-beli linkje: `[DETECT-2026-XXXX](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/<fájlnév>.yml)`.>

| detect_id | Szabály | Altechnika | Telemetria | Szint |
| --------- | ------- | ---------- | ---------- | ----- |
|           |         |            |            |       |

## Kapcsolódó jegyzetek

Navigáció a jegyzet-hálóban (szabály-linkek külön, a "Kapcsolódó szabályok" szekcióban). Csak hierarchia- és rokon-jegyzet linkek — taktikát taktikával továbbra se köss össze.

- **Taktika:** [[TAxxxx - <taktika>]]
- **Altechnikák:** [[Txxxx.001 - <név>]] · [[Txxxx.002 - <név>]]
- **Rokon technikák:** [[Txxxx - <rokon technika>]] — <miért kapcsolódik (átfedő eszköz, közös telemetria, gyakori lánc)>
- **Fogalmak:** [[<Alapfogalom>]]
- **MITRE:** <url>

## Saját feljegyzések

<Saját tapasztalat, nyitott kérdés, amit még meg kell érteni.>
