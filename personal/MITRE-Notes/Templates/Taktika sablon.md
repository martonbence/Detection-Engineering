---
mitre_id: TAxxxx
mitre_type: tactic
name: <angol név>
aliases:
  - TAxxxx
  - <angol név>
url: https://attack.mitre.org/tactics/TAxxxx/
matrix_position: <hányadik a mátrixban, 1-14>
technique_count: <db>
coverage: <teljes | részleges | nincs | hatókörön kívül>
---
# TAxxxx — <angol név>

## Cél

<2-4 mondat: mit akar elérni a támadó ebben a fázisban, és miért éri meg neki. Nem felsorolás — összefüggő szöveg, mert ez az a rész, amit fél év múlva újraolvasva vissza kell adnia a lényeget.>

> [!quote] MITRE definíció
> <Az attack.mitre.org egymondatos definíciója. Külön blokkban, hogy mindig látszódjon, mi az övék és mi a saját megfogalmazásod.>

## Hely a támadási láncban

- **Előtte tipikusan:** [TAxxxx - <előző taktika>]  *(taktika-hivatkozás szándékosan egykapcsos: ne kösse össze a taktikákat a gráf nézetben)*
- **Utána tipikusan:** [TAxxxx - <következő taktika>]
- **Mit feltételez:** <milyen állapotban kell lennie a támadónak ahhoz, hogy ide eljusson>

## Technikák

| ID                  | DE prioritás | Lefedettség | Megjegyzés |
| ------------------- | :----------- | :---------- | :--------- |
| [[Txxxx - <név>]]   |              |             |            |

## Detekciós stratégia (taktikai szint)

<Hol él a detekció ennél a taktikánál általánosan: melyik telemetria hordozza a súlyt (Sysmon / natív Windows log / hálózati / cloud audit), mi a taktikára jellemző közös FP-forrás, és mi az, ami ezen a szinten egyáltalán nem látható. A konkrét logika a technika- és altechnika-jegyzetekbe tartozik, ide csak az irány.>

## Lefedettség ebben a repóban

<Hány szabály van, mely technikákra, és hol a legnagyobb hiány. Egy-két bekezdés, nem táblázat — a részletes állapot a technika-jegyzetekben van.>

## Saját feljegyzések

<SOC-ban látott minták, környezet-specifikus megjegyzések, nyitott kérdések, amiknek utána kell nézni.>
