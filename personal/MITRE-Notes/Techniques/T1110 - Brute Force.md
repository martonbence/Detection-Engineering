---
mitre_id: T1110
mitre_type: technique
name: Brute Force
aliases:
  - T1110
  - Brute Force
url: https://attack.mitre.org/techniques/T1110/
tactic:
  - "[[TA0006 - Credential Access]]"
subtechnique_count: 4
platforms:
  - Windows
de_priority: magas
coverage: nincs
status: kész
---
# T1110 — Brute Force

## Lényeg

A támadó **nem ismer érvényes hitelesítő adatot** (vagy csak egy hash-t, jelszó nélkül), és ezt szisztematikus próbálgatással próbálja pótolni — ellentétben a [[T1557 - Adversary-in-the-Middle]]-lel, ahol a hitelesítő adat egy hamis hálózati pozícióból *érkezik hozzá*. A közös nevező a négy altechnikában nem egy protokoll, hanem a **próbálgatás iránya és forrása**: vagy közvetlenül egy élő hitelesítési szolgáltatás ellen fut sok kísérlet (online), vagy egy már megszerzett hash ellen, a támadó saját gépén, kapcsolat nélkül (offline).

Ez az irány-különbség a legfontosabb DE-tanulság: az **online** altechnikák (.001, .003, .004) mindegyike **sok sikertelen hitelesítési kísérletet** hagy a célrendszeren vagy a domain controlleren — ez natívan naplózott, jól detektálható jel. Az **offline** (.002) viszont a támadó saját infrastruktúráján zajlik, semmilyen forgalmat nem generál a védett környezet felé, amíg a feltört jelszót ténylegesen fel nem használja — az pedig egy darab, teljesen normálisnak látszó sikeres bejelentkezés.

> [!quote] MITRE definíció
> Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.

## Mihez vezet

Egy sikeres próbálgatás közvetlenül **érvényes hitelesítő adatot** ad — innentől a támadó tevékenysége legitim bejelentkezésnek látszik. Ha a feltört/kitalált fiók kiemelt jogú, ez azonnal [TA0004 - Privilege Escalation]; tipikusabban azonban a cél a kezdeti belépési pont vagy egy oldalirányú mozgáshoz használható fiók megszerzése — ez utóbbi esetben [TA0008 - Lateral Movement] felé vezet, ugyanúgy, mint a [[T1557 - Adversary-in-the-Middle]] relay-ága, csak jelszótörés/próbálgatás útján, nem hálózati pozícióból.

## Altechnikák

- [[T1110.001 - Password Guessing]] — **egy (vagy kevés) fiók**, sok jelszó; a klasszikus "brute force" szűk értelemben, magas lockout-kockázattal
- [[T1110.002 - Password Cracking]] — offline, egy már megszerzett hash ellen; a támadó saját gépén fut, a védett környezet felé semmilyen forgalmat nem generál
- [[T1110.003 - Password Spraying]] — **sok fiók**, kevés (gyakori) jelszó; pont azért fordítja meg a .001 logikáját, hogy elkerülje a fiók-szintű lockout-küszöböt
- [[T1110.004 - Credential Stuffing]] — ugyanazok az eszközök, mint .001/.003-nál, de a bemenet nem kitalált jelszó, hanem egy **másik, független incidensből szivárgott, már helyes** felhasználónév:jelszó pár — a jelszó-újrafelhasználásra épít

## Összehasonlítás

|                    | [[T1110.001 - Password Guessing\|.001 Password Guessing]] | [[T1110.002 - Password Cracking\|.002 Password Cracking]] | [[T1110.003 - Password Spraying\|.003 Password Spraying]] | [[T1110.004 - Credential Stuffing\|.004 Credential Stuffing]] |
| ------------------ | ------------------------------------------------------------ | -------------------------------------------------------------- | ---------------------------------------------------- | ------------------------------------------ |
| **Minta**          | 1 (vagy kevés) fiók × sok jelszó                              | n/a — offline, nincs élő kísérlet                                | sok fiók × kevés, gyakori jelszó                       | sok fiók × sok, de *páronként helyes* jelszó |
| **Mit szerez meg** | egy találgatott jelszó, ha eltalálja                          | egy már birtokolt hash tiszta szövegű jelszava                  | egy gyakori jelszót viselő fiók(ok)                    | egy másik szivárgásból ismert, itt is működő pár |
| **Irány**          | online, célzott                                                | offline, a támadó gépén                                         | online, szórt                                          | online, szórt, gyakran elosztott forrás-IP-kről |
| **Eszközök**       | Hydra, CrackMapExec/NetExec                                    | hashcat, John the Ripper (+ előfeltétel: `secretsdump.py` a hash-hez) | kerbrute, DomainPasswordSpray.ps1, CrackMapExec spray-mód | Hydra `-C` combo-lista, CrackMapExec, dedikált stuffing-eszközök (pl. OpenBullet-szerűek) |
| **Telemetria**     | 4625 (sok, egy fiókra), 4771/4776                              | **nincs** — a védett környezet felé semmilyen forgalom            | 4625/4771 (sok fiókra, kevés/fiók), forrás-IP szerint csoportosítva | 4625/4776, magas siker-arány, gyakran sok különböző forrás-IP |
| **Detekció helye** | végpont/DC (natív log)                                          | —                                                                 | DC (natív log)                                          | DC + alkalmazás-/cloud-oldali auth-log (OWA, O365, SSO) |
| **DE prioritás**   | magas                                                            | alacsony (nincs mit detektálni)                                  | magas                                                   | magas                                       |

A legfontosabb sor a **Minta**: a `.001` és a `.003` ugyanazt a jelenséget nézi két, egymással ellentétes tengelyen — ez az oka, hogy **nem építhető egy közös szabály** rájuk (lásd Detekciós stratégia). A `.004` mindkettőtől abban különbözik, hogy nem *találgat*, hanem *már helyes* párokat próbál — ez a siker-arányban látszik meg a legjobban.

## Mitigáció

- **Fiók-lockout házirend** — a `.001` ellen közvetlenül hatásos (kevés próbálkozás után lezárja a célfiókot), de **a `.003` pont ez ellen van tervezve**: a támadó a küszöb alatt marad fiókonként, miközben sok fiókot próbál. Ez fontos DE-tanulság: sok szervezet azt hiszi, a lockout "megoldja" a brute force-ot — valójában csak a `.001`-et zárja le, a `.003`-at nem.
- **MFA, különösen külső elérésű szolgáltatásokon** — az egyetlen kontroll, ami mind a négy altechnikánál hatásos *azután is*, hogy a jelszó helyesnek bizonyul: egy helyes jelszó önmagában nem elég. Ez teszi a `.004`-nél (ahol a jelszó *tényleg* helyes) a gyakorlatban az egyetlen valódi védelmet.
- **Tiltott/gyakori jelszavak listája (NIST-stílusú jelszóházirend)** — a `.003` ellen specifikusan hatásos: ha a sprayelt gyakori jelszavak (`Summer2026!`, `Welcome1`) eleve tiltottak, a szórásnak nincs mit eltalálnia.
- **Proaktív fiók-reset ismert szivárgás ellen (Have I Been Pwned-szerű feed)** — ez a `.004` saját, MITRE által is nevesített (M1018) mitigációja: a védekezés *a próbálkozás előtt* történik, nem a detekción múlik.
- **Jelszóhossz/komplexitás** — a `.002`-nél az egyetlen releváns kontroll, mert ez emeli a offline törés költségét; online egyik altechnikánál sem sokat számít (a lockout/MFA sokkal erősebb gát).

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés | Érintett altechnika |
| ---------- | ----- | ---------- | -------------------- |
| Windows Security 4625 | Logon (Failure) | sikertelen bejelentkezés — `auditpol`: Logon/Logoff → Audit Logon (Failure) | .001, .003, .004 |
| Windows Security 4771 | Kerberos Auth (Failure) | Kerberos pre-auth hiba — `auditpol`: Account Logon → Audit Kerberos Authentication Service (Failure) | .001, .003 (főleg kerbrute-jellegű eszközöknél) |
| Windows Security 4776 | Credential Validation (Failure) | NTLM hitelesítés-ellenőrzés hibája — `auditpol`: Account Logon → Audit Credential Validation (Failure) | .001, .003, .004 |
| Windows Security 4624 (Type 3) | Logon (Success) | a sikeres bejelentkezés a sok hiba után/mellett — korrobációra | .001, .003, .004 |
| Alkalmazás-/cloud-auth log (OWA, O365, SSO) | Application | külső elérésű szolgáltatásoknál gyakran itt van a legjobb jel, nem a DC-n | .003, .004 |

### Detekciós lehetőség

Ez a taktika-rész strukturálisan **fordítottja** annak, amit a [[T1557 - Adversary-in-the-Middle]] jegyzet mutat: ott csak a `.001`-nek volt végponti lába, itt viszont **három a négyből** (`.001`, `.003`, `.004`) natívan, jól naplózott — csak nem Sysmonon, hanem a domain controller Security logján. A repo saját `docs/credential-access-buildout.md` tervező dokumentuma ezt már fel is mérte (N4 sor): a szükséges `auditpol` alkategóriák ismertek, a hiányzó láncszem a `service: security` log-forrás pipeline-beli bekötése, nem a detekciós logika.

**A `.001` és a `.003` ugyanazt a jelet nézi, két ellentétes tengelyen — ezért nem egy szabály.** A `.001` küszöbe *egy fiókra* vetített hibaszám (sok hiba, ugyanaz a `TargetUserName`); a `.003` küszöbe *egy forrásra* vetített, *különböző fiókok száma* (kevés hiba fiókonként, de sok különböző fiók, azonos forrásból/időablakban). A két aggregáció más SPL-alakot igényel (`stats count by user` vs. `stats dc(user) by src_ip`), ezért a `docs/credential-access-buildout.md` is két külön szabályt tervez (0040 alatt, "likely two rules in practice").

**A spray/guessing megkülönböztethető az egyszerű fiók-enumerációtól is** — a Windows a `SubStatus` mezőben eltérő kódot ad rossz jelszóra (`0xC000006A`) és nem létező felhasználónévre (`0xC0000064`). Egy támadó, aki csak azt teszteli, mely felhasználónevek léteznek (nem a jelszót próbálja), túlnyomórészt `0xC0000064`-et generál — ez más minta, mint a valódi `.001`/`.003`, ahol a felhasználónév helyes, csak a jelszó nem.

**A `.004` a fentiekkel azonos telemetrián él, de a mintája eltér**: nem *egy* gyakori jelszó sok fiókon (mint `.003`), hanem *sok, egymáshoz nem hasonló* jelszó, fiókonként *pontosan egy*, valós (nem találgatott) párosítással — ez a magasabb sikerarányban (4624/4625 arány) és gyakran az elosztott forrás-IP-kben (rezidenciális proxy-pool, hogy az IP-alapú rate-limitet is kikerülje) látszik.

**A `.002`-nél nincs mit építeni** — ez teljesen a támadó saját infrastruktúráján zajlik, a védett környezet felé semmilyen forgalmat nem generál. Az egyetlen detektálható lépés a hash *megszerzése* (LSASS-dump, NTDS.dit-kiolvasás), ami már [[T1003 - OS Credential Dumping]] és [[T1558 - Steal or Forge Kerberos Tickets]] hatásköre — a `.002` maga strukturálisan láthatatlan, ugyanúgy, ahogy a [[T1557 - Adversary-in-the-Middle]] `.002`/`.003`/`.004` altechnikái is azok, csak más okból (ott hálózati réteg, itt offline számítás).

**Pipeline-oldali megkötés, amit érdemes fejben tartani:** ez a repo Sigma-korrelációs szabályokat (multi-document YAML) **nem tud betölteni/futtatni** — a `scripts/lib/rules.py`/`sigma_to_spl.py` egy-fájl-egy-`detect_id` feltevésre épül, és a séma sem enged `name:`-alapú korrelációs referenciát. Emiatt egy jövőbeli `.001`/`.003`/`.004` szabály nem natív Sigma `correlation:` blokkal, hanem a `custom.splunk.raw_query` fallback-kal fog aggregálni (lásd [[sigma-rule-authoring]]) — ugyanaz a mechanizmus, amit a repo már a Kerberoasting-tervnél (0039) is használ.

## Kapcsolódó szabályok

*Nincs még megépített szabály erre a technikára.* A `docs/credential-access-buildout.md` Track B terve **0040** néven ütemezi ("Password Spraying and Brute Force", T1110.001/.003/.004, 4625+4771+4776, `raw_query` aggregáció), a `service: security` log-forrás pipeline-beli bevezetése után (0037 DCSync a "proof point" előtte). A `.002`-re nincs és nem is tervezett szabály — lásd Detekciós lehetőség.

## Kapcsolódó jegyzetek

- **Rokon technikák:** [[T1003 - OS Credential Dumping]] — a `.002` offline törésének előfeltétele (innen jön a hash); [[T1558 - Steal or Forge Kerberos Tickets]] — a Kerberos-oldali testvér-technika, hasonlóan natív-log-only, ugyanazon a DC audit-policy alapon épül
- **MITRE:** https://attack.mitre.org/techniques/T1110/

## Saját feljegyzések
