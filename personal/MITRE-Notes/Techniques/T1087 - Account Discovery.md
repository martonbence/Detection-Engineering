---
mitre_id: T1087
mitre_type: technique
name: Account Discovery
aliases:
  - T1087
  - Account Discovery
url: https://attack.mitre.org/techniques/T1087/
tactic:
  - "[[TA0007 - Discovery]]"
subtechnique_count: 4
platforms:
  - Windows
  - Linux
  - macOS
  - Cloud
de_priority: magas
coverage: részleges
status: kész
---
# T1087 — Account Discovery

## Lényeg

A támadó felderíti, mely fiókok (helyi, domain, e-mail, cloud) léteznek a célkörnyezetben — nem egy fiók jelszavát próbálja kitalálni, hanem magát a fiók *létezését* deríti fel, tipikusan egy későbbi, célzottabb credential-access lépés (brute force, password spraying, célzott phishing) előkészítéseként. A négy altechnika a **fiók-hatókör** szerint különül el: helyi gépi fiókok, domain-fiókok, e-mail-fiókok, illetve cloud-identitások.

A legérdekesebb eset — és a repóban ténylegesen lefedett forma — az, amikor ez nem direkt LDAP/SAM-lekérdezéssel történik (amit egy jól konfigurált AD nem enged meg mindenkinek), hanem egy **hitelesítési oracle** kihasználásával: a válaszkód különbségéből ("a fiók nem létezik" vs. "rossz jelszó, de a fiók létezik") derül ki, mely nevek valósak, anélkül hogy egyetlen zárolást is kockáztatna.

> [!quote] MITRE definíció
> Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a compromised environment. This information can help adversaries determine which accounts exist to aid in follow-on behavior.

## Altechnikák

- .001 Local Account — egy gép saját helyi felhasználói fiókjainak felsorolása (`net user`, `/etc/passwd`); nincs lefedve
- **[[T1087.002 - Domain Account]]** — domain-fiókok létezésének felderítése hitelesítési oracle-lel (Kerbrute userenum és rokon eszközök); **lefedve, 1 szabály**
- .003 Email Account — postafiók-nevek/e-mail-címek felderítése (Global Address List, SMTP-alapú enumeráció); nincs lefedve
- .004 Cloud Account — cloud-identitás-szolgáltatás (Azure AD/Entra ID, AWS IAM) fiókjainak felsorolása API-hívásokkal; nincs lefedve, cloud-telemetria nélkül

## Mitigáció

- **A MITRE ehhez a technikához elsősorban a detekciót javasolja megelőző kontroll helyett** — a hitelesítési válasz maga a protokoll (Kerberos/NTLM/SMTP) normál, szükséges működése.
- **Null session / anonim SAM-enumeráció letiltása** (`RestrictAnonymous`) megszünteti a *direkt* LDAP/SAM-alapú enumerációs utat (.001, .002 direkt formája), de nem hat az oracle-alapú (hitelesítési válaszkód-különbségen alapuló) formára.
- **Cloud IAM naplózás és riasztás szokatlan tömeges API-lekérdezésre** — a .004 egyetlen realista védelme, cloud-natív audit log nélkül nem kivitelezhető.
- **Fiók-zárolási politika nem releváns kontroll** a jelenleg lefedett formára: a technika lényege pont az, hogy egyetlen valós jelszót sem próbál ki létező fiókon.

## Detekciós stratégia

### Szükséges telemetria

| Adatforrás | Típus | Megjegyzés | Érintett altechnika |
| ---------- | ----- | ---------- | -------------------- |
| Windows Security 4625/4768/4776 | Logon | "nem létező fiók" válaszkódok — a jelenlegi egyetlen szabály erre épül | .002 |
| Windows Security 4798/4799 (helyi fiók/csoport enumeráció) | Account | — nincs bekötve | .001 |
| Exchange/O365 GAL-hozzáférési log | Application | — nincs ebben a pipeline-ban | .003 |
| Cloud IAM audit log (Entra ID sign-in/Graph API, AWS CloudTrail) | Cloud | — nincs bekötve | .004 |

### Detekciós lehetőség

A repó lefedettsége a **.002 Domain Account** oracle-alapú formájára korlátozódik, és ott is tudatosan a "*nem létező* fiók" válaszkódokra szűkít, megkülönböztetve a [[T1110.001 - Password Guessing]]/[[T1110.003 - Password Spraying]] "*létező* fiók, rossz jelszó" logikájától (lásd [[T1087.002 - Domain Account]] Detekciós logika szakaszát). A .001 Local Account és .003 Email Account strukturálisan hasonló, natív Windows Security-alapú (4798/4799) vagy alkalmazás-audit-alapú detekcióval lenne megközelíthető, de egyik sincs implementálva. A .004 Cloud Account ettől eltérő adatforrást (cloud IAM audit log) igényelne, ami teljesen kívül esik a jelenlegi, végponti/DC-fókuszú pipeline-on.

## Kapcsolódó szabályok

| detect_id | Altechnika | Miért szükséges |
| --------- | ---------- | --------------- |
| [DETECT-2026-0004](https://github.com/martonbence/Detection-Engineering/blob/main/rules/sigma/DETECT-2026-0004_Windows-Domain-Account-Enumeration-via-Authentication-Response-Differences.yml) (lásd [[T1087.002 - Domain Account]]) | .002 | Hitelesítési oracle alapú fiók-enumeráció (Kerbrute userenum és rokon eszközök) — "nem létező fiók" válaszkódokra szűkítve |

**Nem fedett:** .001 Local Account, .003 Email Account, .004 Cloud Account.

## Kapcsolódó jegyzetek

- **Rokon technikák:** [[T1110 - Brute Force]] — a Domain Account enumeráció klasszikus előkészítő lépése egy password spraying/guessing kampánynak, ugyanazon a natív DC audit-policy alapon
- **MITRE:** https://attack.mitre.org/techniques/T1087/

## Saját feljegyzések
