# GitHub Marketplace tooling — mit érdemes bevezetni

**Készítette:** Yara (Technology Strategist) · **Dátum:** 2026-09-09 · **Státusz:** javaslat, még nincs zöld út
**Hatókör:** a repo CI/CD- és fejlesztői toolchainje. Kutatás + javaslat — nincs implementálva semmi.

> Yara elemzése alapján. A zizmor-findingok mértek (Yara lefuttatta a repóra); a `sigma check` payoff nem mért, spike kell hozzá.

---

## A vezérelv

A repónak van egy le nem írt szabálya: **minden lintert pinned CLI-ként futtat `run:` blokkban, sose Marketplace action-ként.** Az egyetlen `uses:` az `actions/*`. Indok: a workflow-k prod Splunk credentialt (`SPLUNK_PASSWORD`) és `GH_PAT_DEV_PUSH`-t tartanak, három job self-hosted lab-gépen fut → egy third-party action valódi supply-chain kockázat.

**Ezért: „vedd át az eszközt, ne az actiont."** Az alábbi ajánlások szinte mind CLI-ként, meglévő jobba beillesztve.

---

## Csináld ezeket előbb (top 5)

### 1. zizmor — GitHub Actions statikus elemző (pinned pip CLI)
- **Mit:** template injection, credential persistence, overscoped token, unpinned uses elemzése a workflow-kban.
- **Miért — MÉRT adat:** Yara lefuttatta. **14 medium finding**, mind ugyanaz: minden `actions/checkout`-ból hiányzik a `persist-credentials: false`. Ebből **4 viszi a `GH_PAT_DEV_PUSH`-t**, **2 self-hosted runneren fut** (`de-lab`), aminek a workspace-e nem eldobható VM.
- **Miért fontos:** ez egy **félbehagyott döntés teteje**. A 4.4 audit már kivette a PAT-ot a self-hosted verify jobból („nincs rá szüksége"), de a default `GITHUB_TOKEN` ott marad a `.git/config`-ban. A `persist-credentials: false` ennek a döntésnek a maradéka.
- **Az `actionlint` NEM fedi** — az schema/korrektség linter, nincs credential-audit része. Nulla átfedés.
- **Költség:** `zizmor==1.30.1` a `requirements-dev.txt`-be + egy step a `ci_code_checks.yml` `workflow_analysis` jobjába, az `actionlint` mellé. Kezdés: `--min-severity medium` (14 finding, mind auto-fix van rá).
- **NE a `zizmor-action`-t** — az `security-events: write`-ot kér és default módban nem bukatja a buildet findingra.
- **Ki:** Jamal wire-öli, Priya triage-eli. A `persist-credentials` fix Jamal.

### 2. GitHub Actions policy allow-list (repo setting, 0 kód)
- **Mit:** Settings → Actions → „Allow `actions/*` and selected", explicit SHA allow-listtel.
- **Miért:** a „first-party only, SHA-pinned" konvenció most **kulturális** — semmi nem állít meg egy jövőbeli workflow-editet, ami third-party action-t ad egy `SPLUNK_PASSWORD`-öt tartó jobhoz. A repo szereti a jó konvenciókat mechanikus gate-té alakítani (`check_version_bump.py` ugyanez a mozdulat). Egy toggle.
- **Ki:** Kai.

### 3. CodeQL default setup (repo setting, ingyen, first-party, nincs workflow-fájl)
- **Mit:** GitHub saját SAST-ja, Python + JavaScript, publikus repóra ingyen.
- **Miért — két valódi rés:** (a) a semgrep csak Priya ad-hoc MCP-auditja, nincs folyamatos; (b) a `page.js` ~7500 sor front-end, amin **nulla** statikus biztonsági elemzés van (csak `node --check` + Playwright smoke). A Python oldal sem triviális: `deploy_spl_to_splunk.py`, `splunk_client.py` credentialt/HTTP-t/TLS-t kezel.
- **Költség:** repo setting (default setup — NEM az advanced `github/codeql-action` workflow, az egy 5. workflow-fájl + 10-15 perc). Findingok a Security tabon, nem merge-blocker.
- **Ki:** Kai engedélyezi, Priya triage.

### 4. gitleaks CLI + custom `SPLUNK_*` ruleset (NEM a `gitleaks-action`)
- **Mit:** secret scanner binárisként CI-ben, repo-local `.gitleaks.toml`-lal.
- **Miért — a konkrét rés:** a GitHub ingyenes publikus secret scanningje csak **partner-patterneket** néz (AWS, Slack stb.). A `SPLUNK_USERNAME/PASSWORD/BASE_URL` és a lab hostnevek: nincs partner-pattern, nincs issuer, akit értesítsen → egy commitba beillesztett lab-credential **ma láthatatlan**. Custom pattern = fizetős GitHub Secret Protection. Egy 10 soros `.gitleaks.toml` ingyen zárja.
- **Miért a bináris:** a `gitleaks-action` commercial EULA-s, org-repóhoz licenckulcs kell. A MIT bináris `run:` blokkban ugyanezt tudja (mint az `actionlint`).
- **NEM fedi:** a `matched-events` artefakt aggodalmat — az már megoldott (`anonymize_matched_events.py` fut upload előtt, fail-closed). Secret scanner git-historyt néz, nem artefaktot.
- **Ki:** Priya írja a rulesetet, Jamal wire-öli.

### 5. `sigma check` — pySigma validátorok (a `sigma-cli` MÁR pinned)
- **Mit:** a `sigma-cli` validate parancsa, ~30 beépített pySigma validátor (dangling detection reference, duplikált érték, wildcard-hiba, `all of them` veszély).
- **Miért:** a `validate_sigma.py` csak a Draft-07 sémára validál — **struktúra**. A `threat_model.md` ezt ki is mondja: „Schema validity is enforced; logical soundness is not." A `DanglingDetectionValidator` pont az a hibaosztály, ami most 100% Bjorn kézi olvasása. **0 új függőség** — a `sigma-cli==3.1.0` / `pySigma==1.5.0` már a `requirements.txt`-ben van.
- **Caveat:** Yara nem tudta lefuttatni (nincs telepítve a gépén), a payoff mérve nincs. **20 perces spike kell**, mielőtt eldől — utána vagy első helyre kerül, vagy kiesik.
- **NE a Marketplace `SigmaHQ/sigma-rules-validator`-t** — az JSON-schema-only, gyengébb, mint amit a repo már csinál. Regresszió lenne.
- **Ki:** Jamal wire-öli, Bjorn dönti el, mely validátorok aktívak.

---

## Feltételes / alacsonyabb prioritás

- **StepSecurity Harden-Runner** — self-hosted runneren **némán no-op-ol** Enterprise előfizetés nélkül (pont a `pipeline-ci-gotchas` silent-skip mintája, a 1.5 / 2.14 audit-itemek erről szólnak). Csak az `ubuntu-latest` PAT-tartó jobokra érdemes (`prepare_validate_convert`, `open_promotion_pr`, `update_dashboard`), explicit kommenttel, hogy miért nincs a self-hosted jobokon. Ez a brief legmagasabb-bizalmi eleme (network-level runner hookok). Jamal + Priya sign-off.
- **OSSF Scorecard** — futtasd a **CLI-t egyszer kézzel**, ne wire-öld be. A repo már jobb, mint amit a score lát (SHA pin, Dependabot, attestation, `permissions:` minden jobon). Priya.
- **lychee** link-checker — 49 `.md` + a MITRE-vault deep linkjei. `schedule:`-re, ne push-ra (a link-rot ne pirosítson egy független commitot). **Caveat:** Obsidian `[[wikilink]]`-et és register-anchort NEM néz — a 2.12 / 2.10 audit-item-eket sem fogta volna el. Csak külső URL-rot. Jamal wire + Chloe triage.

---

## Megvizsgálva és elvetve

| Jelölt | Miért nem |
|---|---|
| SigmaHQ/sigma-rules-validator | JSON-schema-only, gyengébb a meglévőnél — regresszió |
| **pre-commit.ci / autofix.ci** | (a) a `.githooks/pre-commit` bespoke Python, nem a pre-commit framework; (b) **autofix commitokat push-ol** → a 4.4 audit-item (6 meglévő writeback path, 3-4 gépi commit/run) rosszabb lesz, ÉS ütközik a „én commitolok" szabályoddal |
| release-please / release-drafter / semantic-release | `git tag` üres, nincs release-koncepció — a „release" itt a promotion PR a `main`-re, ami már automatizált + attesztált |
| `actions/dependency-review-action` | Csak `pull_request`-en fut → csak a Dependabot bumpok + a gépi promotion PR → amit a Dependabot alerts + `pip-audit` már fed. Duplikáció |
| Renovate | A `dependabot.yml` a repo egyik legátgondoltabb configja (`target-branch: dev`, dev-tooling/pipeline-toolchain szétválasztás inline indoklással) — csere = ezt eldobni semmiért |
| labeler / PR-size / stale-bot / auto-assign | Egy-fős repo. A reporting felület már jó (`open_promotion_pr.py` per-rule verdict tábla a PR-be, `$GITHUB_STEP_SUMMARY` mind a 4 workflow-ból, Slack webhook) |
| Codecov / Coveralls | `pytest-cov` → `$GITHUB_STEP_SUMMARY` ugyanazt adja külső szolgáltatás/token nélkül. Ha kell coverage (1.6 / 4.5 audit), in-repo |
| Splunk / ATT&CK / Atomic Red Team Actionök | Nincs a Marketplace-en érdemi. A `splunk/contentctl` CLI, és alternatív *architektúra*, nem kiegészítés |

---

## Process-megjegyzés

Ha 2+ zöld utat kap ezekből, az „adopt the tool, decline the action" szabály megér **egy sort a CLAUDE.md-ben vagy a registerben** (most 5 külön inline kommentből rekonstruálható a `ci_code_checks.yml`-ben). Nem skill — egy sor elég.

## Ki mit visz (ha zöld út)

- **Jamal:** zizmor wire, gitleaks step, `sigma check` step, lychee
- **Priya:** zizmor triage, CodeQL triage, gitleaks ruleset, Scorecard CLI, Harden-Runner trust-döntés
- **Kai:** Actions allow-list, CodeQL enable
- **Bjorn:** `sigma check` validátor-scope
- **Chloe:** lychee finding-triage a doksikban

---

## Források

- [zizmorcore/zizmor](https://github.com/zizmorcore/zizmor) · [zizmor docs](https://docs.zizmor.sh/)
- [step-security/harden-runner](https://github.com/step-security/harden-runner)
- [SigmaHQ/sigma-rules-validator](https://github.com/SigmaHQ/sigma-rules-validator) · [pySigma Rule Validation](https://sigmahq-pysigma.readthedocs.io/en/latest/Rule_Validation.html)
- [gitleaks/gitleaks-action](https://github.com/gitleaks/gitleaks-action) · [gitleaks commercial license](https://gitleaks.io/COMMERCIAL-LICENSE.txt)
- [ossf/scorecard-action](https://github.com/ossf/scorecard-action)
- [actions/dependency-review-action](https://github.com/actions/dependency-review-action)
- [lycheeverse/lychee-action](https://github.com/lycheeverse/lychee-action)
- [GitHub Docs — CodeQL default setup](https://docs.github.com/code-security/code-scanning/enabling-code-scanning/configuring-default-setup-for-code-scanning)
- [GitHub Docs — supported secret scanning patterns](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns)
