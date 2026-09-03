<img src="docs/pictures/branding/logo.png" alt="Detection-Engineering logo" width="200">

# Detection-Engineering

*<small>What isn't proven is assumption.</small>*

<!-- STATS_START -->
[![Total Rules](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_rules&label=Total%20Rules&color=informational)](https://github.com/martonbence/Detection-Engineering/tree/main/rules)

[![Sigma Rules](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_compiled_sigma_rules&label=Sigma%20Rules&color=00ACD7)](https://github.com/martonbence/Detection-Engineering/tree/main/rules/sigma) [![Native SPL](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_native_spl_rules&label=Native%20SPL&color=FF6600)](https://github.com/martonbence/Detection-Engineering/tree/main/rules/splunk)

![Pass](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.verified_pass_current&label=Pass&color=brightgreen) ![Fail](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.verified_fail_current&label=Fail&color=red) ![Pass Rate](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.pass_rate_pct&label=Pass%20Rate%20%25&color=brightgreen) ![Not Verified](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.not_verified&label=Not%20Verified&color=lightgrey) ![MITRE Coverage](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.mitre_coverage_pct&label=MITRE%20Coverage%20%25&color=8f95d6)
<!-- STATS_END -->

## The live picture

Generated views of where the rule library actually stands right now — regenerated and published by both the `dev` and `prod` workflows, and recomputed against the current date on every load.

<table>
<tr>
<td><img src="docs/pictures/branding/rule_browser.png" width="150" alt="Rule Browser icon"></td>
<td><strong><a href="https://martonbence.github.io/Detection-Engineering/">Rule Browser</a></strong><br>Every rule in the repo — searchable, filterable, sortable, each carrying the verdict the pipeline last measured for it.</td>
</tr>
<tr>
<td><img src="docs/pictures/branding/mitre_navigator.png" width="150" alt="MITRE Navigator icon"></td>
<td><strong><a href="https://martonbence.github.io/Detection-Engineering/#tab=navigator">MITRE Navigator</a></strong><br>The coverage and the gaps, laid over the full ATT&amp;CK matrix — and exportable straight into MITRE's own Navigator.</td>
</tr>
<tr>
<td><img src="docs/pictures/branding/dashboards.png" width="150" alt="Dashboards icon"></td>
<td><strong><a href="https://martonbence.github.io/Detection-Engineering/#tab=dashboards">Dashboards</a></strong><br>The big-picture view of the detection program — what the library adds up to today, and how it got there.</td>
</tr>
</table>

## Under the hood

When the live views prompt a "but how?", these go down to the mechanics — every stage, the artefacts that move between them, the threat model, and a per-file map of the pipeline.

<table>
<tr>
<td><img src="docs/pictures/branding/architecture.png" width="125" alt="Architecture icon"></td>
<td><strong><a href="docs/architecture/">Architecture</a></strong><br>How every moving part actually works, in prose and diagrams — from a Sigma file to a prod deploy.</td>
</tr>
</table>

## The team behind it

This repo is maintained largely by a small team of scoped AI agents under a human lead — each owning one surface. The rules of engagement — every agent's scope, the review gates, and what stays the human's call — are in [`CLAUDE.md`](CLAUDE.md).

<table>
<tr>
<td><img src="docs/pictures/branding/team.png" width="120" alt="Team dashboard icon"></td>
<td><strong><a href="https://martonbence.github.io/Detection-Engineering/team-ops.html">Team Dashboard</a></strong><br>Every agent, their scope, their place in the org chart, and what they've actually shipped.</td>
</tr>
</table>

## The problem this repo solves

Most "detection-as-code" projects stop at the linter: once a rule's YAML parses, it counts as finished. That leaves unanswered the questions that actually matter to a security team — is the rule still live in the SIEM, does it fire when the technique it targets is genuinely executed, and does anyone find out the moment that stops being true?

This repository closes that loop end to end, automatically, on every change:

- **Authored once.** Each detection is a single file carrying its full definition: logic, severity, MITRE ATT&CK mapping, and test plan.
- **Deployed for real.** The rule is installed as a live saved search in a running SIEM (Splunk), not merely validated on paper.
- **Exercised by a real attack.** The technique the rule targets is executed against a live host — through Atomic Red Team, or a custom emulation script where the technique needs one — and the SIEM is then queried for the resulting detection.
- **Promoted only on evidence.** A rule reaches the production environment only after clearing that entire loop in an isolated proving ground first.
- **Revalidated over time.** A passing verdict has a shelf life: it is invalidated when the rule's logic changes, and it expires when too long passes without a re-test. A stale result does not count as proof.

Nothing here about whether a detection works is self-reported. Every verdict is a measurement the pipeline made — and it can show its work.

## How it fits together

The pipeline runs in five phases — Strategic, Development, Validation, its nested Testing phase, and Measurement & Reporting — with a Calibration feedback loop that carries verification results back into Development.
The diagram below spans both workflows that implement it: `ci_dev_workflow.yml`, which runs the full detection engineering CI/CD pipeline on the `dev` branch, and `ci_prod_workflow.yml`, which deploys already-verified rules to the production Splunk app once a promotion PR merges to `main`.

<p align="center">
  <a href="https://raw.githubusercontent.com/martonbence/Detection-Engineering/dev/docs/pictures/Workflow.drawio.svg" target="_blank" rel="noopener">
    <img src="docs/pictures/Workflow.drawio.svg" alt="Detection-Engineering pipeline diagram: the Strategic Phase feeds the Development Phase (write a Sigma or native-SPL rule, validate against the schema, convert to SPL), which feeds the Validation Phase (deploy to the dev proving-ground Splunk, then a nested Testing Phase running Atomic Red Team and script-emulation tests on a Windows workstation and/or domain controller, then a pass/fail verification), which feeds the Measurement &amp; Reporting Phase (update docs and stats, deploy GitHub Pages, open a promotion PR to main, notify Slack) — with a Calibration / Tune feedback loop running from Verification back into Development; merging the promotion PR triggers a separate prod workflow that deploys the verified rules to production Splunk." width="900">
  </a>
</p>
<p align="center"><sub>Click the diagram to open the full-size vector (browser zoom works cleanly on it).</sub></p>

Reading the diagram top to bottom:

- **Strategic** — the *why* and the *what*: deciding which adversary techniques are worth detecting and threat-modelling the coverage gap. This phase is human and agent judgement, not automation — no workflow runs here.

- **Development** — the *how*: author the detection as a single Sigma rule or a native-SPL rule, then [`ci_dev_workflow.yml`](workflows/ci_dev_workflow.yml) validates it against the JSON schema, checks test routing, MITRE tags and version-bump discipline, and converts it to a deployable `.spl` query plus a metadata sidecar.
- **Validation** — the *proof*: the rule is deployed as a live saved search in the `dev` proving-ground Splunk, then the nested **Testing** phase runs the real attack against a live host. The rule's own `custom.testing` config independently picks the target host (a domain-joined Windows workstation and/or the domain controller) and the mechanism (an Atomic Red Team test and/or a script-emulation test). Both hosts are VMs running a Splunk Universal Forwarder that ships their Windows Event Log and Sysmon telemetry to the `dev` Splunk instance, so the attack's traces land there for Verification to query for the resulting hit and write a pass/fail verdict per rule.
- **Measurement & Reporting** — the run folds those verdicts into `outputs/reports/`, regenerates the rule library, the MITRE Navigator and the dashboards, republishes GitHub Pages, opens a **promotion PR** to `main` for the rules that just passed, and sends a Slack summary notification, that contains the result of the workflow and a link to the run.
<br>When a human merges that PR, `ci_prod_workflow.yml` takes over: it re-verifies each rule's build provenance and deploys the promoted rules to the production Splunk app.
- **Calibration** — the feedback loop: It exists because a passing verdict decays: editing a rule's logic invalidates its last result and age-out expires a stale one, so the loop re-runs the whole attack-and-measure cycle to keep every "PASS" badge honest.

One caveat: the lab environment — the dev Splunk and the victim VMs (workstation + DC) — isn't always running, so a repository variable, `LAB_ONLINE`, decides the run path — with it true the pipeline deploys, attacks and verifies; with it false a push still validates, converts and commits its SPL and still passes green, but nothing is deployed, attacked or measured. The rule browser therefore leads with a last live verification date and an ATT&CK coverage figure rather than a bare pass count, since a passing run doesn't by itself mean a rule was deployed and exercised.

## What "pass" actually means here

A checkmark in this repo is not a claim the rule's author made about their own work. It's the output of a pipeline that deployed the rule for real, ran a real attack technique, and queried the SIEM for a real hit. And a verdict doesn't stay valid forever by default: edit the rule and the old result stops applying to it; let too much time pass without re-testing and the result ages out on its own. A rule only counts as "proven" while there's still a recent measurement that actually matches the logic currently sitting in the file. The exact mechanics of how that's computed — and there's a fair amount of nuance to it — live in [`docs/architecture/`](docs/architecture/) rather than here.

## Building a new detection, in broad strokes

1. **Write** the detection as a single Sigma-format rule file — logic, severity, MITRE mapping, and test plan all live together in that one file. If the underlying idea genuinely can't be expressed in Sigma's own syntax, the same file can carry the raw SIEM query directly instead; either way there is one authoring format and one pipeline, not two.
2. **Open a pull request.** The pipeline validates and compiles the rule before anything else happens, and shows you the result before it's merged.
3. **Merge, and the pipeline takes over**: it deploys the rule, runs the attack technique it's meant to catch, and checks whether it actually fired.
4. **Watch it show up** in the [rule browser](https://martonbence.github.io/Detection-Engineering/) with a real verdict and its place on the ATT&CK matrix.
5. **Once proven**, the rule becomes eligible to be promoted from the proving-ground branch to production — via a pull request the pipeline opens for a human to review and merge, never automatically.

The full step-by-step version of this — exact filenames, the scaffold command, which checks gate what — is in [`CONTRIBUTING.md`](CONTRIBUTING.md), with the deeper mechanics in [`docs/architecture/`](docs/architecture/).

## Repository layout

| Path | What's there |
|---|---|
| [`rules/sigma/`](rules/sigma/) | The source of truth — every detection rule, as Sigma YAML |
| [`rules/splunk/`](rules/splunk/) | The compiled, deployable query for every rule |
| [`scripts/`](scripts/) | The pipeline itself, one subdirectory per stage (validate, convert, deploy, atomic, verify, docs, state) — see [`docs/architecture/scripts_reference.md`](docs/architecture/scripts_reference.md) for what each file does |
| [`config/`](config/) | Pipeline configuration as data, not code |
| [`tests/`](tests/) | The pipeline's own automated test suite |
| [`docs/index.html`](https://martonbence.github.io/Detection-Engineering/) | The generated rule browser and MITRE Navigator — live on GitHub Pages |
| [`docs/architecture/`](docs/architecture/) | Deeper technical references, with diagrams |
| [`outputs/reports/`](outputs/reports/) & [`outputs/results/`](outputs/results/) | Generated stats and per-rule verification results |
| [`.github/workflows/`](.github/workflows/) | The automation that runs the whole pipeline |

## Run by GitHub's own tooling, too

Part of what this repo is meant to demonstrate is disciplined use of GitHub itself as the engineering platform, not just as a place to host YAML: planned work is tracked as Issues, sequenced on a GitHub Project board, and the pipeline's own promotion pull requests are wired into that same board automatically rather than living in a separate tracker. For a newcomer, the polished starting point is the [Rule Browser](https://martonbence.github.io/Detection-Engineering/), followed by [`CONTRIBUTING.md`](CONTRIBUTING.md) and the deeper references in [`docs/architecture/`](docs/architecture/).

## Further reading

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — the end-to-end flow for adding a new detection, plus [how to run the lint + test checks locally](CONTRIBUTING.md#running-the-checks-locally)
- [`docs/architecture/`](docs/architecture/) — pipeline overview, data flow, threat model, a per-file scripts reference, and the agent-workflow guide, all with Mermaid diagrams
- [`LICENSE`](LICENSE) — MIT
