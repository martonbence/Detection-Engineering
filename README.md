<img src="docs/pictures/branding/logo.png" alt="Detection-Engineering logo" width="200">

# Detection-Engineering

*<small>What isn't proven is assumption.</small>*

<!-- STATS_START -->
[![Total Rules](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_rules&label=Total%20Rules&color=informational)](https://github.com/martonbence/Detection-Engineering/tree/main/rules)

[![Sigma Rules](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_compiled_sigma_rules&label=Sigma%20Rules&color=00ACD7)](https://github.com/martonbence/Detection-Engineering/tree/main/rules/sigma) [![Native SPL](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.total_native_spl_rules&label=Native%20SPL&color=FF6600)](https://github.com/martonbence/Detection-Engineering/tree/main/rules/splunk)

![Pass](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.verified_pass_current&label=Pass&color=brightgreen) ![Fail](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.verified_fail_current&label=Fail&color=red) ![Pass Rate](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.pass_rate_pct&label=Pass%20Rate%20%25&color=brightgreen) ![Not Verified](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.not_verified&label=Not%20Verified&color=lightgrey) ![MITRE Coverage](https://img.shields.io/badge/dynamic/json?style=flat-square&url=https%3A%2F%2Fraw.githubusercontent.com%2Fmartonbence%2FDetection-Engineering%2Fmain%2Foutputs%2Freports%2Fstats.json&query=%24.mitre_coverage_pct&label=MITRE%20Coverage%20%25&color=8f95d6)
<!-- STATS_END -->

**Live views** — the published rule browser, generated straight from the pipeline's own output:

| | |
|---|---|
| <img src="docs/pictures/branding/rule_browser.png" width="200" alt="Rule Browser icon"> | **[Rule Browser](https://martonbence.github.io/Detection-Engineering/)**<br>Every rule in the repo, searchable and filterable, with its ATT&CK mapping and its current pass/fail verdict. |
| <img src="docs/pictures/branding/mitre_navigator.png" width="200" alt="MITRE Navigator icon"> | **[MITRE Navigator](https://martonbence.github.io/Detection-Engineering/#tab=navigator)**<br>The same coverage plotted against the full ATT&CK matrix, exportable as a Navigator layer for the official MITRE tool. |
| <img src="docs/pictures/branding/dashboards.png" width="200" alt="Dashboards icon"> | **[Dashboards](https://martonbence.github.io/Detection-Engineering/#tab=dashboards)**<br>Rule-library breakdowns by type, severity, status and verification outcome, MITRE tactic spread, and coverage/rule-count trends over the repo's own history. |
| <img src="docs/pictures/branding/team.png" width="200" alt="Team icon"> | **[Team](https://martonbence.github.io/Detection-Engineering/team-ops.html)**<br>The org chart for this repo's own Claude Code subagent team, a logged per-agent dispatch activity feed, and token-usage/dispatch-count stats generated from the agent usage log and this repo's own git history. |

**Reference docs** — deeper technical background, for after the live views raise a question:

| | |
|---|---|
| <img src="docs/pictures/branding/architecture.png" width="90" alt="Architecture icon"> | **[Architecture](docs/architecture/)**<br>Pipeline overview, data flow, threat model, a per-file scripts reference, and how the AI-agent team is coordinated — all with Mermaid diagrams. |

## The problem this repo solves

Most "detection as code" projects stop at linting YAML: a rule is considered finished the moment it parses. That answers almost nothing security teams actually care about — does the rule still exist in the SIEM, does it fire when the technique it claims to catch actually happens, and does anyone find out the moment that stops being true?

This repo is an attempt at closing that loop end to end, automatically, on every change:

- A detection is **written once**, in one format, with everything about it — logic, severity, MITRE ATT&CK mapping, test plan — in a single file.
- It's **shipped for real**, deployed as a live saved search in an actual SIEM (Splunk), not just validated on paper.
- It's **attacked on purpose**, using real adversary emulation (Atomic Red Team) against a real host, and then checked for whether the deployed rule actually caught it.
- Only a rule that survives that whole loop is allowed to move from a proving-ground environment into the one that matters.
- And because software rots, a "yes, this worked" verdict has a shelf life — it stops counting as evidence once the rule changes or enough time passes, rather than sitting there forever as a stale green checkmark.

Nothing about "does this detection work" is self-reported here. It's a measurement the pipeline makes and can show its work for.

## How it fits together

The five-phase shape of the pipeline, end to end — Strategic phase through Development, Continuous Integration (with its nested Testing phase), and Measurement & Reporting, plus the "Tune" feedback loop that runs verification results back into Development:

<p align="center">
  <a href="https://raw.githubusercontent.com/martonbence/Detection-Engineering/dev/docs/pictures/Workflow.drawio.svg" target="_blank" rel="noopener">
    <img src="docs/pictures/Workflow.drawio.svg" alt="Detection-Engineering pipeline diagram: Strategic Phase feeds the Development Phase (write Sigma/SPL rule, validate syntax, convert), which feeds the Continuous Integration Phase (deploy to dev Splunk, then a nested Testing Phase running Atomic Red Team and script emulation, then a pass/fail verification), which feeds the Measurement &amp; Reporting Phase (update docs and stats, deploy GitHub Pages, open a promotion PR, deploy to dev Splunk, notify Slack) — with a Tune feedback loop running from Verification back into Development." width="900">
  </a>
</p>
<p align="center"><sub>Click the diagram to open the full-size vector in a new tab (browser zoom works cleanly on it).</sub></p>

The exact job graph below is the same pipeline drawn from `ci_dev_workflow.yml`'s own dependency structure:

```mermaid
flowchart LR
    A(["Prepare, Validate, Convert"])
    B(["Deploy to Splunk"])

    subgraph tests["Attack &amp; Emulation Tests"]
        direction TB
        C(["Atomic Red Team Test"])
        D(["Atomic Red Team Test (DC)"])
        E(["Script Emulation Test"])
    end

    F(["Splunk Verification"])
    G(["Update Dashboard &amp; Docs"])
    H(["Persist Verification Results (fallback)"])

    subgraph fanout["After Dashboard Update"]
        direction TB
        I(["Open Promotion PR"])
        J(["Deploy GitHub Pages"])
        K(["Notify Pipeline Status (Slack)"])
    end

    A --> B
    A --> C
    B --> C
    A --> D
    B --> D
    A --> E
    B --> E
    A --> F
    B --> F
    C --> F
    D --> F
    E --> F
    A --> G
    F --> G
    F --> H
    G --> H
    F --> I
    G --> I
    G --> J
    F --> K
    G --> K
    H --> K

    classDef stage fill:#f0a341,stroke:#8a5a1a,color:#1a1200,font-weight:bold;
    classDef fallback fill:#f0a341,stroke:#8a5a1a,color:#1a1200,font-weight:bold,stroke-dasharray: 5 5;
    class A,B,C,D,E,F,G,I,J,K stage
    class H fallback
```

This is the real job graph of `ci_dev_workflow.yml` — every node is an actual GitHub Actions job, every arrow an actual `needs:` dependency, including ones that look transitively redundant (e.g. the attack-test jobs each depend on both "Prepare, Validate, Convert" *and* "Deploy to Splunk" even though the latter already depends on the former) — that's how GitHub's own UI draws it, so this does too. "Persist Verification Results (fallback)" has a dashed border because it's conditional: it only does anything if verification ran but the dashboard update didn't succeed, so on a normal green run it executes zero steps. A push to the repo runs this whole graph without a human clicking through any of it.

One caveat about that green checkmark: the lab it deploys to isn't always online. A repository variable, `LAB_ONLINE`, gates the entire lab-dependent half of the pipeline — deploy to Splunk, the attack tests, verification. When it's set to `false`, a push still validates, converts and commits its SPL, and the run still goes green, but the deploy/attack/verify stages skip themselves and nothing is re-measured. That's exactly why the "Last live verification" line in the stats block and the coverage badge exist: a green run on its own doesn't tell you anything was tested — the date and the coverage percentage do.

That whole loop first runs in a low-stakes proving-ground environment. Only once a batch of rules has actually survived it does the repo open a pull request offering to promote them to the environment that matters — a human still has to look at that PR and merge it; nothing ships to production purely because a script said so.

```mermaid
flowchart LR
    dev(("proving ground<br/>branch")) -- "verified by the pipeline" --> pr{{"promotion PR"}}
    pr -- "human review & merge" --> main(("production<br/>branch"))

    classDef auto fill:#f0a341,stroke:#8a5a1a,color:#1a1200,font-weight:bold;
    classDef human fill:#7a4a12,stroke:#4d2e0a,color:#ffffff,font-weight:bold;
    class dev,main auto
    class pr human
```

## See it live

| | |
|---|---|
| 🔍 **[Rule Browser](https://martonbence.github.io/Detection-Engineering/)** | Every rule in the repo, searchable and filterable, with its ATT&CK mapping and its current pass/fail verdict — generated straight from the pipeline's own output, published on GitHub Pages. |
| 🛡️ **[MITRE ATT&CK Navigator](https://martonbence.github.io/Detection-Engineering/#tab=navigator)** | The same coverage plotted against the full ATT&CK matrix, exportable as a Navigator layer for use in the official MITRE tool. |

*The badges near the top of this page are a live, regenerated snapshot, not something typed by hand — treat them, not any number written into the prose on this page, as current.*

## What "pass" actually means here

A checkmark in this repo is not a claim the rule's author made about their own work. It's the output of a pipeline that deployed the rule for real, ran a real attack technique, and queried the SIEM for a real hit. And a verdict doesn't stay valid forever by default: edit the rule and the old result stops applying to it; let too much time pass without re-testing and the result ages out on its own. A rule only counts as "proven" while there's still a recent measurement that actually matches the logic currently sitting in the file. The exact mechanics of how that's computed — and there's a fair amount of nuance to it — live in [`docs/architecture/`](docs/architecture/) rather than here.

## Building a new detection, in broad strokes

1. **Write** the detection as a single Sigma-format rule file — logic, severity, MITRE mapping, and test plan all live together in that one file. If the underlying idea genuinely can't be expressed in Sigma's own syntax, the same file can carry the raw SIEM query directly instead; either way there is one authoring format and one pipeline, not two.
2. **Open a pull request.** The pipeline validates and compiles the rule before anything else happens, and shows you the result before it's merged.
3. **Merge, and the pipeline takes over**: it deploys the rule, runs the attack technique it's meant to catch, and checks whether it actually fired.
4. **Watch it show up** in the [rule browser](https://martonbence.github.io/Detection-Engineering/) with a real verdict and its place on the ATT&CK matrix.
5. **Once proven**, the rule becomes eligible to be promoted from the proving-ground branch to production — via a pull request the pipeline opens for a human to review and merge, never automatically.

The full step-by-step version of this — exact filenames, the scaffold command, which checks gate what — is in [`CONTRIBUTING.md`](CONTRIBUTING.md), with the deeper mechanics in [`docs/architecture/`](docs/architecture/).

## Built partly by an AI agent team

One thing worth knowing about how this repo itself gets maintained: a chunk of the day-to-day work on it — pipeline changes, rule authoring, quality review, documentation, security auditing — is carried out by a small team of scoped AI agents working under a human lead, each responsible for one surface of the repo rather than one generalist touching everything. That division of labor, and how work moves between agents, is itself documented in the repo (`CLAUDE.md`, `TEAM.md`) — treated as a real engineering practice worth being transparent about, not a hidden implementation detail.

The team even tracks its own activity: an internal dashboard (`.claude/team-ops.html`, viewable after cloning the repo) shows what each agent has been doing. It's deliberately *not* published alongside the public rule browser — it's an internal working tool, not something meant for outside visitors.

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
