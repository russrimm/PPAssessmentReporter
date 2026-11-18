# Changelog

All notable changes to `Invoke-PPCSReview.ps1`. Dates are release dates.

## 2.1.0 - 2026-11-17

### Added

- **Dataverse environment security checks** (finding 6.6): IP firewall, IP address-based cookie binding, content security policy and session and inactivity timeouts. All are informational and recommended when not configured. Guest access to Dataverse (5.7) is a Warning on production and default environments.
- **Copilot Studio agent access checks** (9.1): agents usable from other Microsoft Entra tenants (multitenant access policy) and agents that do not ask for sign-in up front. The second is a Warning only when the agent also uses maker credentials or SharePoint knowledge.
- **Bot Transcript Viewer role holders** (6.5), including holders through group teams.
- **Managed Environment settings** read from the BAP `governanceConfiguration`: sharing limits on the default environment for canvas apps (7.1) and agents (9.4), solution checker enforcement (7.6), and maker welcome content (1.3, only when the API returns it).
- New risk signals in the agent risk register (multitenant access, sign-in only when a topic asks) and the environment profile (guest access to Dataverse).
- **Why line** under each recommended action, in "Fix these first" and in each finding card, plus the `Why` column in `findings.csv` and `findings.json`.
- **Microsoft Learn links** on every finding and in the exports.
- About dialog and disclaimers in the report and the script header.
- README rewritten with parameters, access requirements, scoring, a full reference of every check with its recommendation, why and Microsoft Learn links, known gaps and troubleshooting. `.PARAMETER` help for every parameter.
- `CONTRIBUTING.md` and `tools/Test-ReadmeCoverage.ps1`.

### Changed

- **Managed Environments coverage (3.4) is informational and recommended**, not a Fail or Critical finding. Rolling it out is each customer's decision.
- Optional features chosen per customer (IP firewall, cookie binding, content security policy, session timeouts, sharing limits, solution checker enforcement) are reported as Pass or Info, never as gaps.
- Report restyled in a Microsoft blue theme; status colors were adjusted so they stay readable.
- `Add-Unavailable` accepts `-Severity` and `-AlsoCovers`.

## 2.0.0

Initial release: the read-only review script and its HTML, CSV and JSON outputs, with the maturity band, "Fix these first", Start here, roadmap, scorecard, usage lens, agent risk register, environment profile, findings with evidence, manual checks, data collection health and baseline comparison.
