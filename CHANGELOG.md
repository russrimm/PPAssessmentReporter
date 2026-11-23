# Changelog

All notable changes to `Invoke-PPCSReview.ps1`. Dates are release dates.

## Unreleased

### Added

- **Accepted risks (`-ExceptionsPath`).** Pass a CSV or JSON file of exceptions (`Id`, optional `Title`, `Reason`, `Owner`, `ApprovedBy`, `Approved`, `Reviewed`, `Expires`) and a matching Fail or Warning becomes **Accepted**: it leaves the score, Fix these first and the roadmap, and stays listed in a new **Accepted risks** report section, in `accepted-risks.csv`, in `findings.csv` and `findings.json` (`AcceptedFrom`, `AcceptedReason`, `AcceptedOwner`, `AcceptedApprovedBy`, `AcceptedExpires`) and in `run-summary.json`. Expired and invalid rows never apply, and a finding whose acceptance lapses is open again. The summary always states how many accepted risks are Critical or High. `-BaselinePath` lists newly accepted gaps as "Risks accepted" (not as resolved) and shows a lapsed acceptance as "got worse". See "Accepting a risk" in the README and `docs/exceptions-template.csv`.
- **Finding 1.5, Exception register (accepted risks).** With `-ExceptionsPath`, checklist item 1.5 is no longer manual: it is a Warning when an active exception has no owner or expiry date, is expired or invalid, or was last approved or reviewed more than 90 days ago.
- A **Accepted risks** governance KPI and an **Accepted risk** status chip, filter, legend entry and scorecard count.
- **`PPCS-Checklist.csv` is now in the repository, and the script carries its own copy.** The script reads the checklist for its manual-checks list, coverage and default severities, but the file was never committed, so a fresh clone ran without it and silently lost them. It now ships with the script (167 items in the framework's 18 areas), and a compressed copy is built into `Invoke-PPCSReview.ps1` so a script copied on its own still has it. A CSV next to the script (or `-ChecklistPath`) overrides the built-in copy. The appendix and `run-summary.json` record which source was used.
- `tools/Export-Checklist.ps1` rebuilds the CSV and the built-in copy from the framework document (ASCII and US English, identical output on PowerShell 7 and Windows PowerShell 5.1) and cross-checks item counts against the document's own summary table.
- `tools/Test-Checklist.ps1` fails when the CSV is missing, differs from the framework document, differs from the built-in copy, or lacks a check ID that the script reports.
- `.github/workflows/validate.yml` runs the parse (both PowerShell editions), lint, README coverage and checklist checks on every push and pull request.
- If neither checklist copy can be read, the run warns and records it in the report's limitations instead of only a console line.
- **Related tools links** to the independent [Agent Governance Navigator](https://akadrno.github.io/agent-governance-navigator-site/) by akadrno, in the report's About dialog and footer, the roadmap, the agent risk register and the appendix, plus a Related tools section in the README. Link only: the repository has no published license, so nothing is copied, and the report never contacts the site.

### Changed

- Roadmap status pills are now aligned in a fixed-width column on the right of each item, so they line up in every column of the 30/60/90-day roadmap.
- **Optional features stay optional.** Finding 3.1 no longer fails an unmanaged default environment: it is Info with a "Recommended" action, and a Warning only when the default environment holds more assets than `-DefaultEnvironmentAssetWarnThreshold`. Environment routing (3.6) and the weekly admin digest (14.3) are Info when off, because both need Managed Environments.
- Finding 3.8 no longer counts developer environments, which Microsoft's security group guidance does not cover.
- The framework document rated checklist item 18.8 (Power Pages sites without traffic) Medium in its item table but counted it High in its own summary table. It is now High in both, matching the Microsoft Advisor recommendation's own High severity and the High rating of its agent counterpart (18.7). The 18.8 finding takes High severity.
- The README now says that if no checklist copy can be read, findings that set no severity of their own default to Medium.

### Fixed

- `-BaselinePath` comparison now works on Windows PowerShell 5.1. That edition returns a JSON array as one object, so every finding was read as a single row and the "Since the last run" lists were wrong.
- Findings 4.6 and 4.7 now treat a connector that is not listed in a policy as Blocked when the policy's default group is Blocked, instead of reporting it as not blocked.
- Finding 4.6 no longer treats custom connector URL patterns as HTTP endpoint filtering. It reads HTTP endpoint filtering rules when the policy data includes them and reports Warning, not Fail, when it cannot see any.
- Finding 8.2 (HTTP request triggers) now counts flows set to Anyone, flows with no recognized setting, and restricted flows separately, shows whether each flow is On, Off or Suspended, and is Pass when every HTTP-triggered flow is restricted. A missing setting is listed to verify, never assumed safe or open.
- Finding 6.1 no longer says the admin center recommendation fires above 10 System Administrators (Microsoft Learn: more than 20, managed environments, preview), and is Not verified when the role members cannot be read instead of a Pass with a count of 0.
- Finding 2.4 now says that an admin who is only PIM-eligible and has not activated the role is listed as a non-admin creator.
- The open channel patterns no longer match channel names that only contain the letters "line".
- `tools/Test-ReadmeCoverage.ps1` reads the bullet layout the README now uses (it found no IDs before) and runs on Windows PowerShell 5.1 (`$PSScriptRoot` is empty in parameter defaults there).
- Two Microsoft Learn link titles now match the page titles.

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
