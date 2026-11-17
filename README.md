# Power Platform and Copilot Studio governance review

`Invoke-PPCSReview.ps1` runs read-only checks against a Power Platform tenant and writes a single, self-contained HTML report (plus CSV and JSON exports) that shows the current state of Power Platform and Copilot Studio governance: an executive summary with a maturity band, a "start here" list, a 30/60/90-day roadmap, a scorecard by area, an agent risk register, an environment profile, and every finding with evidence and Microsoft Learn references.

> **Not an official Microsoft product.** This is a personal creation of Russ Rimmerman (Cloud Solution Architect), built to help customers evaluate the current state of their overall Power Platform governance. It is not supported by Microsoft. See the disclaimer at the top of the script.

## Quick start

```powershell
# PowerShell 7 or later is recommended
.\Invoke-PPCSReview.ps1 -OpenReport

# Customer tenant, skip the checks you cannot access
.\Invoke-PPCSReview.ps1 -TenantId contoso.onmicrosoft.com -CustomerName "Contoso" -SkipDataverse -SkipEntra

# Compare with a previous run
.\Invoke-PPCSReview.ps1 -BaselinePath .\PPCS-Review-20261101-090000
```

Run `Get-Help .\Invoke-PPCSReview.ps1 -Full` for every parameter.

## Access required

The script only reads. It runs as a signed-in user (service principals are not supported by the inventory API).

| Area | Required |
|---|---|
| Power Platform API, tenant settings, data policies | Power Platform Administrator (or Global Administrator) |
| Entra checks (admin roles, PIM, Conditional Access, owners) | Global Reader, with delegated Graph `Directory.Read.All`, `RoleManagement.Read.Directory`, `Policy.Read.All` |
| Dataverse checks (auditing, admins, transcripts, topic and flow scans) | System Administrator in each environment scanned. Tenant admins must self-elevate first. |

Anything the signed-in user cannot read is reported as "Not verified" rather than guessed.

## Output

Each run writes a `PPCS-Review-<timestamp>` folder containing `report.html`, `findings.csv/json`, `findings-register.csv`, `agent-risk-register.csv`, `environment-profile.csv`, `run-summary.json`, usage and evidence CSVs, and an API call log. These folders contain tenant data and are excluded by `.gitignore`.

## Files

- `Invoke-PPCSReview.ps1`: the review script.
- `PowerPlatform_CopilotStudio_Security_Review_v2.docx` / `.pptx`: the assessment framework the checks and scoring follow.
- Optional: place `PPCS-Checklist.csv` next to the script so checklist items that are not automated appear as manual checks.
