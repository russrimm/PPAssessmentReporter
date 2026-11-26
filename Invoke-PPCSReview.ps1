# ------------------------------------------------------------------------------------------------
# NOT AN OFFICIAL MICROSOFT PRODUCT. This script is a personal creation of Russ Rimmerman, Cloud
# Solution Architect, to help customers evaluate the current state of their overall Power Platform
# governance. It is not supported by Microsoft.
#
# DISCLAIMER
# This Sample Code is provided for the purpose of illustration only and is not intended to be used
# in a production environment. THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS"
# WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. We grant You a
# nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and
# distribute the object code form of the Sample Code, provided that You agree: (i) to not use Our
# name, logo, or trademarks to market Your software product in which the Sample Code is embedded;
# (ii) to include a valid copyright notice on Your software product in which the Sample Code is
# embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against
# any claims or lawsuits, including attorneys' fees, that arise or result from the use or
# distribution of the Sample Code.
# ------------------------------------------------------------------------------------------------

<#
.SYNOPSIS
    Automated Power Platform and Copilot Studio security / best-practice review.

.DESCRIPTION
    Runs read-only checks against a tenant and writes an HTML, CSV and JSON report with
    Pass / Fail / Warning / Info results mapped to the review checklist (PPCS-Checklist.csv).
    Checks that cannot be automated are listed as "Manual" so nothing is silently skipped.

    Includes a usage lens: highest-used and not-used apps, flows, agents and sites, using Advisor usage
    recommendations, Copilot credit consumption (entitlement insight), flow runs and app sharing counts.

    The HTML report follows the assessment framework: executive summary with maturity band, the "start here"
    checks, a 30/60/90-day roadmap, a scorecard by area, the usage lens, an agent risk register, an
    environment profile, every finding with evidence, the checklist items that still need a manual review and
    a data-quality appendix that explains what could not be read and why. Use -BaselinePath to add a
    "since the last run" comparison.

    Primary data source : Power Platform API (https://api.powerplatform.com)
        - Inventory (Resource Query)            apps, flows, agents, sites, environments, connectors
        - Environment Management                environments, settings, environment groups, backups
        - Governance                            rule-based policies, rule sets, cross-tenant connection reports
        - Analytics / Advisor recommendations   security recommendations (actions page)
        - Licensing                             tenant capacity, storage warnings, billing policies
    Fallback sources (only where no api.powerplatform.com endpoint exists)
        - api.bap.microsoft.com                 tenant settings, data policies (DLP), tenant isolation,
                                                  Managed Environment settings (sharing limits, solution checker)
        - Microsoft Graph                       admin roles, PIM, Conditional Access, owner lookup
        - Dataverse Web API (per environment)   System Administrator count, auditing, transcripts, solutions,
                                                  environment security settings (IP firewall, cookie binding, guest
                                                  access, content security policy, session timeouts),
                                                  agent access control and sign-in settings, agent topic/knowledge/
                                                  trigger scan, flow definition scan, production roles, guests,
                                                  application users and Bot Transcript Viewer role holders

    The script never changes anything in the tenant.

.PARAMETER AuthMethod
    DeviceCode (default, no modules needed), Az (uses Az.Accounts), or Token (supply -AccessToken for the
    Power Platform API only; Graph/BAP/Dataverse checks are then skipped).
    The inventory API supports delegated user sign-in only (service principals get 403).

.PARAMETER AccessToken
    Bearer token for https://api.powerplatform.com (AuthMethod Token). If omitted, the PPCS_ACCESS_TOKEN
    environment variable is used, which keeps the token out of the command line and shell history.

.PARAMETER BaselinePath
    A previous run folder (or its findings.json). Adds a "Since the last run" section that lists new,
    resolved, improved and regressed findings and the change in the governance KPIs.

.PARAMETER ExceptionsPath
    A CSV or JSON file of accepted risks (framework item 1.5). Columns: Id (required, the check ID such as 9.1), Title
    (optional, the finding title; blank matches every finding with that Id, * and ? are wildcards), Reason (required),
    Owner, ApprovedBy, Approved, Reviewed, Expires (dates as yyyy-MM-dd). A finding that is a Fail or Warning and matches
    an unexpired row becomes Accepted: it is left out of the score, Fix these first and the roadmap, and stays visible in
    the Accepted risks section and in accepted-risks.csv. An expired row no longer applies, so its finding is open again.
    A row with no owner, no expiry date or no review for more than 90 days makes finding 1.5 a Warning. See
    docs\exceptions-template.csv.

.PARAMETER CustomerName
    Shown on the report cover and written to run-summary.json.

.PARAMETER PreparedBy
    Shown on the report cover. Defaults to the signed-in user.

.PARAMETER Redact
    Share-safe mode. Replaces names, accounts, GUIDs and URLs from the tenant with consistent pseudonyms (Environment 001,
    Agent 001, App 001, Flow 001, Site 001, Policy 001, User 001, user001@redacted.example and similar) in every file the run
    writes: report.html, all CSV, findings.json, run-summary.json, api-log.csv, usage-*.csv and evidence\*.csv. The same real
    value always gets the same pseudonym, and counts, scores, rankings and charts do not change, because the checks run on the
    real values and only the output is redacted. After writing, the script scans the output folder for any value it registered
    and warns (and records a limitation) if one survived. Names that are common words (for example Production or Test) are not
    replaced. Redaction is best effort: review the files before you share them. Do not use a redacted run as the -BaselinePath
    for an unredacted run (finding titles are matched by ID and title). A redacted run can use an unredacted baseline.

.PARAMETER RedactionMapPath
    With -Redact, writes a CSV (Pseudonym, Original, Kind) that maps each pseudonym back to the real value so you can
    un-redact later. The file contains the real names: keep it private. The script refuses a path inside the output folder,
    which is meant to be shared. No map is written unless you supply this parameter.

.PARAMETER StaleDays
    Age in days after which an app, flow, published agent or widely shared app counts as dormant when it has
    not been modified. Default 365.

.PARAMETER DeveloperEnvironmentDeadline
    Date by which unmanaged developer environments must be managed or removed. Default 15 Dec 2026 (confirm the
    current date on Microsoft Learn, Managed environments overview).

.PARAMETER TenantId
    Tenant domain or ID to sign in to. Defaults to the home tenant of the signed-in user.

.PARAMETER ClientId
    Public client used for device code sign-in. Default is the Microsoft Azure PowerShell client. If the Graph
    checks return 403, supply your own public-client app registration or use -AuthMethod Az.

.PARAMETER OutputPath
    Folder for the report and exports. Default .\PPCS-Review-<timestamp>.

.PARAMETER ChecklistPath
    The framework checklist CSV (Id, Topic, Feature, Check, Verify, Target, Priority). Default PPCS-Checklist.csv
    next to the script. When present, items that are not automated are listed as Manual and coverage is calculated.
    If the file is not found, the copy built into the script is used (it is generated from the framework document by
    tools\Export-Checklist.ps1). A CSV next to the script wins, so it can be customized.
    Findings that do not set their own severity take the checklist priority.

.PARAMETER PowerPlatformApiHost
    Power Platform API host. Default api.powerplatform.com.

.PARAMETER BapApiHost
    Business Application Platform API host. Default api.bap.microsoft.com.

.PARAMETER GraphHost
    Microsoft Graph host. Default graph.microsoft.com.

.PARAMETER BapResource
    Token audience for the BAP API. Default https://service.powerapps.com.

.PARAMETER SkipLegacyApis
    Skip everything read from api.bap.microsoft.com: tenant settings, tenant isolation, data policies and
    Managed Environment settings.

.PARAMETER SkipEntra
    Skip the Microsoft Graph checks: admin roles, PIM, Conditional Access and owner lookup.

.PARAMETER SkipDataverse
    Skip every per-environment Dataverse check.

.PARAMETER SkipDeepScan
    Skip the agent topic, knowledge and trigger scan and the flow definition scan. The agent access settings
    check still runs.

.PARAMETER SkipHandoff
    Skip the hand-off files: owner-outreach.csv, workitems-azure-devops.csv and workitems-jira.csv. The suggested owner and
    effort columns in findings.csv, findings.json and findings-register.csv, and in the report, are still written.

.PARAMETER SkipUsage
    Skip the usage and adoption analysis.

.PARAMETER MaxAgentComponentsPerEnvironment
    Agent components (topics, knowledge, triggers) read per environment. Default 2000.

.PARAMETER MaxFlowDefinitionsPerEnvironment
    Cloud flow definitions read per environment. Default 300.

.PARAMETER MaxEntitlementEnvironments
    Environments whose Copilot credit entitlements are read. Default 100.

.PARAMETER UsageLookbackDays
    Look-back in days for credit consumption and flow runs. Default 30.

.PARAMETER FlowRunSampleLimit
    Cloud flows sampled for run history. Default 100. Use 0 to skip run history.

.PARAMETER MaxAppSharingEnvironments
    Environments (those with the most apps) whose app sharing counts are read. Default 25.

.PARAMETER TopN
    Rows in each top-N list. Default 15.

.PARAMETER MaxDataverseEnvironments
    Environments scanned in Dataverse, default then production then sandbox first. Default 10. A capped scan is
    labeled Sample.

.PARAMETER MaxEnvironmentSettingsCalls
    Environments whose management settings and Managed Environment settings are read. Default 200.

.PARAMETER DefaultEnvironmentAssetWarnThreshold
    Number of apps, flows, agents and sites in the default environment above which it is flagged. Default 25.

.PARAMETER EvidenceRowLimit
    Evidence rows written per finding CSV. Default 500. The report shows the first 50.

.PARAMETER OpenReport
    Open the report when the run finishes.

.EXAMPLE
    .\Invoke-PPCSReview.ps1 -OpenReport

.EXAMPLE
    .\Invoke-PPCSReview.ps1 -TenantId contoso.onmicrosoft.com -SkipDataverse -SkipEntra

.EXAMPLE
    .\Invoke-PPCSReview.ps1 -Redact -RedactionMapPath D:\private\contoso-redaction-map.csv

.NOTES
    Output (in -OutputPath, default .\PPCS-Review-<timestamp>):
        report.html, findings.csv, findings.json, findings-register.csv (framework template, owner/date blank),
        agent-risk-register.csv, environment-profile.csv, run-summary.json, checklist-coverage.csv, api-log.csv,
        usage-*.csv, evidence\*.csv, accepted-risks.csv (only with -ExceptionsPath)
        Hand-off (off with -SkipHandoff): owner-outreach.csv (one row per asset owner with the assets to fix and the recommended
        action), workitems-azure-devops.csv and workitems-jira.csv (open Fail and Warning findings for CSV import into a tracker)

    The output folder contains tenant data (users, environments, agent names). Store and share it accordingly.
    Use -Redact to produce a copy that is safer to share (see -Redact for what is replaced and what is not).
    CSV cells that start with = + - @ are prefixed with an apostrophe so a maker-chosen name cannot run as a
    spreadsheet formula.

    Run it with PowerShell 7 or later (Windows PowerShell 5.1 can fail on large inventory responses).

    Access needed (read only): a user who can see the tenant in the Power Platform admin center
    (Power Platform Administrator or equivalent). Graph checks need directory read rights
    (role assignments, Conditional Access); Dataverse checks need a role in each target environment.
    Anything the signed-in user cannot read is reported as "Not verified" (status Unavailable in the CSV and JSON files) rather than guessed.

    Endpoint maturity: several api.powerplatform.com operations used here are preview
    (inventory, governance rule sets, advisor recommendations). The BAP tenant-settings, data-policy and
    tenant-isolation calls are best-effort fallbacks because api.powerplatform.com has no equivalent yet.
    Review api-log.csv after the first run to see which calls worked in your tenant.

    Place PPCS-Checklist.csv next to this script to customize the checklist. Without it the script uses a built-in copy
    (generated from the framework document by tools\Export-Checklist.ps1), so a script copied on its own still lists
    the framework items that automation cannot cover.
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [ValidateSet('DeviceCode', 'Az', 'Token')][string]$AuthMethod = 'DeviceCode',
    [string]$ClientId = '1950a258-227b-4e31-a9cf-717495945fc2',
    [string]$AccessToken,
    [string]$OutputPath,
    [string]$ChecklistPath,
    [string]$PowerPlatformApiHost = 'api.powerplatform.com',
    [string]$BapApiHost = 'api.bap.microsoft.com',
    [string]$GraphHost = 'graph.microsoft.com',
    [string]$BapResource = 'https://service.powerapps.com',
    [switch]$SkipLegacyApis,
    [switch]$SkipEntra,
    [switch]$SkipDataverse,
    [switch]$SkipUsage,
    [switch]$SkipDeepScan,
    [switch]$SkipHandoff,
    [int]$MaxAgentComponentsPerEnvironment = 2000,
    [int]$MaxFlowDefinitionsPerEnvironment = 300,
    [int]$MaxEntitlementEnvironments = 100,
    [int]$UsageLookbackDays = 30,
    [int]$FlowRunSampleLimit = 100,
    [int]$MaxAppSharingEnvironments = 25,
    [int]$TopN = 15,
    [int]$MaxDataverseEnvironments = 10,
    [int]$MaxEnvironmentSettingsCalls = 200,
    [int]$StaleDays = 365,
    [int]$DefaultEnvironmentAssetWarnThreshold = 25,
    [int]$EvidenceRowLimit = 500,
    [datetime]$DeveloperEnvironmentDeadline = [datetime]'2026-12-15',
    [string]$BaselinePath,
    [string]$ExceptionsPath,
    [string]$CustomerName,
    [string]$PreparedBy,
    [switch]$Redact,
    [string]$RedactionMapPath,
    [switch]$OpenReport
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ScriptVersion = '2.2.0'
if ($PSVersionTable.PSVersion.Major -lt 7) { Write-Warning 'PowerShell 7 or later is recommended. Windows PowerShell 5.1 can fail on large inventory responses.' }
if (-not $AccessToken -and $env:PPCS_ACCESS_TOKEN) { $AccessToken = $env:PPCS_ACCESS_TOKEN }
if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location).Path ('PPCS-Review-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if (-not $ChecklistPath) { $ChecklistPath = Join-Path $scriptDir 'PPCS-Checklist.csv' }
$ApiVersion = '2024-10-01'
$HtmlEvidenceRows = 50
$MinScoredChecks = 10
$ExceptionReviewDays = 90
$ExceptionExpiringDays = 30

$script:Findings = New-Object System.Collections.ArrayList
$script:ApiLog = New-Object System.Collections.ArrayList
$script:Checklist = @{}
$script:ChecklistSource = 'Not available'
$script:Kpi = [ordered]@{}
$script:Limitations = New-Object System.Collections.ArrayList
$script:StepConfidence = 'Configuration'
$script:DvLimitNoted = $false
$script:EnvFacts = @{}
$script:EnvMap = @{}
$script:AgentView = @()
$script:DeepAgentRows = @()
$script:AgentAccess = @{}
$script:OrphanedAssets = @()
$script:AgentCredits = @{}
$script:OwnerNames = @{}
$script:ExceptionRows = @()
$script:ExceptionsLoaded = $false
$script:Inventory = $null
$script:Redaction = @{ Active = [bool]$Redact; MapPath = [string]$RedactionMapPath; Ready = $false }
$script:Auth = @{ Method = $AuthMethod; Tenant = $TenantId; Refresh = $null; Tokens = @{}; StaticToken = $AccessToken; TenantGuid = $null; User = $null }

$TopicNames = @{
    1 = 'Governance and ownership'; 2 = 'Tenant settings and admin access'; 3 = 'Environments and Managed Environments'
    4 = 'Data policies and connectors'; 5 = 'Identity and authentication'; 6 = 'Dataverse and data protection'
    7 = 'Power Apps and Power Pages'; 8 = 'Power Automate'; 9 = 'Copilot Studio: configuration and publishing'
    10 = 'Copilot Studio: knowledge'; 11 = 'Copilot Studio: tools, MCP and autonomy'; 12 = 'Responsible AI and quality'
    13 = 'ALM and DevOps'; 14 = 'Monitoring and response'; 15 = 'Capacity and cost'; 16 = 'Compliance and privacy'
    17 = 'Resilience and lifecycle'; 18 = 'Usage and adoption (highest used, not used)'
}

# Framework reference data (from the assessment framework document) used by the report.
$TopicSection = @{
    1 = 'Foundation'; 2 = 'Foundation'; 3 = 'Foundation'; 4 = 'Data and identity'; 5 = 'Data and identity'; 6 = 'Data and identity'
    7 = 'Build platforms'; 8 = 'Build platforms'; 9 = 'Copilot Studio'; 10 = 'Copilot Studio'; 11 = 'Copilot Studio'; 12 = 'Copilot Studio'
    13 = 'Operate'; 14 = 'Operate'; 15 = 'Operate'; 16 = 'Operate'; 17 = 'Operate'; 18 = 'Usage'
}
$SectionOrder = @('Foundation', 'Data and identity', 'Build platforms', 'Copilot Studio', 'Operate', 'Usage')
$TopicWhy = @{
    1 = 'Technology controls fail without clear ownership. A defined operating model decides who can build what, where, with which data, and who answers when something goes wrong.'
    2 = 'Tenant-level switches and admin roles set the ceiling for everything below them. A few over-privileged or standing admin accounts can undo every other control.'
    3 = 'Environments are the security, data and lifecycle boundary for Power Platform and Copilot Studio. Weak separation means weak controls everywhere else.'
    4 = 'Data policies are the main preventive control against data exfiltration through connectors, HTTP calls, channels and knowledge sources.'
    5 = 'Most incidents trace back to who an asset runs as and who can reach it: shared connections, maker credentials, anonymous access and orphaned owners.'
    6 = 'Dataverse holds business data and, for Copilot Studio, agent definitions and conversation transcripts. Its security roles and environment controls decide who can read or change them.'
    7 = 'Apps are easy to build and easy to overshare. Risk concentrates in sharing scope, borrowed connections, personal ownership and exposed external sites.'
    8 = 'Flows move data between systems with the identity that created the connection. Poorly scoped triggers, secrets in actions and orphaned owners create silent, high-impact risk.'
    9 = 'An agent is an externally reachable application. How it authenticates users, where it is published and who can edit it determines its exposure.'
    10 = 'Agents surface whatever their knowledge sources let them reach. Oversharing in SharePoint and other sources becomes immediately discoverable once an agent can search it.'
    11 = 'Tools let an agent take actions. Combined with autonomy and untrusted input, they turn a chat risk into an action risk, so credential mode, scope and approval matter most.'
    12 = 'Security controls prevent unauthorized access; responsible-AI controls prevent harmful, wrong or manipulated answers. Both are needed before agents influence decisions.'
    13 = 'Repeatable, reviewed deployment is both a quality and a security control. Manual production changes bypass review, break traceability and cause drift.'
    14 = 'You can only defend what you can see. Audit trails, alerting and rehearsed response shorten detection and containment time for misuse or compromise.'
    15 = 'Unmetered consumption becomes a security and operational risk: autonomous agents can exhaust credits, and license gaps push work into shadow tenants.'
    16 = 'Regulators and customers ask where data lives, how long it stays, who processes it and how a person''s data is found or deleted. Agents add new places where personal data can accumulate.'
    17 = 'Business processes depend on apps, flows and agents long after their makers move on. Ownership, support and retirement planning prevent outages and abandoned risk.'
    18 = 'Usage shows where risk is concentrated and where it is wasted. The assets used most deserve the strongest controls; assets nobody uses add exposure and cost with no benefit.'
}
$StartHere = @(
    @{ N = 1; Check = 'Admin roles and PIM'; Area = 2; Ids = @('2.1', '2.2'); Question = 'How many standing Global, Power Platform and Dynamics 365 admins exist? Any shared admin accounts?' }
    @{ N = 2; Check = 'Tenant data policy'; Area = 4; Ids = @('4.1', '4.3', '4.6', '4.7'); Question = 'Is there a tenant-wide data policy with the default group blocked or deliberate? Are HTTP, custom connectors and unauthenticated chat controlled?' }
    @{ N = 3; Check = 'Default environment'; Area = 3; Ids = @('3.1', '3.6'); Question = 'Is the default environment hardened, managed, routed and free of production workloads?' }
    @{ N = 4; Check = 'Managed Environments and developer environments'; Area = 3; Ids = @('3.4', '3.5'); Question = 'What percent of environments are managed? Which unmanaged developer environments need action before the deadline?' }
    @{ N = 5; Check = 'Unauthenticated agents'; Area = 9; Ids = @('9.1', '9.2', '9.3'); Question = 'Are any agents set to No authentication or published to open web channels?' }
    @{ N = 6; Check = 'Maker-provided credentials'; Area = 5; Ids = @('5.3', '11.2'); Question = 'Which agents and flows run as their maker? Is Control maker credential options configured?' }
    @{ N = 7; Check = 'Sharing with Everyone'; Area = 7; Ids = @('7.1', '9.4'); Question = 'Are apps, flows or agents shared tenant-wide (which includes guests)?' }
    @{ N = 8; Check = 'HTTP triggers and secrets'; Area = 8; Ids = @('8.2', '8.3', '9.7'); Question = 'Which flows can be called anonymously? Are there secrets in flow definitions, topics or variables?' }
    @{ N = 9; Check = 'Knowledge oversharing'; Area = 10; Ids = @('10.2', '10.4', '10.5'); Question = 'Are agents grounded on SharePoint sites with broad permissions or unlabeled sensitive content?' }
    @{ N = 10; Check = 'Write tools and autonomy'; Area = 11; Ids = @('11.3', '11.4'); Question = 'Which agents can send, update or delete, or run on triggers, and under what identity?' }
    @{ N = 11; Check = 'Audit and detection'; Area = 14; Ids = @('14.1', '6.4', '14.2'); Question = 'Is Purview and Dataverse auditing on? Are there detections for risky agent and policy changes?' }
    @{ N = 12; Check = 'Ownership and orphaned assets'; Area = 5; Ids = @('5.8', '17.1'); Question = 'Who owns the production assets? How many depend on departed users or personal connections?' }
    @{ N = 13; Check = 'Transcripts'; Area = 6; Ids = @('6.5'); Question = 'Who can read conversation transcripts and how long are they kept?' }
    @{ N = 14; Check = 'Spend controls'; Area = 15; Ids = @('15.2'); Question = 'Are pay-as-you-go caps, budgets and alerts in place for Copilot Studio?' }
    @{ N = 15; Check = 'Most-used assets'; Area = 18; Ids = @('18.2', '18.4', '18.6'); Question = 'Which apps, flows and agents are used most, and do they have owners, managed environments, authentication and ALM?' }
    @{ N = 16; Check = 'Unused assets'; Area = 18; Ids = @('18.3', '18.5', '18.7', '18.8'); Question = 'Which apps, flows, agents and sites have had no recent use and can be quarantined and retired?' }
)
$SeverityOrder = @('Critical', 'High', 'Medium', 'Low')

# ------------------------------------------------------------------ helpers
function Get-Prop {
    param($Obj, [string]$Path, $Default = $null)
    $cur = $Obj
    $Path = $Path.Replace('@odata.', '@odata~')
    foreach ($seg0 in $Path.Split('.')) {
        $seg = $seg0.Replace('@odata~', '@odata.')
        if ($null -eq $cur) { return $Default }
        if ($cur -is [System.Collections.IDictionary]) {
            if ($cur.Contains($seg)) { $cur = $cur[$seg] } else { return $Default }
        }
        else {
            $p = $cur.PSObject.Properties[$seg]
            if ($null -eq $p) { return $Default }
            $cur = $p.Value
        }
    }
    if ($null -eq $cur) { return $Default }
    return $cur
}

function ConvertFrom-Jwt {
    param([string]$Jwt)
    try {
        $p = $Jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
        switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
        return ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json)
    }
    catch { return $null }
}

function Get-HttpStatus {
    param($ErrorRecord)
    try {
        $r = $ErrorRecord.Exception.Response
        if ($r) { return [int]$r.StatusCode }
    }
    catch { Write-Verbose "Could not read the HTTP status: $($_.Exception.Message)" }
    return 0
}

function Get-HttpErrorText {
    param($ErrorRecord)
    $t = $null
    try { $t = $ErrorRecord.ErrorDetails.Message } catch { Write-Verbose "No error details: $($_.Exception.Message)" }
    if (-not $t) { $t = $ErrorRecord.Exception.Message }
    if ($t -and $t.Length -gt 400) { $t = $t.Substring(0, 400) }
    return $t
}

function Get-HeaderValue {
    param($Headers, [string[]]$Names)
    if (-not $Headers) { return '' }
    foreach ($n in $Names) {
        try {
            $v = $null
            if ($Headers -is [System.Net.Http.Headers.HttpHeaders]) { $vals = $null; if ($Headers.TryGetValues($n, [ref]$vals)) { $v = @($vals)[0] } }
            else { $x = $Headers[$n]; if ($x) { $v = @($x)[0] } }
            if ($v) { return [string]$v }
        }
        catch { Write-Verbose "Header '$n' could not be read: $($_.Exception.Message)" }
    }
    return ''
}

function Get-RetryAfterSeconds {
    # Honors Retry-After on PowerShell 7 (HttpResponseHeaders) and Windows PowerShell 5.1 (WebHeaderCollection); capped at 2 minutes.
    param($ErrorRecord, [int]$Default)
    try {
        $h = $ErrorRecord.Exception.Response.Headers
        if ($h) {
            $ra = 0
            if ($h -is [System.Net.Http.Headers.HttpResponseHeaders]) {
                if ($h.RetryAfter -and $h.RetryAfter.Delta) { $ra = [int][Math]::Ceiling($h.RetryAfter.Delta.TotalSeconds) }
                elseif ($h.RetryAfter -and $h.RetryAfter.Date) { $ra = [int][Math]::Ceiling(($h.RetryAfter.Date - [DateTimeOffset]::UtcNow).TotalSeconds) }
            }
            else { $v = Get-HeaderValue $h @('Retry-After'); if ($v) { $ra = [int]$v } }
            if ($ra -gt 0) { return [Math]::Min($ra, 120) }
        }
    }
    catch { Write-Verbose "Retry-After could not be read: $($_.Exception.Message)" }
    return $Default
}

function Add-ApiLog {
    param($Name, $Method, $Uri, $Status, $Ok, $Ms, $Rows, $Err, $RequestId = '')
    $safe = ($Uri -replace '\?.*$', '')
    [void]$script:ApiLog.Add([pscustomobject]@{ Name = $Name; Method = $Method; Endpoint = $safe; Status = $Status; Ok = $Ok; Ms = $Ms; Rows = $Rows; Error = $Err; RequestId = $RequestId })
}

function Add-Limitation {
    param([string]$Area, [string]$Text)
    [void]$script:Limitations.Add([pscustomobject]@{ Area = $Area; Text = $Text })
}

function Add-EnvFact {
    param([string]$EnvId, [string]$Name, $Value)
    $k = ([string]$EnvId).ToLower()
    if (-not $script:EnvFacts.ContainsKey($k)) { $script:EnvFacts[$k] = @{} }
    $script:EnvFacts[$k][$Name] = $Value
}

# CSV cells that start with = + - @ (or a control character) can run as formulas when opened in a spreadsheet.
# Names of apps, flows and agents are chosen by makers, so every exported string cell is neutralized.
function ConvertTo-SafeCsvCell {
    param($Value)
    # DateTime values arrive on PowerShell 7 only; write them as ISO-8601 UTC so the CSV does not depend on the machine's culture.
    if ($Value -is [datetime]) { return $(if ($Value.Kind -eq [DateTimeKind]::Unspecified) { $Value } else { $Value.ToUniversalTime() }).ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [string] -and $Value.Length -gt 0) {
        if ($Value -match '^[=+\-@\t\r]') { return "'" + $Value }
        return (ConvertTo-IsoText $Value)
    }
    return $Value
}

function Export-SafeCsv {
    param($Rows, [string]$Path, [switch]$Raw)
    # -Raw skips redaction; only the redaction map (which holds the real values on purpose) uses it.
    $redact = ($script:Redaction.Active -and -not $Raw)
    $safe = foreach ($r in @($Rows)) {
        $o = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) {
            $cell = $p.Value
            if ($redact -and ($cell -is [string] -or $cell -is [guid] -or $cell -is [uri])) { $cell = Protect-Text ([string]$cell) }
            $o[$p.Name] = ConvertTo-SafeCsvCell $cell
        }
        [pscustomobject]$o
    }
    $lines = @($safe | ConvertTo-Csv -NoTypeInformation)
    [System.IO.File]::WriteAllLines($Path, $lines, (New-Object System.Text.UTF8Encoding($true)))
}

# ------------------------------------------------------------------ authentication
function Get-TokenEndpoint { "https://login.microsoftonline.com/$($script:Auth.Tenant)/oauth2/v2.0" }

function Initialize-Auth {
    if ($script:Auth.Method -eq 'Token') {
        if (-not $script:Auth.StaticToken) { throw 'AuthMethod Token requires -AccessToken (a token for https://api.powerplatform.com).' }
        $claims = ConvertFrom-Jwt $script:Auth.StaticToken
        if ($claims) { $script:Auth.TenantGuid = $claims.tid; $script:Auth.User = $claims.upn }
        return
    }
    if ($script:Auth.Method -eq 'Az') {
        if (-not (Get-Module -ListAvailable Az.Accounts)) { throw 'Az.Accounts module not found. Install-Module Az.Accounts or use -AuthMethod DeviceCode.' }
        Import-Module Az.Accounts -ErrorAction Stop
        if (-not (Get-AzContext)) {
            if ($TenantId) { Connect-AzAccount -Tenant $TenantId | Out-Null } else { Connect-AzAccount | Out-Null }
        }
        $tok = Get-AccessTokenFor "https://$PowerPlatformApiHost"
        $claims = ConvertFrom-Jwt $tok
        if ($claims) { $script:Auth.TenantGuid = $claims.tid; $script:Auth.User = $claims.upn }
        return
    }
    if (-not $script:Auth.Tenant) { $script:Auth.Tenant = 'organizations' }
    $scope = "https://$PowerPlatformApiHost/.default offline_access"
    $dc = Invoke-RestMethod -Method Post -Uri "$(Get-TokenEndpoint)/devicecode" -Body @{ client_id = $ClientId; scope = $scope }
    Write-Host ''
    Write-Host $dc.message -ForegroundColor Yellow
    $interval = [int]$dc.interval
    if ($interval -lt 2) { $interval = 5 }
    $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
    $tok = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            $tok = Invoke-RestMethod -Method Post -Uri "$(Get-TokenEndpoint)/token" -Body @{
                grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; client_id = $ClientId; device_code = $dc.device_code
            }
            break
        }
        catch {
            $b = $null
            try { $b = $_.ErrorDetails.Message | ConvertFrom-Json } catch { Write-Verbose 'Device code response was not JSON.' }
            if ($b -and $b.error -eq 'authorization_pending') { continue }
            if ($b -and $b.error -eq 'slow_down') { $interval += 5; continue }
            throw "Device code sign-in failed: $(Get-HttpErrorText $_)"
        }
    }
    if (-not $tok) { throw 'Device code sign-in timed out.' }
    $script:Auth.Refresh = $tok.refresh_token
    $claims = ConvertFrom-Jwt $tok.access_token
    if ($claims) { $script:Auth.TenantGuid = $claims.tid; $script:Auth.User = $claims.upn; $script:Auth.Tenant = $claims.tid }
    $script:Auth.Tokens[("https://$PowerPlatformApiHost").ToLower()] = @{ Token = $tok.access_token; Expires = (Get-Date).AddSeconds([int]$tok.expires_in) }
}

function Get-AccessTokenFor {
    param([string]$Resource)
    $key = $Resource.TrimEnd('/').ToLower()
    $c = $script:Auth.Tokens[$key]
    if ($c -and $c.Expires -gt (Get-Date).AddMinutes(5)) { return $c.Token }
    $token = $null
    switch ($script:Auth.Method) {
        'Token' {
            if ($key -eq ("https://$PowerPlatformApiHost").ToLower()) { return $script:Auth.StaticToken }
            return $null
        }
        'Az' {
            try {
                $r = Get-AzAccessToken -ResourceUrl $Resource -ErrorAction Stop
                $token = $r.Token
                if ($token -is [securestring]) { $token = [System.Net.NetworkCredential]::new('', $token).Password }
                $script:Auth.Tokens[$key] = @{ Token = $token; Expires = $r.ExpiresOn.LocalDateTime }
            }
            catch { return $null }
        }
        'DeviceCode' {
            if (-not $script:Auth.Refresh) { return $null }
            try {
                $r = Invoke-RestMethod -Method Post -Uri "$(Get-TokenEndpoint)/token" -Body @{
                    grant_type = 'refresh_token'; client_id = $ClientId; refresh_token = $script:Auth.Refresh
                    scope = "$($Resource.TrimEnd('/'))/.default offline_access"
                }
                if ($r.refresh_token) { $script:Auth.Refresh = $r.refresh_token }
                $token = $r.access_token
                $script:Auth.Tokens[$key] = @{ Token = $token; Expires = (Get-Date).AddSeconds([int]$r.expires_in) }
            }
            catch { return $null }
        }
    }
    return $token
}

# ------------------------------------------------------------------ HTTP
function Invoke-Api {
    param(
        [string]$Name, [string]$Uri, [string]$Method = 'GET', $Body = $null,
        [string]$Resource, [switch]$Paged, [int]$MaxPages = 100, [hashtable]$ExtraHeaders, [switch]$UseContinuationToken
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $token = Get-AccessTokenFor $Resource
    if (-not $token) {
        Add-ApiLog $Name $Method $Uri 0 $false 0 0 "No access token for $Resource"
        return [pscustomobject]@{ Ok = $false; Status = 0; Error = "No access token for $Resource"; Data = $null; Truncated = $false }
    }
    $headers = @{ Authorization = "Bearer $token"; Accept = 'application/json' }
    if ($ExtraHeaders) { foreach ($k in $ExtraHeaders.Keys) { $headers[$k] = $ExtraHeaders[$k] } }
    $items = New-Object System.Collections.ArrayList
    $next = $Uri
    $pages = 0
    $single = $null
    do {
        $attempt = 0
        $json = $null
        while ($true) {
            try {
                $req = @{ Uri = $next; Method = $Method; Headers = $headers; UseBasicParsing = $true; ErrorAction = 'Stop' }
                if ($null -ne $Body -and $Method -ne 'GET') { $req.Body = ($Body | ConvertTo-Json -Depth 20 -Compress); $req.ContentType = 'application/json' }
                $resp = Invoke-WebRequest @req
                if ($resp.Content) { $json = $resp.Content | ConvertFrom-Json }
                break
            }
            catch {
                $status = Get-HttpStatus $_
                if (($status -eq 429 -or $status -ge 500) -and $attempt -lt 4) {
                    $attempt++
                    $wait = Get-RetryAfterSeconds $_ ([Math]::Pow(2, $attempt) + 1)
                    Start-Sleep -Seconds $wait
                    continue
                }
                $msg = Get-HttpErrorText $_
                $rid = ''
                try { $rid = Get-HeaderValue $_.Exception.Response.Headers @('x-ms-correlation-request-id', 'request-id', 'x-ms-request-id', 'x-ms-correlation-id') } catch { Write-Verbose "Request id not available: $($_.Exception.Message)" }
                Add-ApiLog $Name $Method $Uri $status $false $sw.ElapsedMilliseconds $items.Count $msg $rid
                return [pscustomobject]@{ Ok = $false; Status = $status; Error = $msg; Data = $null; Truncated = $false }
            }
        }
        $pages++
        if ($Paged) {
            $v = Get-Prop $json 'value'
            if ($null -eq $v) { $v = Get-Prop $json 'objectResult' }
            if ($null -eq $v -and $json -is [System.Array]) { $v = $json }
            if ($null -ne $v) { foreach ($i in @($v)) { [void]$items.Add($i) } }
            $next = Get-Prop $json '@odata.nextLink'
            if (-not $next) { $next = Get-Prop $json 'nextLink' }
            if (-not $next -and $UseContinuationToken) {
                $ct = Get-Prop $json 'continuationtoken'
                if (-not $ct) { $ct = Get-Prop $json 'continuationToken' }
                if ($ct) { $sep = if ($Uri.Contains('?')) { '&' } else { '?' }; $next = $Uri + $sep + 'continuationToken=' + [uri]::EscapeDataString([string]$ct) }
            }
        }
        else { $single = $json; $next = $null }
    } while ($next -and $pages -lt $MaxPages)
    $rows = if ($Paged) { $items.Count } else { 1 }
    Add-ApiLog $Name $Method $Uri 200 $true $sw.ElapsedMilliseconds $rows ''
    $data = if ($Paged) { , $items.ToArray() } else { $single }
    return [pscustomobject]@{ Ok = $true; Status = 200; Error = $null; Data = $data; Truncated = [bool]$next }
}

function Invoke-InventoryQuery {
    param([string]$Name, [object[]]$Clauses, [int]$PageSize = 1000, [int]$MaxRows = 100000)
    $rows = New-Object System.Collections.ArrayList
    $skipToken = $null
    do {
        $opts = @{ Top = $PageSize }
        if ($skipToken) { $opts.SkipToken = $skipToken } else { $opts.Skip = 0 }
        $body = @{ TableName = 'PowerPlatformResources'; Clauses = $Clauses; Options = $opts }
        $r = Invoke-Api -Name $Name -Method POST -Uri "https://$PowerPlatformApiHost/resourcequery/resources/query?api-version=$ApiVersion" -Body $body -Resource "https://$PowerPlatformApiHost"
        if (-not $r.Ok) { return $r }
        foreach ($d in @(Get-Prop $r.Data 'data' @())) { [void]$rows.Add($d) }
        $skipToken = Get-Prop $r.Data 'skipToken'
    } while ($skipToken -and $rows.Count -lt $MaxRows)
    return [pscustomobject]@{ Ok = $true; Status = 200; Error = $null; Data = $rows.ToArray(); Truncated = [bool]$skipToken }
}

function New-TypeClause {
    param([string[]]$Types)
    $vals = @($Types | ForEach-Object { "'$_'" })
    return ,@(@{ '$type' = 'where'; FieldName = 'type'; Operator = 'in~'; Values = $vals })
}

# ------------------------------------------------------------------ findings
function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'Warning', 'Info', 'Unavailable')][string]$Status,
        [string]$Value = '', [string]$Detail = '', [string]$Recommendation = '', [string]$Source = '',
        [string]$Severity, [object[]]$Evidence = @(), [string[]]$AlsoCovers = @(),
        [ValidateSet('', 'Configuration', 'Sample', 'Heuristic')][string]$Confidence = '', [string]$RollupKey = ''
    )
    $topic = 0
    [void][int]::TryParse(($Id.Split('.')[0]), [ref]$topic)
    $sev = $Severity
    if (-not $sev) {
        $cl = $script:Checklist[$Id]
        $sev = if ($cl) { $cl.Priority } else { 'Medium' }
    }
    if ($sev -notin $SeverityOrder) { $sev = 'Medium' }
    # Evidence confidence uses the framework labels: configuration read, sample, heuristic, not verified.
    $conf = $Confidence
    if ($Status -eq 'Unavailable') { $conf = 'NotVerified' }
    elseif (-not $conf) { $conf = if ($script:StepConfidence) { $script:StepConfidence } else { 'Configuration' } }
    $f = [pscustomobject]@{
        Key = ('F{0:D3}' -f ($script:Findings.Count + 1)); Id = $Id; Topic = $topic
        TopicName = $TopicNames[$topic]; Title = $Title; Status = $Status; Severity = $sev
        AlsoCovers = @($AlsoCovers); Value = $Value; Detail = $Detail; Recommendation = $Recommendation; Source = $Source
        EvidenceCount = @($Evidence | Where-Object { $null -ne $_ }).Count; EvidenceFile = ''; Evidence = @($Evidence | Where-Object { $null -ne $_ })
        Confidence = $conf; RollupKey = $RollupKey; AcceptedFrom = ''; Acceptance = $null
    }
    [void]$script:Findings.Add($f)
}

function Add-Unavailable {
    param([string]$Id, [string]$Title, $ApiResult, [string]$Source, [string]$Severity, [string[]]$AlsoCovers = @())
    $why = if ($ApiResult) { "HTTP $($ApiResult.Status): $($ApiResult.Error)" } else { 'Not run' }
    Add-Finding -Id $Id -Title $Title -Status Unavailable -Detail $why -Source $Source -Severity $Severity -AlsoCovers $AlsoCovers `
        -Recommendation 'Check permissions or endpoint availability, then verify this item manually.'
}

function Get-DaysSince {
    param($Date)
    if (-not $Date) { return $null }
    try { return [int]((Get-Date) - [datetime]$Date).TotalDays } catch { return $null }
}

# PowerShell 7 turns ISO timestamps into DateTime; Windows PowerShell 5.1 leaves strings. Show both the same way (UTC).
function Format-IsoDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return '' }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $d = $null
    if ($Value -is [datetime]) { $d = $(if ($Value.Kind -eq [DateTimeKind]::Unspecified) { $Value } else { $Value.ToUniversalTime() }) }
    elseif ($Value -is [datetimeoffset]) { $d = $Value.UtcDateTime }
    else {
        $s = [string]$Value
        $o = [datetimeoffset]::MinValue
        if ($s -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}' -or -not [datetimeoffset]::TryParse($s, $inv, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$o)) { return $s }
        $d = $o.UtcDateTime
    }
    return $d.ToString("yyyy-MM-dd HH:mm 'UTC'", $inv)
}

# On PowerShell 7 a DateTime cast to a string reads MM/dd/yyyy HH:mm:ss, which is ambiguous and sorts badly; rewrite that shape as ISO 8601.
function ConvertTo-IsoText {
    param([string]$Text)
    if ($Text -match '^(\d{2})/(\d{2})/(\d{4}) (\d{2}:\d{2}:\d{2})$') { return "$($Matches[3])-$($Matches[1])-$($Matches[2]) $($Matches[4])" }
    return $Text
}

function ConvertTo-SortableDate {
    param($Value)
    if ($Value) { try { return [datetime]$Value } catch { Write-Verbose "Unrecognized date '$Value'" } }
    return [datetime]::MinValue
}

# ------------------------------------------------------------------ data loading
$ExternalDataConnectors = @{
    shared_smtp = 'SMTP'; shared_sftp = 'SFTP'; shared_sftpwithssh = 'SFTP-SSH'; shared_ftp = 'FTP'; shared_gmail = 'Gmail'
    shared_dropbox = 'Dropbox'; shared_googledrive = 'Google Drive'; shared_box = 'Box'; shared_twitter = 'Twitter/X'
    shared_facebook = 'Facebook'; shared_instagram = 'Instagram'; shared_linkedin = 'LinkedIn'; shared_onedrive = 'OneDrive (consumer)'
    shared_outlook = 'Outlook.com (consumer)'; shared_googlecalendar = 'Google Calendar'; shared_googlecontacts = 'Google Contacts'
    shared_webcontents = 'HTTP with Microsoft Entra ID (preauthorized)'; shared_azureblob = 'Azure Blob Storage'
}
$WriteLikeOperation = '^(Post|Send|Create|Update|Delete|Add|Remove|Patch|Run|Set|Move|Insert|Upsert|Reply|Forward|Share|Copy|Append|Write|Approve|Cancel|Invoke|Execute)'

function Get-Inventory {
    $inv = @{}
    $envClauses = New-TypeClause @('microsoft.powerplatform/environments')
    $inv.Envs = Invoke-InventoryQuery 'Inventory: environments' $envClauses
    $inv.Groups = Invoke-InventoryQuery 'Inventory: environment groups' (New-TypeClause @('microsoft.powerplatform/environmentgroups'))
    $inv.Agents = Invoke-InventoryQuery 'Inventory: Copilot Studio agents' (New-TypeClause @('microsoft.copilotstudio/agents'))
    $inv.Apps = Invoke-InventoryQuery 'Inventory: apps' (New-TypeClause @('microsoft.powerapps/canvasapps', 'microsoft.powerapps/modeldrivenapps', 'microsoft.powerapps/codeapps', 'microsoft.powerapps/apps'))
    $inv.Flows = Invoke-InventoryQuery 'Inventory: flows' (New-TypeClause @('microsoft.powerautomate/cloudflows', 'microsoft.powerautomate/agentflows', 'microsoft.powerautomate/m365agentflows'))
    $inv.Sites = Invoke-InventoryQuery 'Inventory: Power Pages sites' (New-TypeClause @('microsoft.powerpages/sites'))
    $inv.Connectors = Invoke-InventoryQuery 'Inventory: connector catalog' ((New-TypeClause @('microsoft.powerplatformconnector/connectors')) + @(@{ '$type' = 'project'; FieldList = @('name', 'displayName = tostring(properties.displayName)', 'connectorId = tostring(properties.connectorId)', 'publisher = tostring(properties.publisher)', 'tier = tostring(properties.tier)', 'isDeprecated = tobool(properties.isDeprecated)') })) -MaxRows 20000
    $inv.EnvMgmt = Invoke-Api -Name 'EnvironmentManagement: list environments' -Uri "https://$PowerPlatformApiHost/environmentmanagement/environments?api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost" -Paged
    foreach ($k in @('Envs', 'Groups', 'Agents', 'Apps', 'Flows', 'Sites', 'Connectors', 'EnvMgmt')) {
        if ($inv[$k] -and $inv[$k].Ok -and $inv[$k].Truncated) { Add-Limitation 'Inventory' "The $k inventory reached its row or page cap, so counts below may be understated." }
    }
    return $inv
}

function Get-OkRows {
    param($Result)
    if ($Result -and $Result.Ok -and $null -ne $Result.Data) { return @($Result.Data) }
    return @()
}

function Merge-Environments {
    param($Inv)
    $map = @{}
    foreach ($r in (Get-OkRows $Inv.Envs)) {
        $id = ([string]$r.name).ToLower()
        $map[$id] = [pscustomobject]@{
            Id = $id; Name = (Get-Prop $r 'properties.displayName' $id); Type = (Get-Prop $r 'properties.environmentType' '')
            IsManaged = [bool](Get-Prop $r 'properties.isManaged' $false); GroupId = (Get-Prop $r 'properties.environmentGroupId' '')
            Group = (Get-Prop $r 'properties.environmentGroup' ''); Location = $r.location; CreatedAt = (Get-Prop $r 'properties.createdAt' '')
            LastModifiedAt = (Get-Prop $r 'properties.lastModifiedAt' ''); SecurityGroupId = ''; State = ''; Geo = ''; Url = ''
            DataverseId = ''; Retention = ''; Cmk = $false; Vnet = $false; ProtectionLevel = ''; AzureRegion = ''
            CreatedById = ''; CreatedByType = ''; AdminMode = ''; Apps = 0; Flows = 0; Agents = 0; Sites = 0; InMgmtApi = $false
        }
    }
    foreach ($e in (Get-OkRows $Inv.EnvMgmt)) {
        $id = ([string]$e.id).ToLower()
        if (-not $map.ContainsKey($id)) {
            $map[$id] = [pscustomobject]@{
                Id = $id; Name = $e.displayName; Type = $e.type; IsManaged = $false; GroupId = ''; Group = ''; Location = ''; CreatedAt = ''
                LastModifiedAt = ''; SecurityGroupId = ''; State = ''; Geo = ''; Url = ''; DataverseId = ''; Retention = ''; Cmk = $false
                Vnet = $false; ProtectionLevel = ''; AzureRegion = ''; CreatedById = ''; CreatedByType = ''; AdminMode = ''; Apps = 0; Flows = 0; Agents = 0; Sites = 0; InMgmtApi = $false
            }
        }
        $m = $map[$id]
        $m.InMgmtApi = $true
        if ($e.displayName) { $m.Name = $e.displayName }
        if ($e.type -and -not $m.Type) { $m.Type = $e.type }
        $m.SecurityGroupId = [string](Get-Prop $e 'securityGroupId' '')
        $m.State = [string](Get-Prop $e 'state' '')
        $m.Geo = [string](Get-Prop $e 'geo' '')
        $m.Url = [string](Get-Prop $e 'url' '')
        $m.DataverseId = [string](Get-Prop $e 'dataverseId' '')
        $m.Retention = [string](Get-Prop $e 'retentionDetails.retentionPeriod' '')
        $m.ProtectionLevel = [string](Get-Prop $e 'protectionLevel' '')
        $m.AzureRegion = [string](Get-Prop $e 'azureRegion' '')
        $m.CreatedById = [string](Get-Prop $e 'createdBy.id' '')
        $m.CreatedByType = [string](Get-Prop $e 'createdBy.type' '')
        $m.AdminMode = [string](Get-Prop $e 'adminMode' '')
        $m.Cmk = [bool](Get-Prop $e 'enterprisePolicies.encryption.id' $false)
        $m.Vnet = [bool](Get-Prop $e 'enterprisePolicies.networkInjection.id' $false)
        if (-not $m.GroupId -and (Get-Prop $e 'environmentGroupId')) { $m.GroupId = [string]$e.environmentGroupId }
        if (-not $m.CreatedAt -and (Get-Prop $e 'createdDateTime')) { $m.CreatedAt = [string]$e.createdDateTime }
    }
    return $map
}

function Get-EnvLabel {
    param($Map, $EnvId)
    if (-not $EnvId) { return '' }
    $k = ([string]$EnvId).ToLower()
    if ($Map.ContainsKey($k)) { return $Map[$k].Name }
    return [string]$EnvId
}

# ------------------------------------------------------------------ checks: tenant settings (BAP)
function Test-TenantSettings {
    if ($SkipLegacyApis) {
        Add-Finding -Id '2.3' -Title 'Tenant settings' -Status Unavailable -Detail 'Skipped (-SkipLegacyApis). No api.powerplatform.com endpoint exists for tenant settings.' -Source 'api.bap.microsoft.com'
        return
    }
    $r = Invoke-Api -Name 'BAP: list tenant settings' -Method POST -Uri "https://$BapApiHost/providers/Microsoft.BusinessAppPlatform/listtenantsettings?api-version=2020-10-01" -Resource $BapResource
    if (-not $r.Ok) { Add-Unavailable '2.3' 'Tenant settings (Power Platform admin center > Settings)' $r "$BapApiHost listtenantsettings"; return }
    $s = $r.Data
    $src = "$BapApiHost listtenantsettings (no api.powerplatform.com equivalent)"
    $all = New-Object System.Collections.ArrayList
    function Flatten($o, $prefix) {
        foreach ($p in $o.PSObject.Properties) {
            if ($p.Value -is [System.Management.Automation.PSCustomObject]) { Flatten $p.Value ($prefix + $p.Name + '.') }
            else { [void]$all.Add([pscustomobject]@{ Setting = ($prefix + $p.Name); Value = [string]$p.Value }) }
        }
    }
    Flatten $s ''
    Add-Finding -Id '2.3' -Title 'Tenant settings snapshot' -Status Info -Value "$($all.Count) settings captured" -Source $src -Evidence $all.ToArray() `
        -Detail 'Full list of tenant settings returned by the service. Compare to your documented baseline.'

    $rows = @(
        @{ Id = '2.4'; Title = 'Environment creation limited to admins'; Path = 'disableEnvironmentCreationByNonAdminUsers'; Want = $true; Default = $false; Sev = 'High'
            Rec = 'Set "Who can create production and sandbox environments" to Only specific admins in PPAC > Settings.' }
        @{ Id = '2.4'; Title = 'Trial environment creation limited to admins'; Path = 'disableTrialEnvironmentCreationByNonAdminUsers'; Want = $true; Default = $false; Sev = 'High'
            Rec = 'Restrict trial environment creation to admins to prevent unmanaged shadow environments.' }
        @{ Id = '2.4'; Title = 'Developer environment creation limited to admins'; Path = 'powerPlatform.governance.disableDeveloperEnvironmentCreationByNonAdminUsers'; Want = $true; Default = $false; Sev = 'Medium'
            Rec = 'Restrict developer environment creation if default environment routing is not used.' }
        @{ Id = '7.9'; Title = 'Power Pages site creation limited to admins'; Path = 'disablePortalsCreationByNonAdminUsers'; Want = $true; Default = $false; Sev = 'High'
            Rec = 'Restrict portal creation to admins so external-facing sites go through review.' }
        @{ Id = '7.1'; Title = 'Share with Everyone disabled for Power Apps'; Path = 'powerPlatform.powerApps.disableShareWithEveryone'; Want = $true; Default = $true; Sev = 'Critical'
            Rec = 'Keep Share with Everyone disabled (Everyone includes guests). Use security groups instead.' }
        @{ Id = '7.2'; Title = 'Sharing connections with Everyone disabled'; Path = 'powerPlatform.powerApps.DisableConnectionSharingWithEveryone'; Want = $true; Default = $false; Sev = 'High'
            Rec = 'Set DisableConnectionSharingWithEveryone to true so makers cannot share a connection tenant-wide.' }
        @{ Id = '5.7'; Title = 'Guests cannot create Power Apps'; Path = 'powerPlatform.powerApps.enableGuestsToMake'; Want = $false; Default = $false; Sev = 'High'
            Rec = 'Keep enableGuestsToMake false unless a reviewed business case exists.' }
        @{ Id = '3.6'; Title = 'Default environment routing enabled'; Path = 'powerPlatform.governance.enableDefaultEnvironmentRouting'; Want = $true; Default = $false; Sev = 'High'; Optional = $true
            Rec = 'Recommended: enable environment routing so new makers build in a personal developer environment rather than the shared default environment. It is a premium governance feature that needs Managed Environments, so each customer decides.' }
        @{ Id = '4.12'; Title = 'Desktop flow data policy management enabled'; Path = 'powerPlatform.governance.policy.enableDesktopFlowDataPolicyManagement'; Want = $true; Default = $false; Sev = 'Medium'
            Rec = 'Enable desktop flow data policy management so RPA actions fall under data policies.' }
        @{ Id = '14.3'; Title = 'Weekly admin digest enabled'; Path = 'powerPlatform.governance.disableAdminDigest'; Want = $false; Default = $false; Sev = 'Medium'; Optional = $true
            Rec = 'Recommended: keep the admin digest on so managed environment usage and recommendations reach admins. The digest is a Managed Environments feature, so each customer decides.' }
        @{ Id = '16.1'; Title = 'Model data sharing with Microsoft disabled'; Path = 'powerPlatform.modelExperimentation.enableModelDataSharing'; Want = $false; Default = $false; Sev = 'Medium'
            Rec = 'Leave Power Automate Copilot data sharing off unless approved by privacy and legal.' }
    )
    foreach ($row in $rows) {
        $v = Get-Prop $s $row.Path $null
        $explicit = ($null -ne $v)
        if (-not $explicit) { $v = $row.Default }
        $ok = ([bool]$v -eq [bool]$row.Want)
        $st = if ($ok) { 'Pass' } elseif ($row.Optional) { 'Info' } else { 'Fail' }
        $val = "$($row.Path) = $v" + $(if (-not $explicit) { ' (not returned; service default)' } else { '' })
        Add-Finding -Id $row.Id -Title $row.Title -Status $st -Value $val -Severity $row.Sev -Source $src -Recommendation $(if (-not $ok) { $row.Rec } else { '' })
    }
}

function Test-TenantIsolation {
    if ($SkipLegacyApis -or -not $script:Auth.TenantGuid) { return }
    $uri = "https://$BapApiHost/providers/PowerPlatform.Governance/v1/tenants/$($script:Auth.TenantGuid)/tenantIsolationPolicy?api-version=2020-06-01"
    $r = Invoke-Api -Name 'BAP: tenant isolation policy' -Uri $uri -Resource $BapResource
    $src = "$BapApiHost tenantIsolationPolicy (best effort; no api.powerplatform.com equivalent)"
    if ($r.Ok) {
        $props = Get-Prop $r.Data 'properties' $r.Data
        $state = Get-Prop $props 'isDisabled' $null
        $allowed = @(Get-Prop $props 'allowedTenants' @())
        if ($null -ne $state -and -not [bool]$state) {
            Add-Finding -Id '2.5' -Title 'Tenant isolation enabled' -Status Pass -Value "Enabled; $($allowed.Count) allowed tenant rule(s)" -Source $src -Evidence $allowed
        }
        elseif ($null -ne $state) {
            Add-Finding -Id '2.5' -Title 'Tenant isolation enabled' -Status Fail -Value 'Tenant isolation is off' -Source $src `
                -Recommendation 'Turn on tenant isolation and allow-list only required tenants (PPAC > Security > Identity and access).'
        }
        else {
            Add-Finding -Id '2.5' -Title 'Tenant isolation' -Status Info -Value 'Policy returned but state could not be interpreted' -Source $src -Evidence @($r.Data)
        }
    }
    else { Add-Unavailable '2.5' 'Tenant isolation' $r $src }

    $c = Invoke-Api -Name 'Governance: cross-tenant connection reports' -Uri "https://$PowerPlatformApiHost/governance/crossTenantConnectionReports?api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost" -Paged
    if ($c.Ok) {
        $reports = @($c.Data)
        if ($reports.Count -eq 0) {
            Add-Finding -Id '2.5' -Title 'Cross-tenant connection report' -Status Info -Value 'No reports generated yet' -Source 'api.powerplatform.com governance/crossTenantConnectionReports' `
                -Recommendation 'Generate a cross-tenant connection report (POST governance/crossTenantConnectionReports) to see inbound/outbound tenants.'
        }
        else {
            $latest = $reports | Sort-Object { [datetime](Get-Prop $_ 'requestDate' '1970-01-01') } -Descending | Select-Object -First 1
            $conns = @(Get-Prop $latest 'connections' @())
            $ev = $conns | ForEach-Object { [pscustomobject]@{ Direction = $_.connectionType; TenantId = $_.tenantId } }
            $st = if ($conns.Count -gt 0) { 'Warning' } else { 'Pass' }
            Add-Finding -Id '2.5' -Title 'Cross-tenant connections observed' -Status $st -Value "$($conns.Count) cross-tenant connection(s) in latest report ($($latest.startDate) to $($latest.endDate))" `
                -Source 'api.powerplatform.com governance/crossTenantConnectionReports' -Evidence $ev `
                -Recommendation 'Review each tenant; if not required, enable tenant isolation and block it.'
        }
    }
    else { Add-Unavailable '2.5' 'Cross-tenant connection reports' $c 'api.powerplatform.com governance/crossTenantConnectionReports' }
}

function Test-AdvisorRecommendations {
    $r = Invoke-Api -Name 'Analytics: advisor recommendations' -Uri "https://$PowerPlatformApiHost/analytics/advisorRecommendations?api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost" -Paged
    $src = 'api.powerplatform.com analytics/advisorRecommendations (PPAC Actions page)'
    $names = @{}
    $sc = Invoke-Api -Name 'Analytics: advisor scenarios' -Uri "https://$PowerPlatformApiHost/analytics/advisorRecommendations/scenarios?api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost" -Paged
    if ($sc.Ok) { foreach ($x in @($sc.Data)) { $names[[string](Get-Prop $x 'scenario' '')] = [string](Get-Prop $x 'scenarioName' '') } }
    if (-not $r.Ok) { Add-Unavailable '2.6' 'Advisor (actions page) recommendations' $r $src; return }
    $recs = @($r.Data)
    if ($recs.Count -eq 0) { Add-Finding -Id '2.6' -Title 'Advisor recommendations' -Status Pass -Value 'No active recommendations' -Source $src; return }
    foreach ($rec in $recs) {
        $count = [int](Get-Prop $rec 'details.resourceCount' 0)
        $scen = [string](Get-Prop $rec 'scenario' 'unknown')
        $raw = @()
        if ($count -gt 0) {
            $res = Invoke-Api -Name "Analytics: resources for $scen" -Uri "https://$PowerPlatformApiHost/analytics/advisorRecommendations/$([uri]::EscapeDataString($scen))/resources?api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost" -Paged
            if ($res.Ok) { $raw = @($res.Data) }
        }
        $script:AdvisorData[$scen] = [pscustomobject]@{ Scenario = $scen; Name = [string]$names[$scen]; Count = $count; Resources = $raw }
        $ev = @($raw | Select-Object -First $EvidenceRowLimit | ForEach-Object {
                [pscustomobject]@{ Resource = $_.resourceName; Type = $_.resourceType; Environment = $_.environmentName; Owner = $_.resourceOwner; Users30d = $_.resourceUsage; LastAccessed = $_.lastAccessedDate; LastModified = $_.lastModifiedDate; ActionStatus = $_.resourceActionStatus }
            })
        $title = if ($names[$scen]) { $names[$scen] } else { $scen }
        $st = if ($count -gt 0) { 'Warning' } else { 'Pass' }
        $refreshed = Format-IsoDate (Get-Prop $rec 'details.lastRefreshedTimestamp' '')
        Add-Finding -Id '2.6' -Title "Advisor recommendation: $title" -Status $st -Value "$count resource(s); last refreshed $(if ($refreshed) { $refreshed } else { 'n/a' })" `
            -Source $src -Evidence $ev -Recommendation $(if ($count -gt 0) { 'Open the Actions page in PPAC and remediate the listed resources (managed environments only).' } else { '' })
    }
}

# ------------------------------------------------------------------ checks: environments
function Test-Environments {
    param($EnvMap, $Inv)
    $src = 'api.powerplatform.com resourcequery + environmentmanagement'
    $envs = @($EnvMap.Values)
    if ($envs.Count -eq 0) { Add-Unavailable '3.2' 'Environment inventory' $Inv.Envs $src; return }

    foreach ($a in (Get-OkRows $Inv.Apps)) { $k = ([string](Get-Prop $a 'properties.environmentId' '')).ToLower(); if ($EnvMap.ContainsKey($k)) { $EnvMap[$k].Apps++ } }
    foreach ($a in (Get-OkRows $Inv.Flows)) { $k = ([string](Get-Prop $a 'properties.environmentId' '')).ToLower(); if ($EnvMap.ContainsKey($k)) { $EnvMap[$k].Flows++ } }
    foreach ($a in (Get-OkRows $Inv.Agents)) { $k = ([string](Get-Prop $a 'properties.environmentId' '')).ToLower(); if ($EnvMap.ContainsKey($k)) { $EnvMap[$k].Agents++ } }
    foreach ($a in (Get-OkRows $Inv.Sites)) { $k = ([string](Get-Prop $a 'properties.environmentId' '')).ToLower(); if ($EnvMap.ContainsKey($k)) { $EnvMap[$k].Sites++ } }

    $evAll = $envs | Sort-Object Type, Name | ForEach-Object {
        [pscustomobject]@{ Environment = $_.Name; Id = $_.Id; Type = $_.Type; Managed = $_.IsManaged; Group = $_.Group; SecurityGroup = $(if ($_.SecurityGroupId) { 'Yes' } else { 'No' })
            State = $_.State; Geo = $_.Geo; Retention = $_.Retention; Apps = $_.Apps; Flows = $_.Flows; Agents = $_.Agents; Sites = $_.Sites; Created = $_.CreatedAt }
    }
    $byType = ($envs | Group-Object Type | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
    Add-Finding -Id '3.2' -Title 'Environment inventory' -Status Info -Value "$($envs.Count) environments ($byType)" -Source $src -Evidence $evAll
    $script:Kpi['Environments'] = $envs.Count

    # 3.1 default environment
    $def = @($envs | Where-Object { $_.Type -eq 'Default' })
    if ($def.Count -gt 0) {
        $d = $def[0]
        $assets = $d.Apps + $d.Flows + $d.Agents + $d.Sites
        $st = if ($assets -gt $DefaultEnvironmentAssetWarnThreshold) { 'Warning' } elseif (-not $d.IsManaged) { 'Info' } else { 'Pass' }
        $rec = ''
        if ($assets -gt $DefaultEnvironmentAssetWarnThreshold) {
            $rec = 'Move business-critical apps, flows and agents out of the default environment into governed environments.'
            if (-not $d.IsManaged) { $rec += ' Managed Environments on the default environment is also recommended; each customer decides.' }
        }
        elseif (-not $d.IsManaged) { $rec = 'Recommended: consider Managed Environments on the default environment, then apply sharing limits, a restrictive data policy and maker welcome content. How far to roll it out is each customer''s decision.' }
        Add-Finding -Id '3.1' -Title 'Default environment hardening' -Status $st -Severity 'Critical' -Source $src -Recommendation $rec `
            -Value "Managed=$($d.IsManaged); name='$($d.Name)'; apps=$($d.Apps), flows=$($d.Flows), agents=$($d.Agents), sites=$($d.Sites) (warn above $DefaultEnvironmentAssetWarnThreshold)"
        if ($d.Name -match '\(default\)$') {
            Add-Finding -Id '3.1' -Title 'Default environment renamed to state its purpose' -Status Warning -Severity 'Medium' -Source $src `
                -Value "Name is still '$($d.Name)'" -Recommendation 'Rename to something like "Personal Productivity" to communicate intent.'
        }
    }
    else { Add-Finding -Id '3.1' -Title 'Default environment hardening' -Status Unavailable -Detail 'Default environment not found in inventory.' -Source $src }

    # 3.4 managed coverage (Dataverse for Teams environments are deprecated and not eligible, so they are listed but not counted)
    $teamsEnvs = @($envs | Where-Object { $_.Type -eq 'Teams' })
    $eligible = @($envs | Where-Object { $_.Type -ne 'Teams' })
    $managed = @($eligible | Where-Object { $_.IsManaged })
    $pct = if ($eligible.Count -gt 0) { [math]::Round(100 * $managed.Count / $eligible.Count, 0) } else { 0 }
    $script:Kpi['Managed environments %'] = $pct
    $unmanagedProd = @($eligible | Where-Object { -not $_.IsManaged -and $_.Type -in @('Production', 'Default') })
    $unmanagedOther = @($eligible | Where-Object { -not $_.IsManaged -and $_.Type -notin @('Production', 'Default') })
    # Managed Environments is a recommendation: each customer decides how far to roll it out, so coverage is informational and not scored.
    $st = 'Info'
    $ev = @(($unmanagedProd + $unmanagedOther) | ForEach-Object { [pscustomobject]@{ Environment = $_.Name; Type = $_.Type; Id = $_.Id } })
    $teamsNote = if ($teamsEnvs.Count -gt 0) { "; $($teamsEnvs.Count) Dataverse for Teams environment(s) not counted (deprecated)" } else { '' }
    Add-Finding -Id '3.4' -Title 'Managed Environments coverage' -Status $st -Severity 'Low' -Source $src -Evidence $ev `
        -Value "$($managed.Count) of $($eligible.Count) managed ($pct%); unmanaged production/default: $($unmanagedProd.Count); unmanaged other: $($unmanagedOther.Count)$teamsNote" `
        -Recommendation $(if ($unmanagedProd.Count + $unmanagedOther.Count -gt 0) { 'Recommended: consider Managed Environments for production, default and other environments that hold business-critical assets. How far to roll it out is each customer''s decision (PPAC > Security > Overview > Turn on environment management).' } else { '' })

    # 3.5 developer environment deprecation
    $devUnmanaged = @($envs | Where-Object { $_.Type -eq 'Developer' -and -not $_.IsManaged })
    $days = [int][math]::Floor(($DeveloperEnvironmentDeadline.Date - (Get-Date).Date).TotalDays)
    $when = if ($days -ge 0) { "$days days from today" } else { "passed $([math]::Abs($days)) days ago" }
    if ($devUnmanaged.Count -gt 0) {
        Add-Finding -Id '3.5' -Title 'Unmanaged developer environments (deprecation)' -Status Fail -Severity 'Critical' -Source $src `
            -Value "$($devUnmanaged.Count) unmanaged developer environment(s); Microsoft documents a $($DeveloperEnvironmentDeadline.ToString('d MMM yyyy')) deadline ($when)" `
            -Evidence @($devUnmanaged | ForEach-Object { [pscustomobject]@{ Environment = $_.Name; Id = $_.Id; Created = $_.CreatedAt } }) `
            -Recommendation 'Enable Managed Environments on developer environments you want to keep, or delete them. Confirm the latest date on Microsoft Learn (Managed environments overview).'
    }
    else {
        $devAll = @($envs | Where-Object { $_.Type -eq 'Developer' })
        Add-Finding -Id '3.5' -Title 'Unmanaged developer environments (deprecation)' -Status Pass -Value "$($devAll.Count) developer environment(s); none unmanaged" -Source $src
    }

    # 3.7 environment groups
    $groups = @(Get-OkRows $Inv.Groups)
    $inGroup = @($envs | Where-Object { $_.GroupId })
    $st = if ($groups.Count -eq 0) { 'Warning' } else { 'Info' }
    Add-Finding -Id '3.7' -Title 'Environment groups' -Status $st -Source $src `
        -Value "$($groups.Count) group(s); $($inGroup.Count) of $($envs.Count) environments assigned" `
        -Evidence @($groups | ForEach-Object { [pscustomobject]@{ Group = (Get-Prop $_ 'properties.displayName' $_.name); Id = $_.name; Description = (Get-Prop $_ 'properties.description' '') } }) `
        -Recommendation $(if ($groups.Count -eq 0) { 'Create environment groups per governance zone so sharing, solution-checker and maker-credential rules apply at scale.' } else { '' })
    $script:Kpi['Environments in a group %'] = [math]::Round(100 * $inGroup.Count / $envs.Count, 0)

    # 3.8 security groups
    $needSg = @($envs | Where-Object { $_.DataverseId -and $_.Type -in @('Production', 'Sandbox') -and -not $_.SecurityGroupId })
    $nonSgOther = @($envs | Where-Object { $_.DataverseId -and $_.Type -eq 'Trial' -and -not $_.SecurityGroupId })
    $withMgmt = @($envs | Where-Object { $_.InMgmtApi })
    if ($withMgmt.Count -gt 0) {
        $st = if ($needSg.Count -gt 0) { 'Fail' } elseif ($nonSgOther.Count -gt 0) { 'Warning' } else { 'Pass' }
        Add-Finding -Id '3.8' -Title 'Dataverse environments restricted to a security group' -Status $st -Source $src `
            -Value "Production/sandbox without security group: $($needSg.Count); trial without: $($nonSgOther.Count) (developer environments are not counted: they are for one person, and Microsoft's security group guidance covers other environment types)" `
            -Evidence @(($needSg + $nonSgOther) | ForEach-Object { [pscustomobject]@{ Environment = $_.Name; Type = $_.Type; Id = $_.Id } }) `
            -Recommendation $(if ($st -ne 'Pass') { 'Associate an Entra security group with each Dataverse environment so only licensed, intended users can enter.' } else { '' })
    }
    else { Add-Unavailable '3.8' 'Environment security groups' $Inv.EnvMgmt $src }

    # 3.9 lifecycle
    $empty = @($envs | Where-Object { $_.Type -in @('Production', 'Sandbox', 'Trial') -and ($_.Apps + $_.Flows + $_.Agents + $_.Sites) -eq 0 -and (Get-DaysSince $_.CreatedAt) -gt 90 })
    $trial = @($envs | Where-Object { $_.Type -eq 'Trial' })
    $badState = @($envs | Where-Object { $_.State -and $_.State -notin @('Ready', 'Succeeded', 'Enabled') })
    $st = if ($empty.Count -gt 0 -or $badState.Count -gt 0) { 'Warning' } else { 'Pass' }
    Add-Finding -Id '3.9' -Title 'Environment lifecycle (empty, trial, unhealthy)' -Status $st -Source $src `
        -Value "Empty production/sandbox/trial environments older than 90 days: $($empty.Count); trial environments: $($trial.Count); environments not Ready: $($badState.Count)" `
        -Evidence @(($empty + $badState) | Select-Object -Unique | ForEach-Object { [pscustomobject]@{ Environment = $_.Name; Type = $_.Type; State = $_.State; Created = $_.CreatedAt } }) `
        -Recommendation $(if ($st -ne 'Pass') { 'Retire environments with no apps, flows or agents and investigate environments that are not Ready.' } else { '' })

    # 6.8 CMK / VNet
    $cmk = @($envs | Where-Object { $_.Cmk }); $vnet = @($envs | Where-Object { $_.Vnet })
    if ($withMgmt.Count -gt 0) {
        Add-Finding -Id '6.8' -Title 'Customer-managed key linked environments' -Status Info -Source $src `
            -Value "$($cmk.Count) of $($envs.Count) environments have an encryption enterprise policy linked" `
            -Recommendation 'If regulated data requires CMK, confirm it covers Copilot Studio data and that key recovery is tested.'
        Add-Finding -Id '6.7' -Title 'Virtual network (network injection) linked environments' -Status Info -Source $src `
            -Value "$($vnet.Count) of $($envs.Count) environments have a network injection enterprise policy linked"
    }

    # 6.9 backup retention
    $prod = @($envs | Where-Object { $_.Type -eq 'Production' -and $_.Retention })
    if ($prod.Count -gt 0) {
        $short = @($prod | Where-Object { $_.Retention -eq 'P7D' })
        $st = if ($short.Count -gt 0) { 'Warning' } else { 'Pass' }
        Add-Finding -Id '6.9' -Title 'Production backup retention' -Status $st -Source $src `
            -Value "$($short.Count) of $($prod.Count) production environments use the 7-day default retention (P7D)" `
            -Evidence @($prod | ForEach-Object { [pscustomobject]@{ Environment = $_.Name; Retention = $_.Retention } }) `
            -Recommendation $(if ($st -ne 'Pass') { 'Extend backup retention (up to 28 days in managed environments) for production and take manual backups before changes.' } else { '' })
    }

    # 16.1 residency
    $geo = $envs | Where-Object { $_.Geo -or $_.Location } | Group-Object { if ($_.Geo) { $_.Geo } else { $_.Location } } | Sort-Object Name
    Add-Finding -Id '16.1' -Title 'Environment geography distribution' -Status Info -Source $src -Value (($geo | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ') `
        -Recommendation 'Confirm every geography is approved for the data it holds and review cross-geo generative AI data movement.'
}

function Test-EnvironmentSettings {
    param($EnvMap)
    $allDv = @($EnvMap.Values | Where-Object { $_.DataverseId })
    $targets = @($allDv | Select-Object -First $MaxEnvironmentSettingsCalls)
    if ($targets.Count -eq 0) { return }
    if ($allDv.Count -gt $targets.Count) {
        Add-Limitation 'Environment settings' "Settings were read for $($targets.Count) of $($allDv.Count) Dataverse environments (-MaxEnvironmentSettingsCalls $MaxEnvironmentSettingsCalls)."
        $script:StepConfidence = 'Sample'
    }
    $rows = New-Object System.Collections.ArrayList
    $failures = 0
    foreach ($e in $targets) {
        $r = Invoke-Api -Name "EnvironmentManagement: settings ($($e.Name))" -Uri "https://$PowerPlatformApiHost/environmentmanagement/environments/$($e.Id)/settings?api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost"
        if (-not $r.Ok) { $failures++; continue }
        $s = @(Get-Prop $r.Data 'objectResult' @())
        if ($s.Count -eq 0) { $s = @($r.Data) }
        $x = $s[0]
        Add-EnvFact $e.Id 'ConvAudit' (Get-Prop $x 'copilotStudio_ConversationAuditLoggingEnabled' $null)
        [void]$rows.Add([pscustomobject]@{
                Environment = $e.Name; Type = $e.Type; Id = $e.Id
                ConversationAuditLogging = Get-Prop $x 'copilotStudio_ConversationAuditLoggingEnabled' $null
                ConnectedAgents = Get-Prop $x 'copilotStudio_ConnectedAgents' $null
                CodeInterpreter = Get-Prop $x 'copilotStudio_CodeInterpreter' $null
                ComputerUseCredentialsAllowed = Get-Prop $x 'copilotStudio_ComputerUseCredentialsAllowed' $null
                ComputerUseSharedMachines = Get-Prop $x 'copilotStudio_ComputerUseSharedMachines' $null
                AllowCodeApps = Get-Prop $x 'powerApps_AllowCodeApps' $null
                PagesNonProdPublicSites = Get-Prop $x 'powerPages_AllowNonProdPublicSites' $null
            })
    }
    $src = 'api.powerplatform.com environmentmanagement/environments/{id}/settings'
    if ($failures -gt 0) { Add-Limitation 'Environment settings' "$failures of $($targets.Count) environment settings calls failed, so those environments are not assessed for audit logging, computer use or code apps." }
    if ($rows.Count -eq 0) {
        Add-Finding -Id '14.1' -Title 'Environment management settings' -Status Unavailable -Detail "Settings call failed for all $($targets.Count) environments (see API log)." -Source $src
        return
    }
    $note = if ($failures -gt 0) { " ($failures environment(s) not readable)" } else { '' }
    $off = @($rows | Where-Object { $null -ne $_.ConversationAuditLogging -and -not [bool]$_.ConversationAuditLogging })
    $known = @($rows | Where-Object { $null -ne $_.ConversationAuditLogging })
    if ($known.Count -gt 0) {
        $offProd = @($off | Where-Object { $_.Type -in @('Production', 'Default', 'Sandbox') })
        $st = if ($offProd.Count -gt 0) { 'Fail' } elseif ($off.Count -gt 0) { 'Warning' } else { 'Pass' }
        Add-Finding -Id '14.1' -Title 'Copilot Studio conversation audit logging enabled' -Status $st -Severity 'Critical' -Source $src `
            -Value "Disabled in $($off.Count) of $($known.Count) environments$note" -Evidence @($off) `
            -Recommendation $(if ($st -ne 'Pass') { 'Enable conversation audit logging (environment management settings) so agent conversations reach Purview audit.' } else { '' })
    }
    $cu = @($rows | Where-Object { $_.ComputerUseCredentialsAllowed -eq $true -or $_.ComputerUseSharedMachines -eq $true })
    if (@($rows | Where-Object { $null -ne $_.ComputerUseCredentialsAllowed -or $null -ne $_.ComputerUseSharedMachines }).Count -gt 0) {
        Add-Finding -Id '11.2' -Title 'Computer use: stored credentials or shared machines allowed' -Status $(if ($cu.Count -gt 0) { 'Warning' } else { 'Pass' }) -Severity 'High' -Source $src `
            -AlsoCovers @('5.10') -Value "$($cu.Count) environment(s) allow computer-use credentials or shared machines" -Evidence @($cu) `
            -Recommendation $(if ($cu.Count -gt 0) { 'Disable computer-use credential and shared-machine settings unless a reviewed scenario needs them.' } else { '' })
    }
    $ci = @($rows | Where-Object { $_.CodeInterpreter -eq $true })
    $ca = @($rows | Where-Object { $_.ConnectedAgents -eq $true })
    Add-Finding -Id '11.8' -Title 'Connected agents and code interpreter settings' -Status Info -Source $src `
        -Value "Connected agents enabled in $($ca.Count) environment(s); code interpreter enabled in $($ci.Count)$note" -Evidence @($rows) `
        -Recommendation 'Enable agent-to-agent calls and code execution only in environments where the permission boundaries have been reviewed.'
    $cd = @($rows | Where-Object { $_.AllowCodeApps -eq $true })
    if (@($rows | Where-Object { $null -ne $_.AllowCodeApps }).Count -gt 0) {
        Add-Finding -Id '7.5' -Title 'Code apps allowed in environments' -Status Info -Source $src -Value "$($cd.Count) environment(s) allow code apps" `
            -Recommendation 'Allow code apps only in governed environments with a review process for custom code.'
    }
    $pp = @($rows | Where-Object { "$($_.PagesNonProdPublicSites)" -match '^(true|enabled|allow)' })
    if (@($rows | Where-Object { $null -ne $_.PagesNonProdPublicSites }).Count -gt 0) {
        Add-Finding -Id '7.9' -Title 'Public non-production Power Pages sites allowed' -Status $(if ($pp.Count -gt 0) { 'Warning' } else { 'Pass' }) -Source $src `
            -Value "$($pp.Count) environment(s) allow public non-production sites" -Evidence @($pp) `
            -Recommendation $(if ($pp.Count -gt 0) { 'Disallow public non-production sites to reduce unreviewed exposure.' } else { '' })
    }
}

# ------------------------------------------------------------------ Managed Environment configuration (sharing limits, solution checker)
# Reads properties.governanceConfiguration.settings.extendedSettings from the Business Application Platform environment, the same data
# Get-AdminPowerAppEnvironment returns. The Microsoft example settings (Implement reactive governance controls) are the yardstick.
function Get-SharingLimit {
    param($Mode, $MaxIndividuals, $GroupSharingDisabled = $null)
    $m = ([string]$Mode).Trim()
    $limited = $false
    $text = 'No limit'
    if ($m -eq 'disableSharing') { $limited = $true; $text = 'Sharing blocked' }
    elseif ($m -eq 'excludeSharingToSecurityGroups' -or (-not $m -and "$GroupSharingDisabled" -eq 'true')) {
        $limited = $true
        $text = 'No security groups'
        $n = 0
        if ([int]::TryParse(([string]$MaxIndividuals), [ref]$n) -and $n -ge 0) { $text += ", up to $n individuals" }
    }
    return [pscustomobject]@{ Limited = $limited; Text = $text }
}

function Test-ManagedEnvironmentConfiguration {
    param($EnvMap)
    if ($EnvMap.Count -eq 0) { return }
    $src = "$BapApiHost environments, governanceConfiguration (best effort; no api.powerplatform.com equivalent)"
    $title = 'Managed Environment sharing limits and solution checker'
    if ($SkipLegacyApis) {
        Add-Finding -Id '7.1' -AlsoCovers @('7.6', '9.4') -Title $title -Status Unavailable -Severity 'Medium' -Source $src -Detail 'Skipped (-SkipLegacyApis). Managed Environment settings are read from api.bap.microsoft.com.'
        return
    }
    $managed = @($EnvMap.Values | Where-Object { $_.IsManaged -and $_.Type -ne 'Teams' } | Sort-Object Type, Name)
    if ($managed.Count -eq 0) {
        Add-Finding -Id '7.1' -AlsoCovers @('7.6', '9.4') -Title $title -Status Info -Source $src -Value 'No managed environments, so sharing limits and solution checker enforcement do not apply.'
        return
    }
    $cfg = @{}
    $last = $null
    $bapVersion = '2023-06-01'
    $list = Invoke-Api -Name 'BAP: environments (managed environment configuration)' -Uri "https://$BapApiHost/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=$bapVersion" -Resource $BapResource -Paged
    if ($list.Ok) {
        foreach ($x in @($list.Data)) {
            $k = ([string](Get-Prop $x 'name' '')).ToLower()
            $gc = Get-Prop $x 'properties.governanceConfiguration' $null
            if ($k -and $null -ne $gc) { $cfg[$k] = $gc }
        }
    }
    else { $last = $list }
    # The list may leave out the settings; fall back to reading each managed environment on its own.
    $missing = @($managed | Where-Object { -not $cfg.ContainsKey($_.Id) -or $null -eq (Get-Prop $cfg[$_.Id] 'settings.extendedSettings' $null) })
    if ($missing.Count -gt $MaxEnvironmentSettingsCalls) { Add-Limitation 'Managed Environments' "Managed Environment settings were read for $MaxEnvironmentSettingsCalls of $($missing.Count) managed environments (-MaxEnvironmentSettingsCalls $MaxEnvironmentSettingsCalls)." }
    foreach ($e in ($missing | Select-Object -First $MaxEnvironmentSettingsCalls)) {
        $d = Invoke-Api -Name "BAP: environment ($($e.Name))" -Uri "https://$BapApiHost/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/$($e.Id)?api-version=$bapVersion" -Resource $BapResource
        if (-not $d.Ok) { $last = $d; continue }
        $gc = Get-Prop $d.Data 'properties.governanceConfiguration' $null
        if ($null -ne $gc) { $cfg[$e.Id] = $gc }
    }
    $rows = New-Object System.Collections.ArrayList
    foreach ($e in $managed) {
        $x = Get-Prop $cfg[$e.Id] 'settings.extendedSettings' $null
        if ($null -eq $x) {
            [void]$rows.Add([pscustomobject]@{ Environment = $e.Name; Type = $e.Type; Group = $e.Group; Assessed = 'Not readable'; AppSharing = ''; AgentSharing = ''; SolutionChecker = ''; AppLimited = $false; AgentLimited = $false; Checker = ''; WelcomeKnown = $false; WelcomeSet = $false })
            continue
        }
        $app = Get-SharingLimit (Get-Prop $x 'limitSharingMode' '') (Get-Prop $x 'maxLimitUserSharing' '') (Get-Prop $x 'isGroupSharingDisabled' $null)
        $bot = Get-SharingLimit (Get-Prop $x 'bot-limitSharingMode' '') (Get-Prop $x 'bot-maxLimitUserSharing' '')
        $noEditors = ("$(Get-Prop $x 'bot-authoringSharingDisabled' '')" -eq 'true')
        $agentText = if ($bot.Limited -and $noEditors) { "$($bot.Text); editors cannot be added by sharing" } elseif ($noEditors) { 'Editors cannot be added by sharing' } else { $bot.Text }
        $checker = ([string](Get-Prop $x 'solutionCheckerMode' '')).ToLower()
        if (-not $checker) { $checker = 'none' }
        $url = Get-Prop $x 'makerOnboardingUrl' $null
        $markdown = Get-Prop $x 'makerOnboardingMarkdown' $null
        [void]$rows.Add([pscustomobject]@{
                Environment = $e.Name; Type = $e.Type; Group = $e.Group; Assessed = $(if ($e.GroupId) { 'Group rules' } else { 'Yes' })
                AppSharing = $app.Text; AgentSharing = $agentText; SolutionChecker = ($checker.Substring(0, 1).ToUpperInvariant() + $checker.Substring(1))
                AppLimited = $app.Limited; AgentLimited = ($bot.Limited -or $noEditors); Checker = $checker
                WelcomeKnown = ($null -ne $url -or $null -ne $markdown)
                WelcomeSet = (-not [string]::IsNullOrWhiteSpace([string]$url) -or -not [string]::IsNullOrWhiteSpace([string]$markdown))
            })
    }
    $assessed = @($rows | Where-Object { $_.Assessed -eq 'Yes' })
    $inGroup = @($rows | Where-Object { $_.Assessed -eq 'Group rules' })
    $unread = @($rows | Where-Object { $_.Assessed -eq 'Not readable' })
    $scope = "$($rows.Count) managed environment(s): $($assessed.Count) assessed here, $($inGroup.Count) in an environment group (covered by the group rule checks), $($unread.Count) not readable"
    if ($assessed.Count -eq 0) {
        if ($unread.Count -eq $rows.Count) {
            if (-not $last) { $last = [pscustomobject]@{ Status = 200; Error = 'The environment response did not include governanceConfiguration settings.' } }
            Add-Unavailable '7.1' $title $last $src -Severity 'Medium' -AlsoCovers @('7.6', '9.4')
        }
        else { Add-Finding -Id '7.1' -AlsoCovers @('7.6', '9.4') -Title $title -Status Info -Source $src -Value "$scope. Settings of environments in a group are set by the group rules." }
        return
    }
    $optional = 'This is optional and each customer decides. '

    # The Microsoft example limits sharing on the default environment only; other environment types are left without limits.
    $def = @($assessed | Where-Object Type -eq 'Default')
    if ($def.Count -gt 0) {
        $d0 = $def[0]
        $st = if ($d0.AppLimited) { 'Pass' } else { 'Info' }
        Add-Finding -Id '7.1' -Title 'Sharing limits on the default environment (canvas apps)' -Status $st -Severity 'Medium' -Source $src `
            -Value "Default environment '$($d0.Environment)': $($d0.AppSharing)" -Evidence @($rows | Select-Object Environment, Type, Group, Assessed, AppSharing) `
            -Detail ($optional + 'The Microsoft example settings limit sharing in the default environment and leave other environment types without limits. ' + $scope) `
            -Recommendation $(if ($st -ne 'Pass') { 'Recommended: limit sharing in the default environment, for example exclude sharing with security groups and cap the number of individuals (the Microsoft example uses 20), so apps do not spread across the tenant unreviewed (PPAC > Environments > Edit Managed Environments > Limit sharing).' } else { '' })
        $st = if ($d0.AgentLimited) { 'Pass' } else { 'Info' }
        Add-Finding -Id '9.4' -Title 'Agent sharing limits on the default environment' -Status $st -Severity 'Medium' -Source $src `
            -Value "Default environment '$($d0.Environment)': $($d0.AgentSharing)" -Evidence @($rows | Select-Object Environment, Type, Group, Assessed, AgentSharing) `
            -Detail ($optional + 'Agent sharing rules can stop owners from sharing with security groups or adding editors, and cap the number of viewers. ' + $scope) `
            -Recommendation $(if ($st -ne 'Pass') { 'Recommended: set agent sharing limits in the default environment: restrict sharing with security groups, cap the number of viewers and decide whether owners may add editors (PPAC > Environments > Edit Managed Environments > Limit sharing > Agent sharing rules).' } else { '' })
    }

    # Solution checker: Block in production and default, Warn or Block in sandbox and developer, per the Microsoft example.
    $scRows = @($assessed | Where-Object { $_.Type -in @('Production', 'Default', 'Sandbox', 'Developer') })
    if ($scRows.Count -gt 0) {
        $sc = @($scRows | ForEach-Object {
                $strict = $_.Type -in @('Production', 'Default')
                $met = if ($strict) { $_.Checker -eq 'block' } else { $_.Checker -in @('warn', 'block') }
                [pscustomobject]@{ Environment = $_.Environment; Type = $_.Type; SolutionChecker = $_.SolutionChecker; Recommended = $(if ($strict) { 'Block' } else { 'Warn or Block' }); Meets = $(if ($met) { 'Yes' } else { 'No' }) }
            })
        $meets = @($sc | Where-Object Meets -eq 'Yes')
        $dist = (($scRows | Group-Object SolutionChecker | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ')
        $st = if ($meets.Count -eq $sc.Count) { 'Pass' } else { 'Info' }
        Add-Finding -Id '7.6' -Title 'Solution checker enforcement on managed environments' -Status $st -Severity 'Medium' -Source $src `
            -Value "$($meets.Count) of $($sc.Count) assessed managed environment(s) match the Microsoft example (Block in production and default, Warn or Block in sandbox and developer). Modes: $dist" `
            -Evidence $sc -Detail ($optional + $scope) `
            -Recommendation $(if ($st -ne 'Pass') { 'Recommended: turn on solution checker enforcement in managed environments, Block in production and default and Warn in sandbox and developer, so solutions with high-severity issues are caught on import (PPAC > Environments > Edit Managed Environments > Solution checker).' } else { '' })
    }

    # Maker welcome content is only judged when the environment response includes it, so a missing field is never reported as not set.
    $known = @($assessed | Where-Object WelcomeKnown)
    if ($known.Count -gt 0) {
        $set = @($known | Where-Object WelcomeSet)
        $st = if ($set.Count -eq $known.Count) { 'Pass' } else { 'Info' }
        Add-Finding -Id '1.3' -Title 'Maker welcome content on managed environments' -Status $st -Severity 'Medium' -Source $src `
            -Value "Maker welcome content is set in $($set.Count) of $($known.Count) assessed managed environment(s)" `
            -Evidence @($known | Select-Object Environment, Type, @{ Name = 'WelcomeContent'; Expression = { if ($_.WelcomeSet) { 'Set' } else { 'Not set' } } }) `
            -Detail ($optional + $scope) `
            -Recommendation $(if ($st -ne 'Pass') { 'Recommended: add maker welcome content that explains what the environment is for, which data is allowed and who to ask for help (PPAC > Environments > Edit Managed Environments > Maker welcome content).' } else { '' })
    }
}

function Test-RuleSets {
    $r = Invoke-Api -Name 'Governance: rule sets for tenant' -Uri "https://$PowerPlatformApiHost/governance/ruleSets?api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost" -Paged
    $src = 'api.powerplatform.com governance/ruleSets (environment group rules)'
    if (-not $r.Ok) { Add-Unavailable '3.7' 'Environment group rules' $r $src; return }
    $sets = @($r.Data)
    $ev = New-Object System.Collections.ArrayList
    $types = @{}
    foreach ($s in $sets) {
        $flt = Get-Prop $s 'environmentFilter'
        foreach ($p in @(Get-Prop $s 'parameters' @())) {
            $t = [string](Get-Prop $p 'type' 'Unknown')
            $types[$t] = 1 + [int]$types[$t]
            $rules = (@(Get-Prop $p 'value' @()) | ForEach-Object { "$($_.id)=$($_.value)" }) -join '; '
            [void]$ev.Add([pscustomobject]@{ RuleSetId = $s.id; Type = $t; AppliesTo = [string](Get-Prop $p 'resourceType' ''); FilterType = [string](Get-Prop $flt 'type' ''); Environments = @(Get-Prop $flt 'values' @()).Count; Rules = $rules; LastModified = $s.lastModified })
        }
    }
    $wanted = [ordered]@{
        Sharing = @{ Id = '7.1'; Why = 'limits how broadly apps, flows and agents can be shared' }
        CopilotAuth = @{ Id = '5.3'; Why = 'controls maker-provided credentials for agent tools' }
        GenerativeAISettings = @{ Id = '9.6'; Why = 'controls generative AI features in Copilot Studio' }
        CrossGeoCopilotDataMovement = @{ Id = '16.1'; Why = 'controls cross-geo data movement for generative AI' }
        SolutionChecker = @{ Id = '7.6'; Why = 'enforces solution checker on solution import' }
        MakerOnboarding = @{ Id = '1.3'; Why = 'shows maker welcome content and policies' }
        Lifecycle = @{ Id = '17.7'; Why = 'manages inactive and unused resources' }
        Copilot = @{ Id = '9.6'; Why = 'controls Copilot features for the group' }
        AdminDigest = @{ Id = '14.3'; Why = 'sends the weekly admin digest' }
        FlowAutomationRestrictions = @{ Id = '8.1'; Why = 'restricts flow automation behaviors' }
    }
    Add-Finding -Id '3.7' -Title 'Environment group rule sets configured' -Status Info -Source $src -Evidence $ev.ToArray() `
        -Value "$($sets.Count) rule set(s); types: $((($types.Keys | Sort-Object) -join ', '))"
    foreach ($k in $wanted.Keys) {
        $has = $types.ContainsKey($k)
        $imp = $wanted[$k]
        $isCore = $k -in @('Sharing', 'CopilotAuth', 'GenerativeAISettings', 'SolutionChecker')
        $st = if ($has) { 'Pass' } elseif ($isCore) { 'Warning' } else { 'Info' }
        Add-Finding -Id $imp.Id -Title "Environment group rule: $k" -Status $st -Source $src `
            -Value $(if ($has) { "$($types[$k]) rule set(s) configured" } else { 'No rule set of this type found' }) `
            -Recommendation $(if (-not $has -and $isCore) { "Configure the $k rule on environment groups; it $($imp.Why)." } else { '' })
    }
    $script:Kpi['Rule-set types configured'] = $types.Count
}

# ------------------------------------------------------------------ checks: data policies (DLP)
function ConvertTo-NormalizedPolicy {
    param($P)
    $props = Get-Prop $P 'properties' $P
    $name = [string](Get-Prop $props 'displayName' (Get-Prop $P 'displayName' (Get-Prop $P 'DisplayName' (Get-Prop $P 'name' ''))))
    $envType = [string](Get-Prop $props 'environmentType' (Get-Prop $P 'environmentType' (Get-Prop $P 'EnvironmentType' '')))
    $default = [string](Get-Prop $props 'defaultConnectorsClassification' (Get-Prop $P 'defaultConnectorsClassification' ''))
    $envs = @(Get-Prop $props 'environments' (Get-Prop $P 'environments' @()))
    $groups = @(Get-Prop $props 'connectorGroups' (Get-Prop $P 'connectorGroups' (Get-Prop $P 'ConnectorGroups' @())))
    $map = @{ Confidential = 'Business'; General = 'Non-business'; Blocked = 'Blocked'; Business = 'Business'; 'Non-business' = 'Non-business'; NonBusiness = 'Non-business' }
    $connectors = New-Object System.Collections.ArrayList
    foreach ($g in $groups) {
        $cls = [string](Get-Prop $g 'classification' (Get-Prop $g 'Classification' ''))
        $grp = if ($map.ContainsKey($cls)) { $map[$cls] } else { $cls }
        foreach ($c in @(Get-Prop $g 'connectors' (Get-Prop $g 'Connectors' @()))) {
            [void]$connectors.Add([pscustomobject]@{ Group = $grp; Id = [string](Get-Prop $c 'id' ''); Name = [string](Get-Prop $c 'name' '') })
        }
    }
    $envIds = @($envs | ForEach-Object { ([string](Get-Prop $_ 'name' (Get-Prop $_ 'id' $_))).ToLower() })
    # Connector endpoint filtering (Allow/Deny URL patterns per connector) is separate from the custom connector URL patterns. It is read only when the policy data includes it.
    $endpointCfg = @(Get-Prop $props 'connectorConfigurations.endpointConfigurations' (Get-Prop $P 'connectorConfigurations.endpointConfigurations' (Get-Prop $props 'endpointConfigurations' @())))
    $httpRules = 0; $httpDenyAll = $false
    foreach ($ec in $endpointCfg) {
        if ([string](Get-Prop $ec 'connectorId' '') -notmatch '(^|/)(http|shared_http\w*|shared_webcontents|shared_webhook\w*)$') { continue }
        foreach ($rule in @(Get-Prop $ec 'endpointRules' @())) {
            $httpRules++
            if ([string](Get-Prop $rule 'endpoint' '') -eq '*' -and [string](Get-Prop $rule 'behavior' '') -eq 'Deny') { $httpDenyAll = $true }
        }
    }
    return [pscustomobject]@{
        Name = $name; EnvironmentType = $envType; Default = $(if ($map.ContainsKey($default)) { $map[$default] } else { $default })
        EnvironmentIds = $envIds; Connectors = $connectors.ToArray()
        CustomPatterns = @(Get-Prop $props 'customConnectorUrlPatternsDefinition' (Get-Prop $P 'customConnectorUrlPatternsDefinition' @())).Count
        HttpEndpointRules = $httpRules; HttpEndpointDenyByDefault = $httpDenyAll
    }
}

function Get-DataPolicies {
    $candidates = @(
        "https://$BapApiHost/providers/PowerPlatform.Governance/v2/policies?api-version=2016-11-01",
        "https://$BapApiHost/providers/Microsoft.BusinessAppPlatform/scopes/admin/v2/apiPolicies?api-version=2016-11-01",
        "https://$BapApiHost/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies?api-version=2016-11-01"
    )
    $last = $null
    $emptyOk = $null
    foreach ($u in $candidates) {
        $r = Invoke-Api -Name 'BAP: data policies' -Uri $u -Resource $BapResource -Paged
        if ($r.Ok -and @($r.Data).Count -gt 0) { return $r }
        # A successful but empty answer is remembered, then the next endpoint is tried before concluding there are no policies.
        if ($r.Ok -and -not $emptyOk) { $emptyOk = $r }
        if (-not $r.Ok) { $last = $r }
    }
    if ($emptyOk) { return $emptyOk }
    if (Get-Module -ListAvailable Microsoft.PowerApps.Administration.PowerShell) {
        Write-Host '  Data policy endpoints did not answer; trying the Power Apps admin module (it may ask you to sign in again).'
        try {
            Import-Module Microsoft.PowerApps.Administration.PowerShell -ErrorAction Stop
            if ($script:Auth.TenantGuid) { Add-PowerAppsAccount -TenantID $script:Auth.TenantGuid | Out-Null } else { Add-PowerAppsAccount | Out-Null }
            $pol = @(Get-DlpPolicy)
            $json = $pol | ConvertTo-Json -Depth 12 | ConvertFrom-Json
            Add-ApiLog 'Admin module: Get-DlpPolicy' 'PS' 'Get-DlpPolicy' 200 $true 0 @($json).Count ''
            return [pscustomobject]@{ Ok = $true; Status = 200; Error = $null; Data = @($json) }
        }
        catch { Add-ApiLog 'Admin module: Get-DlpPolicy' 'PS' 'Get-DlpPolicy' 0 $false 0 0 $_.Exception.Message }
    }
    return $last
}

function Test-DataPolicies {
    param($EnvMap)
    $src = "$BapApiHost data policies (best effort; no api.powerplatform.com equivalent) or Get-DlpPolicy"
    if ($SkipLegacyApis) { Add-Finding -Id '4.1' -Title 'Data policies' -Status Unavailable -Detail 'Skipped (-SkipLegacyApis).' -Source $src; return }
    $r = Get-DataPolicies
    if (-not $r -or -not $r.Ok) { Add-Unavailable '4.1' 'Data policies (DLP)' $r $src; return }
    $policies = @(@($r.Data) | ForEach-Object { ConvertTo-NormalizedPolicy $_ })
    if ($policies.Count -eq 0) {
        Add-Finding -Id '4.1' -Title 'Tenant-level data policy exists' -Status Fail -Severity 'Critical' -Source $src -Value 'No data policies returned' `
            -Recommendation 'Create a tenant-scoped baseline data policy; set the default connector group to Blocked where practical.'
        return
    }
    $evPol = $policies | ForEach-Object { [pscustomobject]@{ Policy = $_.Name; Scope = $_.EnvironmentType; DefaultGroup = $_.Default; Business = @($_.Connectors | Where-Object Group -eq 'Business').Count; NonBusiness = @($_.Connectors | Where-Object Group -eq 'Non-business').Count; Blocked = @($_.Connectors | Where-Object Group -eq 'Blocked').Count; Environments = $_.EnvironmentIds.Count } }
    Add-Finding -Id '4.1' -Title 'Data policy inventory' -Status Info -Source $src -Value "$($policies.Count) data policy/policies" -Evidence $evPol

    $tenantScoped = @($policies | Where-Object { $_.EnvironmentType -match 'AllEnvironments|ExceptEnvironments' })
    if ($tenantScoped.Count -eq 0) {
        Add-Finding -Id '4.1' -Title 'Tenant-level data policy exists' -Status Fail -Severity 'Critical' -Source $src `
            -Value 'No policy with scope AllEnvironments / ExceptEnvironments' -Recommendation 'Create a tenant-scoped baseline policy so new environments are covered automatically.'
    }
    else {
        Add-Finding -Id '4.1' -Title 'Tenant-level data policy exists' -Status Pass -Severity 'Critical' -Source $src -Value (($tenantScoped | ForEach-Object { "$($_.Name) [$($_.EnvironmentType)]" }) -join '; ')
    }

    # default group of tenant-scoped policies
    foreach ($p in $tenantScoped) {
        $st = switch ($p.Default) { 'Blocked' { 'Pass' } 'Non-business' { 'Warning' } 'Business' { 'Fail' } default { 'Info' } }
        Add-Finding -Id '4.3' -Title "Default group for new connectors: $($p.Name)" -Status $st -Source $src -Value "Default group = $($p.Default)" `
            -Recommendation $(if ($st -in @('Warning', 'Fail')) { 'Set the default group to Blocked (at least for the default-environment policy) so new connectors stay unusable until reviewed.' } else { '' })
    }

    # effective policy for default environment
    $defEnv = @($EnvMap.Values | Where-Object { $_.Type -eq 'Default' } | Select-Object -First 1)
    if ($defEnv.Count -gt 0) {
        $did = $defEnv[0].Id
        $eff = @($policies | Where-Object { $_.EnvironmentType -match 'AllEnvironments' -or ($_.EnvironmentType -match 'ExceptEnvironments' -and $_.EnvironmentIds -notcontains $did) -or ($_.EnvironmentType -match 'OnlyEnvironments' -and $_.EnvironmentIds -contains $did) })
        Add-Finding -Id '4.4' -Title 'Data policy applies to the default environment' -Status $(if ($eff.Count -gt 0) { 'Pass' } else { 'Fail' }) -Severity 'Critical' -Source $src `
            -Value "$($eff.Count) effective polic(ies): $(($eff | ForEach-Object Name) -join '; ')" `
            -Recommendation $(if ($eff.Count -eq 0) { 'Apply a restrictive data policy to the default environment.' } else { '' })
        $strict = @($eff | Where-Object { $_.Default -eq 'Blocked' -or @($_.Connectors | Where-Object Group -eq 'Blocked').Count -ge 50 })
        if ($eff.Count -gt 0) {
            Add-Finding -Id '4.5' -Title 'Restrictive policy (blocked default or many blocked connectors) on default environment' -Status $(if ($strict.Count -gt 0) { 'Pass' } else { 'Warning' }) -Source $src `
                -Value "$($strict.Count) of $($eff.Count) effective polic(ies) are restrictive" `
                -Recommendation $(if ($strict.Count -eq 0) { 'Use advanced connector policies (managed) or block new connectors by default for the default environment.' } else { '' })
        }
    }

    # connector classification for Copilot Studio related connectors across tenant-scoped policies
    $csConnectors = @(
        @{ Label = 'Chat without Microsoft Entra ID authentication in Copilot Studio'; Pattern = 'Chat without (Microsoft Entra ID|Azure AD)'; Id = '4.7'; MustBlock = $true; Sev = 'Critical'; Why = 'allows agents to be published without sign-in' }
        @{ Label = 'HTTP'; Pattern = '^HTTP$'; Id = '4.6'; MustBlock = $true; Sev = 'High'; Why = 'allows HTTP request nodes and flows to call any endpoint (use endpoint filtering if it must stay open)' }
        @{ Label = 'Skills with Copilot Studio'; Pattern = 'Skills with Copilot Studio'; Id = '4.8'; MustBlock = $false; Sev = 'Medium'; Why = 'Azure Bot Service skills extend agents' }
        @{ Label = 'Microsoft Copilot Studio (event triggers, evaluations)'; Pattern = '^Microsoft Copilot Studio$'; Id = '4.8'; MustBlock = $false; Sev = 'Medium'; Why = 'enables event triggers and automated evaluations' }
        @{ Label = 'Application Insights in Copilot Studio'; Pattern = 'Application Insights in Copilot Studio'; Id = '4.8'; MustBlock = $false; Sev = 'Low'; Why = 'telemetry export from agents' }
        @{ Label = 'Direct Line channels in Copilot Studio'; Pattern = 'Direct Line channels'; Id = '4.8'; MustBlock = $false; Sev = 'High'; Why = 'allows web, mobile and custom channels (allowed by default)' }
        @{ Label = 'Facebook channel in Copilot Studio'; Pattern = 'Facebook channel'; Id = '4.8'; MustBlock = $false; Sev = 'Medium'; Why = 'external social channel' }
        @{ Label = 'WhatsApp channel in Copilot Studio'; Pattern = 'WhatsApp channel'; Id = '4.8'; MustBlock = $false; Sev = 'Medium'; Why = 'external messaging channel' }
        @{ Label = 'Omnichannel in Copilot Studio'; Pattern = 'Omnichannel'; Id = '4.8'; MustBlock = $false; Sev = 'Low'; Why = 'Dynamics 365 Customer Service channel' }
        @{ Label = 'SharePoint channel in Copilot Studio'; Pattern = 'SharePoint channel'; Id = '4.8'; MustBlock = $false; Sev = 'Low'; Why = 'SharePoint channel' }
        @{ Label = 'Microsoft Teams + Microsoft 365 Channel in Copilot Studio'; Pattern = 'Teams \+ (Microsoft )?365 Channel'; Id = '4.8'; MustBlock = $false; Sev = 'Low'; Why = 'Teams and Microsoft 365 channel' }
    )
    if ($tenantScoped.Count -gt 0) {
        $table = New-Object System.Collections.ArrayList
        foreach ($cs in $csConnectors) {
            foreach ($p in $tenantScoped) {
                $hit = @($p.Connectors | Where-Object { $_.Name -match $cs.Pattern } | Select-Object -First 1)
                $cls = if ($hit.Count -gt 0) { $hit[0].Group } else { "Default group ($($p.Default))" }
                [void]$table.Add([pscustomobject]@{ Connector = $cs.Label; Policy = $p.Name; Classification = $cls; Purpose = $cs.Why })
            }
        }
        $unauth = @($table | Where-Object { $_.Connector -like 'Chat without*' })
        # A connector that is not listed in a policy takes the policy's default group, so a Blocked default group blocks it too.
        $isBlocked = { param($row) $row.Classification -eq 'Blocked' -or $row.Classification -eq 'Default group (Blocked)' }
        $unauthBlocked = @($unauth | Where-Object { & $isBlocked $_ })
        $st = if ($unauthBlocked.Count -gt 0) { 'Pass' } else { 'Fail' }
        Add-Finding -Id '4.7' -Title 'Unauthenticated agent chat connector blocked by a tenant-scoped policy' -Status $st -Severity 'Critical' -Source $src `
            -Value (($unauth | ForEach-Object { "$($_.Policy): $($_.Classification)" }) -join '; ') -Evidence @($table) `
            -Recommendation $(if ($st -eq 'Fail') { 'Block "Chat without Microsoft Entra ID authentication in Copilot Studio" in a data policy so agents must authenticate users.' } else { '' })
        $http = @($table | Where-Object { $_.Connector -eq 'HTTP' })
        $httpBlocked = @($http | Where-Object { & $isBlocked $_ })
        $custom = ($policies | Measure-Object -Property CustomPatterns -Sum).Sum
        $epRules = ($tenantScoped | Measure-Object -Property HttpEndpointRules -Sum).Sum
        $epDenyAll = @($tenantScoped | Where-Object HttpEndpointDenyByDefault).Count
        # Endpoint filtering rules may not be returned by the policy API, so an unblocked HTTP connector with no visible rules is a Warning to verify, not a Fail.
        $st = if ($httpBlocked.Count -gt 0 -or $epDenyAll -gt 0) { 'Pass' } else { 'Warning' }
        $httpValue = (($http | ForEach-Object { "$($_.Policy): $($_.Classification)" }) -join '; ') + "; HTTP endpoint filtering rules seen: $epRules ($epDenyAll tenant-scoped policy/policies end with Deny *); custom connector URL pattern rules (these apply to custom connectors, not the HTTP connector): $custom"
        Add-Finding -Id '4.6' -Title 'HTTP connector blocked or endpoint-filtered' -Status $st -Source $src `
            -Value $httpValue `
            -Detail 'Connector endpoint filtering (Configure connector > Connector endpoints in a data policy) limits the URLs the HTTP connector can call. This script reads those rules only when the policy data includes them, so no rules seen does not prove none exist.' `
            -Recommendation $(if ($st -ne 'Pass') { 'Block the HTTP connector or configure connector endpoint filtering that ends with Deny * so agents and flows can only reach approved endpoints. If you already filter endpoints, confirm the rules in the data policy.' } else { '' })
        Add-Finding -Id '4.8' -Title 'Copilot Studio channel, skill, trigger and telemetry connector classification' -Status Info -Source $src -Evidence @($table) `
            -Value "$($csConnectors.Count) Copilot Studio connectors evaluated across $($tenantScoped.Count) tenant-scoped polic(ies)" `
            -Recommendation 'Block channels and capabilities you do not use. Direct Line channels are allowed by default.'
    }

    # risky connectors in Business group
    $risky = '(Dropbox|Google|Gmail|Twitter|Facebook|Instagram|LinkedIn|Box$|FTP|SMTP|Outlook\.com|WhatsApp)'
    $bad = New-Object System.Collections.ArrayList
    foreach ($p in $policies) { foreach ($c in @($p.Connectors | Where-Object { $_.Group -eq 'Business' -and $_.Name -match $risky })) { [void]$bad.Add([pscustomobject]@{ Policy = $p.Name; Connector = $c.Name; Group = $c.Group }) } }
    Add-Finding -Id '4.2' -Title 'Consumer / external-service connectors in the Business group' -Status $(if ($bad.Count -gt 0) { 'Warning' } else { 'Pass' }) -Severity 'Critical' -Source $src -Confidence Heuristic `
        -Value "$($bad.Count) risky connector classification(s) in Business groups" -Evidence $bad.ToArray() `
        -Recommendation $(if ($bad.Count -gt 0) { 'Move consumer and external-service connectors out of the Business group, or block them.' } else { '' })
    $script:Kpi['Data policies'] = $policies.Count
}

# ------------------------------------------------------------------ checks: agents
function Test-Agents {
    param($Inv, $EnvMap)
    $src = 'api.powerplatform.com resourcequery (microsoft.copilotstudio/agents)'
    if (-not $Inv.Agents.Ok) { Add-Unavailable '9.1' 'Copilot Studio agent inventory' $Inv.Agents $src; return }
    $rows = @($Inv.Agents.Data)
    $script:Kpi['Agents'] = $rows.Count
    $view = foreach ($a in $rows) {
        $p = $a.properties
        $conn = @(Get-Prop $p 'powerPlatformConnectors' @())
        $ops = foreach ($c in $conn) { foreach ($o in @(Get-Prop $c 'operations' @())) { [pscustomobject]@{ Connector = [string]$c.connectorId; Operation = [string](Get-Prop $o 'operationId' (Get-Prop $o 'OperationId' '')); UsedAs = [string](Get-Prop $o 'usedAs' ''); Enabled = Get-Prop $o 'isEnabled' $true; Consent = Get-Prop $o 'requiresEndUserConsent' $null; When = [string](Get-Prop $o 'whenCanBeUsed' ''); Provider = [string](Get-Prop $o 'connectionProvider' ''); CreatedBy = [string](Get-Prop $o 'createdBy' '') } } }
        [pscustomobject]@{
            Agent = [string](Get-Prop $p 'displayName' $a.name); Id = [string]$a.name; EnvironmentId = [string](Get-Prop $p 'environmentId' ''); Environment = (Get-EnvLabel $EnvMap (Get-Prop $p 'environmentId' ''))
            Owner = [string](Get-Prop $p 'ownerId' ''); CreatedIn = [string](Get-Prop $p 'createdIn' ''); Harness = [string](Get-Prop $p 'harness' ''); Orchestration = [string](Get-Prop $p 'orchestration' '')
            Auth = [string](Get-Prop $p 'authentication' ''); Channels = (@(Get-Prop $p 'channels' @()) -join ', '); LastPublished = [string](Get-Prop $p 'lastPublishedAt' ''); Created = [string](Get-Prop $p 'createdAt' '')
            ViewerUsers = [int](Get-Prop $p 'sharedWithViewers.userCount' 0); ViewerGroups = [int](Get-Prop $p 'sharedWithViewers.groupCount' 0); EntireTenant = [bool](Get-Prop $p 'sharedWithViewers.entireTenant' $false)
            EditorUsers = [int](Get-Prop $p 'sharedWithEditors.userCount' 0); EditorGroups = [int](Get-Prop $p 'sharedWithEditors.groupCount' 0)
            WebSearch = [bool](Get-Prop $p 'IsWebSearchEnabledForKnowledge' (Get-Prop $p 'isWebSearchEnabledForKnowledge' $false)); Quarantined = [bool](Get-Prop $p 'isQuarantined' $false)
            IsManagedSolution = Get-Prop $p 'isManaged' $null; Ops = @($ops)
        }
    }
    $view = @($view)
    if ($view.Count -eq 0) {
        Add-Finding -Id '9.1' -Title 'Copilot Studio agents' -Status Info -Value 'No agents in inventory' -Source $src
        return
    }
    # 1.7 registry
    $byIn = ($view | Group-Object CreatedIn | ForEach-Object { "$(if ($_.Name) { $_.Name } else { 'unknown' })=$($_.Count)" }) -join ', '
    $byHarness = ($view | Group-Object Harness | ForEach-Object { "$(if ($_.Name) { $_.Name } else { 'unknown' })=$($_.Count)" }) -join ', '
    Add-Finding -Id '1.7' -Title 'Agent registry from inventory' -Status Info -Source $src -Value "$($view.Count) agents; created in: $byIn; harness: $byHarness" `
        -Evidence @($view | Select-Object Agent, Environment, CreatedIn, Harness, Orchestration, Auth, Channels, LastPublished, Owner | Select-Object -First $EvidenceRowLimit) `
        -Recommendation 'Reconcile this registry with Microsoft 365 admin center Agents and any Foundry agents; every agent needs an owner and lifecycle state.'

    # 9.1 / 5.2 authentication
    $none = @($view | Where-Object { $_.Auth -match '^None$|No authentication' })
    $unknown = @($view | Where-Object { -not $_.Auth })
    $noneLive = @($none | Where-Object { $_.LastPublished })
    $st = if ($noneLive.Count -gt 0) { 'Fail' } elseif ($none.Count -gt 0) { 'Warning' } else { 'Pass' }
    $ev = @($none | Select-Object Agent, Environment, Channels, LastPublished, EntireTenant, Owner)
    foreach ($id in @('9.1')) {
        Add-Finding -Id $id -AlsoCovers @('5.2', '9.5') -Title 'Agents configured with No authentication' -Status $st -Severity 'Critical' -Source $src -Evidence $ev `
            -Value "$($none.Count) agent(s) with no authentication ($($noneLive.Count) published); authentication not reported for $($unknown.Count)" `
            -Recommendation $(if ($st -ne 'Pass') { 'Switch to Authenticate with Microsoft or manual Entra ID, and block the unauthenticated chat connector in a data policy.' } else { '' })
    }
    $script:Kpi['Unauthenticated agents'] = $none.Count
    $authDist = ($view | Group-Object Auth | ForEach-Object { "$(if ($_.Name) { $_.Name } else { 'n/a' })=$($_.Count)" }) -join ', '
    Add-Finding -Id '9.1' -Title 'Authentication mode distribution' -Status Info -Source $src -Value $authDist

    # 9.2 channels
    $exposed = @($view | Where-Object { $_.Channels -match 'Demo|Custom website|Direct Line|WhatsApp|Facebook|Telephony|Twilio|Slack|Telegram|\bLine\b|GroupMe' })
    $chDist = @($view | ForEach-Object { @($_.Channels -split ',\s*' | Where-Object { $_ }) } | Group-Object | Sort-Object Count -Descending | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
    Add-Finding -Id '9.2' -Title 'Agents published to external or open-web channels' -Status $(if ($exposed.Count -gt 0) { 'Warning' } else { 'Pass' }) -Severity 'Critical' -Source $src `
        -Value "$($exposed.Count) agent(s) on web/external channels. Channel distribution: $chDist" -Evidence @($exposed | Select-Object Agent, Environment, Auth, Channels, LastPublished) `
        -Recommendation $(if ($exposed.Count -gt 0) { 'Confirm each web/external agent requires authentication, uses secured web channel access and is intentionally public.' } else { '' })
    $noneExposed = @($none | Where-Object { $_.Channels -match 'Demo|Custom website|Direct Line|WhatsApp|Facebook' })
    if ($noneExposed.Count -gt 0) {
        Add-Finding -Id '9.3' -Title 'Unauthenticated agents on open channels' -Status Fail -Severity 'Critical' -Source $src -Value "$($noneExposed.Count) agent(s)" `
            -Evidence @($noneExposed | Select-Object Agent, Environment, Channels, LastPublished) -Recommendation 'Highest priority: require authentication or unpublish these agents.'
    }

    # 9.4 sharing
    $tenantShared = @($view | Where-Object { $_.EntireTenant })
    $manyEditors = @($view | Where-Object { ($_.EditorUsers + $_.EditorGroups) -gt 5 })
    $manyViewers = @($view | Where-Object { $_.ViewerUsers -gt 100 })
    $st = if ($tenantShared.Count -gt 0) { 'Fail' } elseif ($manyEditors.Count -gt 0 -or $manyViewers.Count -gt 0) { 'Warning' } else { 'Pass' }
    Add-Finding -Id '9.4' -Title 'Agent sharing scope' -Status $st -Source $src `
        -Value "Shared with entire tenant: $($tenantShared.Count); more than 5 editors: $($manyEditors.Count); more than 100 individual viewers: $($manyViewers.Count)" `
        -Evidence @(($tenantShared + $manyEditors + $manyViewers) | Select-Object -Unique | Select-Object Agent, Environment, EntireTenant, ViewerUsers, ViewerGroups, EditorUsers, EditorGroups) `
        -Recommendation $(if ($st -ne 'Pass') { 'Share by security group, reduce co-authors, and require review for tenant-wide sharing (Sharing and CopilotAuth rules in environment groups).' } else { '' })
    $script:Kpi['Agents shared with entire tenant'] = $tenantShared.Count

    # 9.9 lifecycle
    $neverPub = @($view | Where-Object { -not $_.LastPublished -and (Get-DaysSince $_.Created) -gt 90 })
    $stalePub = @($view | Where-Object { $_.LastPublished -and (Get-DaysSince $_.LastPublished) -gt $StaleDays })
    $quar = @($view | Where-Object { $_.Quarantined })
    Add-Finding -Id '9.9' -Title 'Agent lifecycle: drafts, stale publishes, quarantine' -Status $(if (($neverPub.Count + $stalePub.Count) -gt 0) { 'Warning' } else { 'Pass' }) -Source $src `
        -Value "Never published and older than 90 days: $($neverPub.Count); last published over $StaleDays days ago: $($stalePub.Count); quarantined: $($quar.Count)" `
        -Evidence @(($neverPub + $stalePub + $quar) | Select-Object -Unique | Select-Object Agent, Environment, Created, LastPublished, Quarantined) `
        -Recommendation $(if (($neverPub.Count + $stalePub.Count) -gt 0) { 'Delete or archive abandoned agents and review stale published agents with their owners.' } else { '' })

    # 10.5 web knowledge
    $web = @($view | Where-Object { $_.WebSearch })
    Add-Finding -Id '10.5' -Title 'Agents with web search enabled as a knowledge source' -Status $(if ($web.Count -gt 0) { 'Warning' } else { 'Pass' }) -Source $src `
        -Value "$($web.Count) of $($view.Count) agents" -Evidence @($web | Select-Object Agent, Environment, Auth, Channels) `
        -Recommendation $(if ($web.Count -gt 0) { 'Limit public-web grounding to approved sites with endpoint filtering and disable it where agents handle internal data.' } else { '' })

    # tools / credentials
    $allOps = New-Object System.Collections.ArrayList
    foreach ($a in $view) { foreach ($o in $a.Ops) { [void]$allOps.Add([pscustomobject]@{ Agent = $a.Agent; Environment = $a.Environment; Auth = $a.Auth; Connector = $o.Connector; Operation = $o.Operation; UsedAs = $o.UsedAs; Enabled = $o.Enabled; Provider = $o.Provider; Consent = $o.Consent; When = $o.When }) } }
    $maker = @($allOps | Where-Object { $_.Provider -eq 'Maker' -and $_.UsedAs -ne 'Knowledge' })
    $makerAgents = @($maker | Select-Object -ExpandProperty Agent -Unique)
    $st = if ($maker.Count -gt 0) { 'Warning' } else { 'Pass' }
    foreach ($id in @('11.2')) {
        Add-Finding -Id $id -AlsoCovers @('5.3', '9.5') -Title 'Agent tools using maker-provided credentials' -Status $st -Severity 'Critical' -Source $src `
            -Value "$($maker.Count) tool operation(s) across $($makerAgents.Count) agent(s) use the maker's connection" -Evidence @($maker | Select-Object -First $EvidenceRowLimit) `
            -Recommendation $(if ($st -ne 'Pass') { "Move tools to end-user credentials (PPAC > environment/group > Control maker credential options) or document each exception. Note: enforcing end-user credentials breaks scheduled/autonomous agents." } else { '' })
    }
    $script:Kpi['Agents using maker credentials'] = $makerAgents.Count
    $riskyCombo = @($maker | Where-Object { $_.Operation -match $WriteLikeOperation })
    Add-Finding -Id '11.3' -Title 'Write-like tool operations running as the maker' -Status $(if ($riskyCombo.Count -gt 0) { 'Fail' } else { 'Pass' }) -Severity 'Critical' -Source $src -Confidence Heuristic `
        -Value "$($riskyCombo.Count) operation(s) whose name looks like a write/send/delete action use maker credentials (heuristic on operationId)" -Evidence @($riskyCombo | Select-Object -First $EvidenceRowLimit) `
        -Recommendation $(if ($riskyCombo.Count -gt 0) { 'Require end-user credentials or user confirmation for these actions; confirm the maker account is least privilege.' } else { '' })
    $noConsent = @($allOps | Where-Object { $_.Consent -eq $false -and $_.Operation -match $WriteLikeOperation -and $_.When -eq 'Anytime' })
    if ($allOps.Count -gt 0) {
        Add-Finding -Id '11.3' -Title 'Write-like tools available "Anytime" without end-user consent' -Status $(if ($noConsent.Count -gt 0) { 'Warning' } else { 'Pass' }) -Source $src -Confidence Heuristic `
            -Value "$($noConsent.Count) operation(s)" -Evidence @($noConsent | Select-Object -First $EvidenceRowLimit) `
            -Recommendation $(if ($noConsent.Count -gt 0) { 'Set whenCanBeUsed to specific topics or add confirmation for impactful actions.' } else { '' })
    }
    $tools = @($view | Sort-Object { $_.Ops.Count } -Descending | Select-Object -First 25 | ForEach-Object { [pscustomobject]@{ Agent = $_.Agent; Environment = $_.Environment; ToolOperations = $_.Ops.Count; Connectors = @($_.Ops | Select-Object -ExpandProperty Connector -Unique).Count; Auth = $_.Auth } })
    Add-Finding -Id '11.1' -Title 'Tool inventory (top agents by operations)' -Status Info -Source $src -Value "$($allOps.Count) tool/knowledge operations across $($view.Count) agents" -Evidence $tools

    $ext = @($allOps | Where-Object { $ExternalDataConnectors.ContainsKey($_.Connector) })
    Add-Finding -Id '16.6' -Title 'Agents using external-service connectors' -Status $(if ($ext.Count -gt 0) { 'Warning' } else { 'Pass' }) -Source $src `
        -Value "$($ext.Count) operation(s) use connectors such as SMTP, SFTP, Gmail, Dropbox or HTTP with Entra ID" `
        -Evidence @($ext | Select-Object -First $EvidenceRowLimit) -Recommendation $(if ($ext.Count -gt 0) { 'Confirm each external connector is approved by data policy and reviewed for data exfiltration risk.' } else { '' })

    # 13.1 managed solution
    $withFlag = @($view | Where-Object { $null -ne $_.IsManagedSolution })
    if ($withFlag.Count -gt 0) {
        $unmanaged = @($withFlag | Where-Object { -not [bool]$_.IsManagedSolution })
        Add-Finding -Id '13.1' -Title 'Agents delivered in managed solutions (preview field)' -Status $(if ($unmanaged.Count -gt 0) { 'Warning' } else { 'Pass' }) -Source $src `
            -Value "$($unmanaged.Count) of $($withFlag.Count) agents are not part of a managed solution" -Evidence @($unmanaged | Select-Object Agent, Environment, Owner, LastPublished) `
            -Recommendation $(if ($unmanaged.Count -gt 0) { 'Package production agents in solutions and deploy through pipelines.' } else { '' })
    }
    return $view
}

# ------------------------------------------------------------------ checks: apps, flows, sites
function Test-AppsFlowsSites {
    param($Inv, $EnvMap, $Catalog)
    $src = 'api.powerplatform.com resourcequery (apps, flows, sites)'
    $apps = @(Get-OkRows $Inv.Apps); $flows = @(Get-OkRows $Inv.Flows); $sites = @(Get-OkRows $Inv.Sites)
    $script:OwnerCandidates = @(Get-OwnerCandidate -Apps $apps -Flows $flows -EnvMap $EnvMap)
    if (-not $Inv.Apps.Ok) { Add-Unavailable '7.4' 'Power Apps inventory' $Inv.Apps $src }
    if (-not $Inv.Flows.Ok) { Add-Unavailable '8.1' 'Power Automate inventory' $Inv.Flows $src }
    if ($Inv.Apps.Ok) { $script:Kpi['Apps'] = $apps.Count }
    if ($Inv.Flows.Ok) { $script:Kpi['Flows'] = $flows.Count }
    $byType = ($apps | Group-Object type | ForEach-Object { "$($_.Name.Split('/')[1])=$($_.Count)" }) -join ', '
    $fByType = ($flows | Group-Object type | ForEach-Object { "$($_.Name.Split('/')[1])=$($_.Count)" }) -join ', '
    $na = 'not available'
    $invText = @(
        "Apps: $(if ($Inv.Apps.Ok) { "$($apps.Count) ($byType)" } else { $na })"
        "flows: $(if ($Inv.Flows.Ok) { "$($flows.Count) ($fByType)" } else { $na })"
        "agents: $(if ($script:Kpi.Contains('Agents')) { $script:Kpi['Agents'] } else { $na })"
        "Power Pages sites: $(if ($Inv.Sites.Ok) { $sites.Count } else { $na })"
    ) -join '; '
    if ($Inv.Apps.Ok -or $Inv.Flows.Ok -or $Inv.Sites.Ok) { Add-Finding -Id '1.6' -Title 'Asset inventory totals' -Status Info -Source $src -Value $invText }

    # stale apps / flows
    $staleApps = @($apps | Where-Object { (Get-DaysSince (Get-Prop $_ 'properties.lastModifiedAt' '')) -gt $StaleDays })
    if ($apps.Count -gt 0) {
        Add-Finding -Id '7.4' -Title "Apps not modified for over $StaleDays days" -Status $(if ($staleApps.Count -gt 0) { 'Warning' } else { 'Pass' }) -Source $src `
            -Value "$($staleApps.Count) of $($apps.Count) apps (last-modified is a proxy; usage analytics are in the Advisor recommendations)" `
            -Evidence @($staleApps | Select-Object -First $EvidenceRowLimit | ForEach-Object { [pscustomobject]@{ App = (Get-Prop $_ 'properties.displayName' $_.name); Environment = (Get-EnvLabel $EnvMap (Get-Prop $_ 'properties.environmentId' '')); Owner = (Get-Prop $_ 'properties.ownerId' ''); LastModified = (Get-Prop $_ 'properties.lastModifiedAt' ''); Type = $_.type } }) `
            -Recommendation $(if ($staleApps.Count -gt 0) { 'Archive or reassign dormant apps; they keep live connections and licenses.' } else { '' })
    }
    $q = @($apps | Where-Object { [bool](Get-Prop $_ 'properties.isQuarantined' $false) }) + @($flows | Where-Object { [bool](Get-Prop $_ 'properties.isQuarantined' $false) })
    # A count from an inventory that could not be read would be a false zero, so these results only appear when apps or flows were read.
    $haveAssets = ($Inv.Apps.Ok -or $Inv.Flows.Ok)
    $partialNote = if ($Inv.Apps.Ok -and $Inv.Flows.Ok) { '' } elseif ($Inv.Apps.Ok) { ' (flow inventory not available)' } else { ' (app inventory not available)' }
    if ($haveAssets) { Add-Finding -Id '17.7' -Title 'Quarantined apps and flows' -Status Info -Source $src -Value "$($q.Count) quarantined resource(s)$partialNote" }

    # code apps
    $code = @($apps | Where-Object { $_.type -eq 'microsoft.powerapps/codeapps' })
    if ($code.Count -gt 0) {
        Add-Finding -Id '7.5' -Title 'Code apps present' -Status Warning -Source $src -Value "$($code.Count) code app(s) ($((@($code | Group-Object { Get-Prop $_ 'properties.subType' 'unknown' } | ForEach-Object { "$($_.Name)=$($_.Count)" })) -join ', '))" `
            -Evidence @($code | ForEach-Object { [pscustomobject]@{ App = (Get-Prop $_ 'properties.displayName' $_.name); Environment = (Get-EnvLabel $EnvMap (Get-Prop $_ 'properties.environmentId' '')); Owner = (Get-Prop $_ 'properties.ownerId' ''); SubType = (Get-Prop $_ 'properties.subType' '') } }) `
            -Recommendation 'Require code review and an allow-list for code apps and confirm they are only enabled in governed environments.'
    }

    # connector usage hotspots
    $use = New-Object System.Collections.ArrayList
    foreach ($r in ($apps + $flows)) {
        foreach ($c in @(Get-Prop $r 'properties.powerPlatformConnectors' @())) {
            $cid = [string]$c.connectorId
            [void]$use.Add([pscustomobject]@{ Resource = (Get-Prop $r 'properties.displayName' $r.name); Type = $r.type.Split('/')[1]; Environment = (Get-EnvLabel $EnvMap (Get-Prop $r 'properties.environmentId' '')); Owner = (Get-Prop $r 'properties.ownerId' ''); Connector = $cid; External = $ExternalDataConnectors.ContainsKey($cid) })
        }
    }
    $extUse = @($use | Where-Object External)
    if ($haveAssets) {
        Add-Finding -Id '8.6' -Title 'Apps and flows using external-service connectors' -Status $(if ($extUse.Count -gt 0) { 'Warning' } else { 'Pass' }) -Source $src `
            -Value "$($extUse.Count) usage(s) across $(@($extUse | Select-Object -ExpandProperty Resource -Unique).Count) resource(s): $((($extUse | Group-Object Connector | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '))$partialNote" `
            -Evidence @($extUse | Select-Object -First $EvidenceRowLimit) `
            -Recommendation $(if ($extUse.Count -gt 0) { 'Review the data leaving the tenant through these connectors and confirm they are allowed by data policy.' } else { '' })
    }

    if ($haveAssets -and $Catalog.Count -gt 0) {
        $customIds = @{}
        foreach ($c in $Catalog.Values) { if ($c.Publisher -and $c.Publisher -notmatch '^Microsoft') { $customIds[$c.ConnectorId] = $c } }
        $thirdParty = @($use | Where-Object { $customIds.ContainsKey($_.Connector) })
        $deprecated = @($use | Where-Object { $Catalog.ContainsKey($_.Connector) -and $Catalog[$_.Connector].Deprecated })
        Add-Finding -Id '4.6' -Title 'Apps/flows using non-Microsoft or custom connectors' -Status $(if ($thirdParty.Count -gt 0) { 'Info' } else { 'Pass' }) -Source $src `
            -Value "$($thirdParty.Count) usage(s) of connectors published by someone other than Microsoft (includes custom connectors)" `
            -Evidence @($thirdParty | Select-Object -First $EvidenceRowLimit) -Recommendation 'Review custom connectors for authentication, ownership and endpoint restrictions.'
        if ($deprecated.Count -gt 0) {
            Add-Finding -Id '17.6' -Title 'Resources using deprecated connectors' -Status Warning -Source $src -Value "$($deprecated.Count) usage(s)" -Evidence @($deprecated | Select-Object -First $EvidenceRowLimit) `
                -Recommendation 'Plan migration away from deprecated connectors before retirement.'
        }
    }

    # flows
    $inDefault = @($flows | Where-Object { $e = ([string](Get-Prop $_ 'properties.environmentId' '')).ToLower(); $EnvMap.ContainsKey($e) -and $EnvMap[$e].Type -eq 'Default' })
    if ($flows.Count -gt 0) {
        Add-Finding -Id '8.1' -Title 'Flows living in the default environment' -Status $(if ($inDefault.Count -gt $DefaultEnvironmentAssetWarnThreshold) { 'Warning' } else { 'Info' }) -Source $src `
            -Value "$($inDefault.Count) of $($flows.Count) flows are in the default environment" -Recommendation 'Move business-critical flows to solution-aware production environments with service identities.'
        $trig = ($flows | Group-Object { Get-Prop $_ 'properties.trigger' '(built-in/manual/schedule)' } | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
        Add-Finding -Id '8.2' -Title 'Flow trigger distribution (connector-based triggers only)' -Status Info -Source $src -Value $trig `
            -Recommendation 'The inventory does not expose HTTP request triggers. The finding Flows started by an HTTP request trigger covers them when the Dataverse flow definition scan runs; otherwise review flows with "When an HTTP request is received" manually.'
    }

    # sites
    if ($sites.Count -gt 0) {
        $anon = @($sites | Where-Object { [bool](Get-Prop $_ 'properties.anonymousAccessAllowed' $false) })
        $anonProd = @($anon | Where-Object { (Get-Prop $_ 'properties.siteType' '') -eq 'Production' })
        $st = if ($anonProd.Count -gt 0) { 'Warning' } else { 'Pass' }
        Add-Finding -Id '7.9' -Title 'Power Pages sites allowing anonymous access' -Status $st -Severity 'Critical' -Source $src `
            -Value "$($anon.Count) of $($sites.Count) sites allow anonymous access ($($anonProd.Count) production)" `
            -Evidence @($sites | ForEach-Object { [pscustomobject]@{ Site = (Get-Prop $_ 'properties.displayName' $_.name); Environment = (Get-EnvLabel $EnvMap (Get-Prop $_ 'properties.environmentId' '')); SiteType = (Get-Prop $_ 'properties.siteType' ''); Visibility = (Get-Prop $_ 'properties.siteVisibility' ''); Anonymous = (Get-Prop $_ 'properties.anonymousAccessAllowed' ''); Status = (Get-Prop $_ 'properties.status' ''); Url = (Get-Prop $_ 'properties.siteUrl' '') } }) `
            -Recommendation $(if ($st -ne 'Pass') { 'Review table permissions, web roles and form/list exposure on every anonymous site; enable WAF for production sites.' } else { '' })
    }
    return $use
}

# ------------------------------------------------------------------ owners via Microsoft Graph
function Test-Owners {
    param($Inv, $EnvMap, $AgentView)
    $src = "$GraphHost directoryObjects/getByIds (owner lookup)"
    $res = New-Object System.Collections.ArrayList
    foreach ($r in (Get-OkRows $Inv.Apps)) { [void]$res.Add([pscustomobject]@{ Kind = 'App'; Name = (Get-Prop $r 'properties.displayName' $r.name); Owner = [string](Get-Prop $r 'properties.ownerId' ''); Env = [string](Get-Prop $r 'properties.environmentId' ''); Type = $r.type }) }
    foreach ($r in (Get-OkRows $Inv.Flows)) { [void]$res.Add([pscustomobject]@{ Kind = 'Flow'; Name = (Get-Prop $r 'properties.displayName' $r.name); Owner = [string](Get-Prop $r 'properties.ownerId' ''); Env = [string](Get-Prop $r 'properties.environmentId' ''); Type = $r.type }) }
    foreach ($a in @($AgentView)) { [void]$res.Add([pscustomobject]@{ Kind = 'Agent'; Name = $a.Agent; Owner = $a.Owner; Env = $a.EnvironmentId; Type = 'agent'; Id = $a.Id }) }
    $noOwner = @($res | Where-Object { -not $_.Owner })
    $ids = @($res | Where-Object { $_.Owner } | Select-Object -ExpandProperty Owner -Unique)
    if ($ids.Count -eq 0) { return }
    $found = @{}
    for ($i = 0; $i -lt $ids.Count; $i += 1000) {
        $chunk = @($ids[$i..([Math]::Min($i + 999, $ids.Count - 1))])
        $r = Invoke-Api -Name 'Graph: directoryObjects/getByIds' -Method POST -Uri "https://$GraphHost/v1.0/directoryObjects/getByIds" -Body @{ ids = $chunk; types = @('user', 'servicePrincipal') } -Resource "https://$GraphHost"
        if (-not $r.Ok) { Add-Unavailable '5.8' 'Owner lookup (orphaned assets)' $r $src; return }
        foreach ($o in @(Get-Prop $r.Data 'value' @())) {
            $found[[string]$o.id] = $o
            $nm = [string](Get-Prop $o 'displayName' '')
            if (-not $nm) { $nm = [string](Get-Prop $o 'userPrincipalName' '') }
            if ($nm) { $script:OwnerNames[([string]$o.id).ToLower()] = $nm }
            $upn = [string](Get-Prop $o 'userPrincipalName' '')
            if ($upn) { $script:OwnerUpns[([string]$o.id).ToLower()] = $upn }
        }
    }
    $missing = @($ids | Where-Object { -not $found.ContainsKey($_) })
    $missingSet = @{}
    foreach ($m0 in $missing) { $missingSet[$m0] = $true; $script:OwnerState[([string]$m0).ToLower()] = 'Deleted'; $script:OwnerNames[([string]$m0).ToLower()] = "(deleted account $(([string]$m0).Substring(0, [Math]::Min(8, ([string]$m0).Length))))" }
    # disabled users (batched, capped)
    $disabled = @{}
    $allUsers = @($ids | Where-Object { $found.ContainsKey($_) -and ((Get-Prop $found[$_] '@odata.type' '') -match 'user') })
    $users = @($allUsers | Select-Object -First 500)
    if ($allUsers.Count -gt $users.Count) { Add-Limitation 'Ownership' "Disabled-account checks covered $($users.Count) of $($allUsers.Count) distinct owners; deleted owners were checked for all of them." }
    for ($i = 0; $i -lt $users.Count; $i += 20) {
        $chunk = @($users[$i..([Math]::Min($i + 19, $users.Count - 1))])
        $reqs = @(); $n = 0
        foreach ($u in $chunk) { $n++; $reqs += @{ id = "$n"; method = 'GET'; url = "/users/$u`?`$select=id,accountEnabled" } }
        $b = Invoke-Api -Name 'Graph: $batch user accountEnabled' -Method POST -Uri "https://$GraphHost/v1.0/`$batch" -Body @{ requests = $reqs } -Resource "https://$GraphHost"
        if (-not $b.Ok) { break }
        foreach ($resp in @(Get-Prop $b.Data 'responses' @())) {
            if ($resp.status -eq 200 -and (Get-Prop $resp 'body.accountEnabled' $true) -eq $false) { $disabled[[string]$resp.body.id] = $true }
        }
    }
    foreach ($dk in @($disabled.Keys)) {
        $nm0 = $script:OwnerNames[([string]$dk).ToLower()]
        $script:OwnerState[([string]$dk).ToLower()] = 'Disabled'
        $script:OwnerNames[([string]$dk).ToLower()] = $(if ($nm0) { "$nm0 (disabled)" } else { '(disabled account)' })
    }
    $orphans = @($res | Where-Object { $_.Owner -and ($missingSet.ContainsKey($_.Owner) -or $disabled.ContainsKey($_.Owner)) })
    $script:OrphanedAssets = $orphans
    $ev = @($orphans | Select-Object -First $EvidenceRowLimit | ForEach-Object { [pscustomobject]@{ Kind = $_.Kind; Name = $_.Name; Environment = (Get-EnvLabel $EnvMap $_.Env); Owner = $_.Owner; Reason = $(if ($disabled.ContainsKey($_.Owner)) { 'Owner account disabled' } else { 'Owner not found (deleted)' }) } })
    $script:Kpi['Orphaned assets'] = $orphans.Count
    foreach ($m in @(@{ Id = '5.8'; K = $null; Also = @('17.1') }, @{ Id = '7.4'; K = 'App'; Also = @() }, @{ Id = '8.1'; K = 'Flow'; Also = @() }, @{ Id = '9.9'; K = 'Agent'; Also = @() })) {
        $subset = @(if ($m.K) { $orphans | Where-Object Kind -eq $m.K } else { $orphans })
        $tot = if ($m.K) { @($res | Where-Object Kind -eq $m.K).Count } else { $res.Count }
        $evSub = @(if ($m.K) { $ev | Where-Object Kind -eq $m.K } else { $ev })
        $label = if ($m.K) { "$($m.K.ToLower())s" } else { 'assets' }
        Add-Finding -Id $m.Id -AlsoCovers $m.Also -Title "Orphaned $label (owner deleted or disabled)" -Status $(if ($subset.Count -gt 0) { 'Fail' } else { 'Pass' }) -Source $src -RollupKey 'orphaned-assets' `
            -Value "$($subset.Count) of $tot $label have a deleted or disabled owner; $($noOwner.Count) assets report no owner" -Evidence $evSub `
            -Recommendation $(if ($subset.Count -gt 0) { 'Reassign ownership (PPAC, Reassign Copilot Agent API, or admin cmdlets) and add a leaver step to offboarding.' } else { '' })
    }
}

# ------------------------------------------------------------------ Entra / Graph
function Test-Entra {
    $src = "$GraphHost (Microsoft Graph)"
    $roles = @(
        @{ Name = 'Global Administrator'; Id = '62e90394-69f5-4237-9190-012177145e10'; Max = 5 }
        @{ Name = 'Power Platform Administrator'; Id = '11648597-926c-4cf3-9c36-bcebb0ba8dcc'; Max = 5 }
        @{ Name = 'Dynamics 365 Administrator'; Id = '44367163-eba1-44c3-98af-f5787879f96a'; Max = 5 }
    )
    foreach ($ro in $roles) {
        $a = Invoke-Api -Name "Graph: role assignments ($($ro.Name))" -Uri "https://$GraphHost/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$($ro.Id)'&`$expand=principal" -Resource "https://$GraphHost" -Paged
        if (-not $a.Ok) { Add-Unavailable '2.1' "Admin role members: $($ro.Name)" $a $src; continue }
        $active = @($a.Data)
        $e = Invoke-Api -Name "Graph: eligible assignments ($($ro.Name))" -Uri "https://$GraphHost/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=roleDefinitionId eq '$($ro.Id)'" -Resource "https://$GraphHost" -Paged
        $elig = if ($e.Ok) { @($e.Data).Count } else { -1 }
        $users = @($active | Where-Object { (Get-Prop $_ 'principal.@odata.type' '') -match 'user' })
        foreach ($u in $users) { $pid_ = [string](Get-Prop $u 'principal.id' ''); if ($pid_) { $script:AdminPrincipalIds[$pid_] = $ro.Name } }
        $st = if ($users.Count -gt $ro.Max) { 'Fail' } elseif ($users.Count -gt 3 -and $ro.Name -ne 'Global Administrator') { 'Warning' } else { 'Pass' }
        Add-Finding -Id '2.1' -Title "$($ro.Name): active members" -Status $st -Severity 'Critical' -Source $src `
            -Value "$($users.Count) active user assignment(s) (threshold $($ro.Max)); eligible (PIM) assignments: $(if ($elig -ge 0) { $elig } else { 'not readable' })" `
            -Evidence @($users | ForEach-Object { [pscustomobject]@{ Role = $ro.Name; User = (Get-Prop $_ 'principal.userPrincipalName' ''); DisplayName = (Get-Prop $_ 'principal.displayName' '') } }) `
            -Recommendation $(if ($st -ne 'Pass') { 'Reduce standing assignments; use Environment Admin or System Administrator where possible and make the rest PIM-eligible.' } else { '' })
        if ($elig -ge 0) {
            $st2 = if ($users.Count -gt 0 -and $elig -eq 0) { 'Warning' } else { 'Pass' }
            Add-Finding -Id '2.2' -Title "$($ro.Name): PIM just-in-time usage" -Status $st2 -Severity 'Critical' -Source $src `
                -Value "Active=$($users.Count); eligible=$elig" `
                -Recommendation $(if ($st2 -ne 'Pass') { 'No eligible assignments found; convert standing assignments to PIM-eligible with MFA and approval.' } else { '' })
        }
    }
    $ca = Invoke-Api -Name 'Graph: conditional access policies' -Uri "https://$GraphHost/v1.0/identity/conditionalAccess/policies" -Resource "https://$GraphHost" -Paged
    if ($ca.Ok) {
        $pol = @($ca.Data | Where-Object { $_.state -eq 'enabled' })
        # A policy only counts when it actually requires MFA (built-in control or an authentication strength).
        $requiresMfa = { param($p) (@(Get-Prop $p 'grantControls.builtInControls' @()) -contains 'mfa') -or ($null -ne (Get-Prop $p 'grantControls.authenticationStrength')) }
        $coversAllUsers = { param($p) @(Get-Prop $p 'conditions.users.includeUsers' @()) -contains 'All' }
        $ppApps = @('475226c6-020e-4fb2-8a90-7a972cbfc1d4', '00000007-0000-0000-c000-000000000000', '7df0a125-d3be-4c96-aa54-591f83ff541c')
        $mfaAll = @($pol | Where-Object { @(Get-Prop $_ 'conditions.applications.includeApplications' @()) -contains 'All' -and (& $requiresMfa $_) })
        $ppTargeted = @($pol | Where-Object { (@(Get-Prop $_ 'conditions.applications.includeApplications' @()) | Where-Object { $ppApps -contains $_ }) -and (& $requiresMfa $_) })
        $mfaAllUsers = @($mfaAll | Where-Object { & $coversAllUsers $_ })
        $ppAllUsers = @($ppTargeted | Where-Object { & $coversAllUsers $_ })
        $st = if ($mfaAllUsers.Count -gt 0 -or $ppAllUsers.Count -gt 0) { 'Pass' } elseif ($mfaAll.Count -gt 0 -or $ppTargeted.Count -gt 0) { 'Warning' } else { 'Fail' }
        Add-Finding -Id '5.1' -Title 'Conditional Access requires MFA for all apps or targets Power Platform' -Status $st -Severity 'Critical' -Source $src `
            -Value "Enabled policies: $($pol.Count); MFA on all cloud apps: $($mfaAll.Count) ($($mfaAllUsers.Count) for all users); MFA targeting Power Apps/Dataverse/Flow service: $($ppTargeted.Count) ($($ppAllUsers.Count) for all users)" `
            -Evidence @(($mfaAll + $ppTargeted) | Select-Object -Unique | ForEach-Object { [pscustomobject]@{ Policy = $_.displayName; State = $_.state; AllUsers = [bool](& $coversAllUsers $_) } }) `
            -Recommendation $(switch ($st) {
                'Fail' { 'Create Conditional Access policies (MFA, compliant device) covering makers, admins and agent end users.' }
                'Warning' { 'MFA policies exist but only cover selected users or roles. Extend them to all users, or document who is intentionally excluded.' }
                default { 'Also verify exclusions, device compliance and legacy auth blocking manually.' }
            })
    }
    else { Add-Unavailable '5.1' 'Conditional Access policies' $ca $src }
}

# ------------------------------------------------------------------ Dataverse
function Test-Dataverse {
    param($EnvMap)
    $targets = @(Get-DataverseTargets $EnvMap)
    if ($targets.Count -eq 0) { return }
    $admins = New-Object System.Collections.ArrayList; $audit = New-Object System.Collections.ArrayList
    $tx = New-Object System.Collections.ArrayList; $sol = New-Object System.Collections.ArrayList; $blocked = 0; $adminRead = 0
    foreach ($e in $targets) {
        $base = $e.Url.TrimEnd('/')
        $h = @{ 'OData-MaxVersion' = '4.0'; 'OData-Version' = '4.0' }
        $o = Invoke-Api -Name "Dataverse: organization ($($e.Name))" -Uri "$base/api/data/v9.2/organizations?`$select=name,isauditenabled,isuseraccessauditenabled,isreadauditenabled,auditretentionperiodv2" -Resource $base -ExtraHeaders $h
        if (-not $o.Ok) {
            $o = Invoke-Api -Name "Dataverse: organization basic ($($e.Name))" -Uri "$base/api/data/v9.2/organizations?`$select=name,isauditenabled" -Resource $base -ExtraHeaders $h
        }
        if (-not $o.Ok) { Add-EnvFact $e.Id 'DvAccess' $false; $blocked++; continue }
        Add-EnvFact $e.Id 'DvAccess' $true
        $org = @(Get-Prop $o.Data 'value' @()) | Select-Object -First 1
        [void]$audit.Add([pscustomobject]@{ Environment = $e.Name; Type = $e.Type; AuditEnabled = [bool](Get-Prop $org 'isauditenabled' $false); UserAccessAudit = Get-Prop $org 'isuseraccessauditenabled' $null; ReadAudit = Get-Prop $org 'isreadauditenabled' $null; RetentionDays = Get-Prop $org 'auditretentionperiodv2' $null })
        Add-EnvFact $e.Id 'DvAudit' ([bool](Get-Prop $org 'isauditenabled' $false))
        $r = Invoke-Api -Name "Dataverse: System Administrators ($($e.Name))" -Uri "$base/api/data/v9.2/roles?`$select=name&`$filter=name eq 'System Administrator'&`$expand=systemuserroles_association(`$select=fullname,domainname,isdisabled,accessmode,applicationid)" -Resource $base -ExtraHeaders $h
        if ($r.Ok) {
            $adminRead++
            $seen = @{}
            foreach ($role in @(Get-Prop $r.Data 'value' @())) {
                foreach ($u in @(Get-Prop $role 'systemuserroles_association' @())) {
                    if ($u.isdisabled -or $u.applicationid -or $u.accessmode -eq 4) { continue }
                    $key = [string]$u.domainname; if (-not $key) { $key = [string]$u.fullname }
                    if (-not $seen.ContainsKey($key)) { $seen[$key] = 1; [void]$admins.Add([pscustomobject]@{ Environment = $e.Name; Type = $e.Type; User = $u.fullname; Upn = $u.domainname }) }
                }
            }
            Add-EnvFact $e.Id 'SysAdmins' $seen.Count
        }
        $t = Invoke-Api -Name "Dataverse: conversation transcripts ($($e.Name))" -Uri "$base/api/data/v9.2/conversationtranscripts?`$select=createdon&`$orderby=createdon asc&`$top=1&`$count=true" -Resource $base -ExtraHeaders $h
        if ($t.Ok) {
            $oldest = @(Get-Prop $t.Data 'value' @()) | Select-Object -First 1
            [void]$tx.Add([pscustomobject]@{ Environment = $e.Name; Type = $e.Type; Count = [int](Get-Prop $t.Data '@odata.count' 0); Oldest = [string](Get-Prop $oldest 'createdon' ''); OldestAgeDays = (Get-DaysSince (Get-Prop $oldest 'createdon' '')) })
        }
        $s = Invoke-Api -Name "Dataverse: solutions ($($e.Name))" -Uri "$base/api/data/v9.2/solutions?`$select=uniquename,friendlyname,ismanaged&`$filter=isvisible eq true" -Resource $base -Paged -ExtraHeaders $h
        if ($s.Ok) {
            $custom = @($s.Data | Where-Object { $_.uniquename -notin @('Default', 'Active', 'Basic', 'System') })
            [void]$sol.Add([pscustomobject]@{ Environment = $e.Name; Type = $e.Type; Managed = @($custom | Where-Object ismanaged).Count; Unmanaged = @($custom | Where-Object { -not $_.ismanaged }).Count })
        }
    }
    $src = 'Dataverse Web API per environment (needs access to each environment)'
    $note = "$($targets.Count) environment(s) targeted" + $(if ($blocked -gt 0) { "; $blocked not accessible" } else { '' })
    if ($blocked -gt 0) { Add-Limitation 'Dataverse' "$blocked of $($targets.Count) targeted environments were not accessible to the signed-in user, so auditing, admin counts, transcripts and solutions are unknown for them." }
    if ($audit.Count -eq 0) { Add-Finding -Id '6.4' -Title 'Dataverse checks' -Status Unavailable -Detail "No environment was accessible ($note). Sign in with a user that has a role in the target environments." -Source $src; return }
    $offAudit = @($audit | Where-Object { -not $_.AuditEnabled })
    Add-Finding -Id '6.4' -Title 'Dataverse auditing enabled' -Status $(if ($offAudit.Count -gt 0) { 'Fail' } else { 'Pass' }) -Source $src -Value "Disabled in $($offAudit.Count) of $($audit.Count) environments ($note)" -Evidence @($audit) `
        -Recommendation $(if ($offAudit.Count -gt 0) { 'Turn on auditing and define retention (environment Settings > Audit settings).' } else { '' })
    if ($adminRead -gt 0) {
        $perEnv = $admins | Group-Object Environment
        $worst = if ($perEnv) { ($perEnv | Measure-Object Count -Maximum).Maximum } else { 0 }
        $st = if ($worst -gt 10) { 'Fail' } elseif ($worst -gt 5) { 'Warning' } else { 'Pass' }
        Add-Finding -Id '6.1' -Title 'Interactive System Administrators per environment' -Status $st -Severity 'Critical' -Source $src `
            -Value "Highest count: $worst (warn above 5, fail above 10); System Administrators read in $adminRead of $($audit.Count) accessible environment(s); $note" -Evidence @($admins | Select-Object -First $EvidenceRowLimit) `
            -Detail 'The Power Platform admin center administrator privileges recommendation (managed environments, preview) currently lists environments with more than 20 System Administrators. The thresholds here are stricter and are this script''s own.' `
            -Recommendation $(if ($st -ne 'Pass') { 'Replace System Administrator with least-privilege custom roles and review who holds the role in each environment listed in the evidence.' } else { '' })
    }
    else { Add-Finding -Id '6.1' -Title 'Interactive System Administrators per environment' -Status Unavailable -Severity 'Critical' -Source $src -Detail "The System Administrator role members could not be read in any of the $($audit.Count) accessible environment(s). Needs a Dataverse role that can read security roles and users." }
    if ($tx.Count -gt 0) {
        $old = @($tx | Where-Object { $_.OldestAgeDays -gt 365 })
        Add-Finding -Id '6.5' -Title 'Conversation transcript retention' -Status $(if ($old.Count -gt 0) { 'Warning' } else { 'Info' }) -Severity 'Critical' -Source $src `
            -Value "Environments holding transcripts older than 365 days: $($old.Count) (counts are capped at 5000 by the API)" -Evidence @($tx) `
            -Recommendation 'Define and enforce transcript retention, restrict read access to the Conversation Transcript table and review for PII.'
    }
    if ($sol.Count -gt 0) {
        $bad = @($sol | Where-Object { $_.Type -eq 'Production' -and ($_.Unmanaged -gt 0 -or $_.Managed -eq 0) })
        Add-Finding -Id '13.1' -Title 'Production environments use managed solutions only' -Status $(if ($bad.Count -gt 0) { 'Warning' } else { 'Pass' }) -Source $src `
            -Value "$($bad.Count) production environment(s) have unmanaged solutions or no managed solutions" -Evidence @($sol) `
            -Recommendation $(if ($bad.Count -gt 0) { 'Deploy managed solutions through pipelines; do not build directly in production.' } else { '' })
    }
}

# ------------------------------------------------------------------ Dataverse environment security settings
# The organization columns behind PPAC > environment > Settings > Product > Privacy + Security, plus the guest access setting.
# Column names are the Dataverse logical names (restrictGuestUserAccess really is camel case).
function Get-DataverseOrgSecurity {
    param([string]$Base, [string]$EnvName, [hashtable]$Headers)
    $groups = [ordered]@{
        Network = @('enableipbasedfirewallrule', 'enableipbasedfirewallruleinauditmode', 'allowediprangeforfirewall', 'enableipbasedcookiebinding')
        Guest = @('restrictGuestUserAccess')
        Web = @('iscontentsecuritypolicyenabled', 'iscontentsecuritypolicyenabledforcanvas', 'contentsecuritypolicyreporturi', 'sessiontimeoutenabled', 'sessiontimeoutinmins', 'inactivitytimeoutenabled', 'inactivitytimeoutinmins')
    }
    $values = @{}
    $read = New-Object System.Collections.ArrayList
    $all = @($groups.Values | ForEach-Object { $_ })
    $r = Invoke-Api -Name "Dataverse: security settings ($EnvName)" -Uri "$Base/api/data/v9.2/organizations?`$select=$($all -join ',')" -Resource $Base -ExtraHeaders $Headers
    if ($r.Ok) {
        $org = @(Get-Prop $r.Data 'value' @()) | Select-Object -First 1
        foreach ($c in $all) { $values[$c] = Get-Prop $org $c $null }
        foreach ($g in $groups.Keys) { [void]$read.Add($g) }
    }
    elseif ($r.Status -eq 400) {
        # The service rejected a column it does not know, so ask for each group alone and lose only that group.
        foreach ($g in $groups.Keys) {
            $rg = Invoke-Api -Name "Dataverse: security settings, $g ($EnvName)" -Uri "$Base/api/data/v9.2/organizations?`$select=$($groups[$g] -join ',')" -Resource $Base -ExtraHeaders $Headers
            if (-not $rg.Ok) { continue }
            $org = @(Get-Prop $rg.Data 'value' @()) | Select-Object -First 1
            foreach ($c in $groups[$g]) { $values[$c] = Get-Prop $org $c $null }
            [void]$read.Add($g)
        }
    }
    return [pscustomobject]@{ Values = $values; Read = @($read) }
}

function Test-DataverseEnvironmentSecurity {
    param($EnvMap)
    $targets = @(Get-DataverseTargets $EnvMap)
    if ($targets.Count -eq 0) { return }
    $src = 'Dataverse organization table per environment (needs access to each environment)'
    $rows = New-Object System.Collections.ArrayList
    $readBy = @{ Network = 0; Guest = 0; Web = 0 }
    $skipped = 0
    $onOff = { param($x) if ($null -eq $x) { 'Not reported' } elseif ([bool]$x) { 'On' } else { 'Off' } }
    $csp = { param($enforced, $reporting) if ($null -eq $enforced) { 'Not reported' } elseif ([bool]$enforced) { 'Enforced' } elseif ($reporting) { 'Report-only' } else { 'Off' } }
    $timeout = { param($on, $mins) if ($null -eq $on) { 'Not reported' } elseif ([bool]$on) { $(if ($mins) { "On ($mins min)" } else { 'On' }) } else { 'Off' } }
    foreach ($e in $targets) {
        $facts = $script:EnvFacts[([string]$e.Id).ToLower()]
        if ($null -ne $facts -and $facts.ContainsKey('DvAccess') -and -not [bool]$facts['DvAccess']) { $skipped++; continue }
        $s = Get-DataverseOrgSecurity -Base $e.Url.TrimEnd('/') -EnvName $e.Name -Headers (Get-DataverseHeaders)
        if ($s.Read.Count -eq 0) { $skipped++; continue }
        foreach ($g in $s.Read) { $readBy[$g]++ }
        $v = $s.Values
        $firewall = 'Not reported'
        $enabled = $v['enableipbasedfirewallrule']
        $auditOnly = $v['enableipbasedfirewallruleinauditmode']
        if ($null -ne $enabled) {
            $firewall = if (-not [bool]$enabled) { 'Off' } elseif ($null -eq $auditOnly) { 'On' } elseif ([bool]$auditOnly) { 'Audit-only' } else { 'Enforced' }
        }
        $ranges = $null
        if ($null -ne $v['allowediprangeforfirewall']) { $ranges = @(([string]$v['allowediprangeforfirewall']) -split ',' | Where-Object { $_.Trim() }).Count }
        $guest = 'Not reported'
        if ($null -ne $v['restrictGuestUserAccess']) {
            $guest = if ([bool]$v['restrictGuestUserAccess']) { 'Restricted' } else { 'Allowed' }
            Add-EnvFact $e.Id 'GuestRestricted' ([bool]$v['restrictGuestUserAccess'])
        }
        $reporting = -not [string]::IsNullOrWhiteSpace([string]$v['contentsecuritypolicyreporturi'])
        [void]$rows.Add([pscustomobject]@{
                Environment = $e.Name; Type = $e.Type; Managed = $(if ($e.IsManaged) { 'Yes' } else { 'No' })
                IpFirewall = $firewall; AllowedIpRanges = $ranges; IpCookieBinding = (& $onOff $v['enableipbasedcookiebinding']); GuestAccess = $guest
                CspModelDriven = (& $csp $v['iscontentsecuritypolicyenabled'] $reporting); CspCanvas = (& $csp $v['iscontentsecuritypolicyenabledforcanvas'] $reporting)
                SessionTimeout = (& $timeout $v['sessiontimeoutenabled'] $v['sessiontimeoutinmins']); InactivityTimeout = (& $timeout $v['inactivitytimeoutenabled'] $v['inactivitytimeoutinmins'])
            })
    }
    if ($rows.Count -eq 0) {
        $why = "No targeted environment could be read ($skipped not accessible). Sign in with a user that has a role in the target environments."
        Add-Finding -Id '6.6' -Title 'IP firewall, cookie binding, content security policy and session settings' -Status Unavailable -Severity 'Medium' -Source $src -Detail $why
        Add-Finding -Id '5.7' -Title 'Guest access to Dataverse restricted per environment' -Status Unavailable -Severity 'Medium' -Source $src -Detail $why
        return
    }
    $note = "$($rows.Count) environment(s) read" + $(if ($skipped -gt 0) { "; $skipped not accessible" } else { '' })
    $optional = 'This is optional and each customer decides. '

    # 5.7 guest access: Microsoft restricts it by default for new environments, so only older ones usually differ.
    if ($readBy.Guest -gt 0) {
        $g = @($rows | Where-Object { $_.GuestAccess -ne 'Not reported' })
        $open = @($g | Where-Object GuestAccess -eq 'Allowed')
        $openCore = @($open | Where-Object { $_.Type -in @('Production', 'Default') })
        $st = if ($openCore.Count -gt 0) { 'Warning' } elseif ($open.Count -gt 0) { 'Info' } else { 'Pass' }
        Add-Finding -Id '5.7' -Title 'Guest access to Dataverse restricted per environment' -Status $st -Severity 'Medium' -Source $src `
            -Value "Guest access is allowed in $($open.Count) of $($g.Count) environments ($($openCore.Count) of them production or default); $note" `
            -Evidence @($g | Select-Object Environment, Type, GuestAccess) `
            -Detail 'The setting (restrictGuestUserAccess) only controls guest access to Dataverse. It does not override Microsoft Entra external collaboration settings or Conditional Access.' `
            -Recommendation $(if ($st -ne 'Pass') { 'Recommended: restrict guest access to Dataverse in production and default environments unless guests need it there (PPAC > Security > Identity and access > Guest access). Allowing it in development or test environments for partner collaboration is a supported pattern.' } else { '' })
    }
    else { Add-Finding -Id '5.7' -Title 'Guest access to Dataverse restricted per environment' -Status Unavailable -Severity 'Medium' -Source $src -Detail 'The restrictGuestUserAccess column could not be read in any environment.' }

    # 6.6 IP firewall and cookie binding: both are Managed Environments features, so only managed production environments are measured.
    if ($readBy.Network -gt 0) {
        $n = @($rows | Where-Object { $_.IpFirewall -ne 'Not reported' })
        if ($n.Count -gt 0) {
            $mp = @($n | Where-Object { $_.Type -eq 'Production' -and $_.Managed -eq 'Yes' })
            $enf = @($mp | Where-Object IpFirewall -eq 'Enforced')
            $aud = @($mp | Where-Object IpFirewall -eq 'Audit-only')
            $enfAll = @($n | Where-Object IpFirewall -eq 'Enforced')
            $st = if ($mp.Count -gt 0 -and $enf.Count -eq $mp.Count) { 'Pass' } else { 'Info' }
            $val = if ($mp.Count -eq 0) { "No managed production environment among the $($n.Count) read, and the IP firewall needs Managed Environments; enforced in $($enfAll.Count) of $($n.Count) environments" }
            else { "Enforced in $($enf.Count) of $($mp.Count) managed production environment(s) ($($aud.Count) audit-only); enforced in $($enfAll.Count) of $($n.Count) environments overall" }
            Add-Finding -Id '6.6' -Title 'IP firewall on managed production environments' -Status $st -Severity 'Medium' -Source $src -Value "$val; $note" `
                -Evidence @($n | Select-Object Environment, Type, Managed, IpFirewall, AllowedIpRanges) `
                -Detail ($optional + 'The IP firewall is a Managed Environments feature, and users in a protected environment also need specific Microsoft 365 licenses.') `
                -Recommendation $(if ($st -ne 'Pass' -and $mp.Count -gt 0) { 'Recommended: consider the IP firewall for managed production environments that hold sensitive data. Try it in a test environment, run audit-only in production for at least a week, then enforce it (PPAC > Security > Identity and access > IP firewall).' } else { '' })
        }
        $c = @($rows | Where-Object { $_.IpCookieBinding -ne 'Not reported' })
        if ($c.Count -gt 0) {
            $cp = @($c | Where-Object { $_.Type -eq 'Production' -and $_.Managed -eq 'Yes' })
            $cOn = @($cp | Where-Object IpCookieBinding -eq 'On')
            $cAll = @($c | Where-Object IpCookieBinding -eq 'On')
            $st = if ($cp.Count -gt 0 -and $cOn.Count -eq $cp.Count) { 'Pass' } else { 'Info' }
            $val = if ($cp.Count -eq 0) { "No managed production environment among the $($c.Count) read, and cookie binding needs Managed Environments; on in $($cAll.Count) of $($c.Count) environments" }
            else { "On in $($cOn.Count) of $($cp.Count) managed production environment(s); on in $($cAll.Count) of $($c.Count) environments overall" }
            Add-Finding -Id '6.6' -Title 'IP address-based cookie binding on managed production environments' -Status $st -Severity 'Medium' -Source $src -Value "$val; $note" `
                -Evidence @($c | Select-Object Environment, Type, Managed, IpCookieBinding) `
                -Detail ($optional + 'Cookie binding is a Managed Environments feature. Users sign in again when their IP address changes, for example when a VPN turns on or off.') `
                -Recommendation $(if ($st -ne 'Pass' -and $cp.Count -gt 0) { 'Recommended: consider IP address-based cookie binding for managed production environments so a stolen session cookie cannot be replayed from another network (PPAC > environment > Settings > Product > Privacy + Security).' } else { '' })
        }
    }
    else { Add-Finding -Id '6.6' -Title 'IP firewall and cookie binding on managed production environments' -Status Unavailable -Severity 'Medium' -Source $src -Detail 'The IP firewall and cookie binding columns could not be read in any environment.' }

    # 6.6 content security policy and session timeouts: measured on production environments, managed or not.
    if ($readBy.Web -gt 0) {
        $w = @($rows | Where-Object { $_.CspModelDriven -ne 'Not reported' })
        if ($w.Count -gt 0) {
            $wp = @($w | Where-Object Type -eq 'Production')
            $md = @($wp | Where-Object CspModelDriven -eq 'Enforced')
            $cv = @($wp | Where-Object CspCanvas -eq 'Enforced')
            $ro = @($wp | Where-Object { $_.CspModelDriven -eq 'Report-only' -or $_.CspCanvas -eq 'Report-only' })
            $full = @($wp | Where-Object { $_.CspModelDriven -eq 'Enforced' -and $_.CspCanvas -eq 'Enforced' })
            $st = if ($wp.Count -gt 0 -and $full.Count -eq $wp.Count) { 'Pass' } else { 'Info' }
            $val = if ($wp.Count -eq 0) { "No production environment among the $($w.Count) read" }
            else { "Enforced for model-driven apps in $($md.Count) and for canvas apps in $($cv.Count) of $($wp.Count) production environment(s); $($ro.Count) in report-only mode" }
            Add-Finding -Id '6.6' -Title 'Content security policy enforced on production environments' -Status $st -Severity 'Medium' -Source $src -Value "$val; $note" `
                -Evidence @($w | Select-Object Environment, Type, CspModelDriven, CspCanvas) `
                -Detail ($optional + 'Enforcing a policy can block scenarios that violate it, so Microsoft suggests enforcing in development or test first, report-only in production, then enforcing in production.') `
                -Recommendation $(if ($st -ne 'Pass' -and $wp.Count -gt 0) { 'Recommended: enforce the content security policy in development and test, run report-only in production, then enforce it in production once no violations are reported (PPAC > environment > Settings > Product > Privacy + Security).' } else { '' })
        }
        $t = @($rows | Where-Object { $_.SessionTimeout -ne 'Not reported' })
        if ($t.Count -gt 0) {
            $tp = @($t | Where-Object Type -eq 'Production')
            $sOn = @($tp | Where-Object { $_.SessionTimeout -like 'On*' })
            $iOn = @($tp | Where-Object { $_.InactivityTimeout -like 'On*' })
            $st = if ($tp.Count -gt 0 -and $sOn.Count -eq $tp.Count -and $iOn.Count -eq $tp.Count) { 'Pass' } else { 'Info' }
            $val = if ($tp.Count -eq 0) { "No production environment among the $($t.Count) read" }
            else { "Session expiration on in $($sOn.Count) and inactivity timeout on in $($iOn.Count) of $($tp.Count) production environment(s)" }
            Add-Finding -Id '6.6' -Title 'Session expiration and inactivity timeout on production environments' -Status $st -Severity 'Medium' -Source $src -Value "$val; $note" `
                -Evidence @($t | Select-Object Environment, Type, SessionTimeout, InactivityTimeout) `
                -Detail ($optional + 'By default the Microsoft Entra session policy governs sessions and there is no inactivity timeout. These settings do not apply to canvas apps.') `
                -Recommendation $(if ($st -ne 'Pass' -and $tp.Count -gt 0) { 'Recommended: consider a session length and an inactivity timeout for production environments that hold sensitive data (PPAC > environment > Settings > Product > Privacy + Security).' } else { '' })
        }
    }
    else { Add-Finding -Id '6.6' -Title 'Content security policy and session timeouts on production environments' -Status Unavailable -Severity 'Medium' -Source $src -Detail 'The content security policy and session timeout columns could not be read in any environment.' }
}

# ------------------------------------------------------------------ capacity and licensing
function Test-Capacity {
    $src = 'api.powerplatform.com licensing/tenantCapacity'
    $r = Invoke-Api -Name 'Licensing: tenant capacity' -Uri "https://$PowerPlatformApiHost/licensing/tenantCapacity?api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost"
    if ($r.Ok) {
        $caps = @(Get-Prop $r.Data 'tenantCapacities' @())
        $ev = New-Object System.Collections.ArrayList
        $worst = 0
        foreach ($c in $caps) {
            $total = [double](Get-Prop $c 'totalCapacity' 0); $used = [double](Get-Prop $c 'consumption.actual' 0)
            $pct = if ($total -gt 0) { [math]::Round(100 * $used / $total, 1) } else { $null }
            if ($null -ne $pct -and $pct -gt $worst -and [string]$c.capacityType -in @('Database', 'File', 'Log')) { $worst = $pct }
            [void]$ev.Add([pscustomobject]@{ CapacityType = [string]$c.capacityType; Units = [string]$c.capacityUnits; Total = $total; Consumed = $used; PercentUsed = $pct; Status = [string]$c.status })
        }
        $st = if ($worst -gt 100) { 'Fail' } elseif ($worst -gt 85) { 'Warning' } else { 'Pass' }
        Add-Finding -Id '15.3' -Title 'Dataverse capacity (database, file, log)' -Status $st -Source $src -Value "Highest consumption of database/file/log capacity: $worst%" -Evidence $ev.ToArray() `
            -Recommendation $(if ($st -ne 'Pass') { 'Reclaim storage (transcripts, audit, attachments) or purchase capacity; over-capacity can block backups and environment operations.' } else { '' })
        $script:Kpi['Highest Dataverse capacity use %'] = $worst
    }
    else { Add-Unavailable '15.3' 'Tenant capacity' $r $src }
    $w = Invoke-Api -Name 'Licensing: storage warnings' -Uri "https://$PowerPlatformApiHost/licensing/storageWarning/getAllStorageWarnings?api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost"
    if ($w.Ok) {
        $docs = @(Get-Prop $w.Data 'value' @($w.Data))
        Add-Finding -Id '15.3' -Title 'Storage warning thresholds configured' -Status Info -Source 'api.powerplatform.com licensing/storageWarning' -Value "$($docs.Count) threshold document(s) returned"
    }
    $b = Invoke-Api -Name 'Licensing: billing policies' -Uri "https://$PowerPlatformApiHost/licensing/billingPolicies?api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost" -Paged
    if ($b.Ok) {
        $pol = @($b.Data)
        $off = @($pol | Where-Object { $_.status -eq 'Disabled' })
        Add-Finding -Id '15.2' -Title 'Pay-as-you-go billing policies' -Status Info -Source 'api.powerplatform.com licensing/billingPolicies' `
            -Value "$($pol.Count) billing polic(ies); $($off.Count) disabled" -Evidence @($pol | ForEach-Object { [pscustomobject]@{ Name = $_.name; Id = $_.id; Status = $_.status; Location = $_.location; Subscription = (Get-Prop $_ 'billingInstrument.subscriptionId' ''); LastModified = $_.lastModifiedOn } }) `
            -Recommendation 'Confirm budgets, caps and alerts exist for each linked Azure subscription (Azure Cost Management) and for Copilot Studio credits; caps are not readable through this API.'
    }
    else { Add-Unavailable '15.2' 'Billing policies' $b 'api.powerplatform.com licensing/billingPolicies' }
}


# ------------------------------------------------------------------ usage and adoption (highest used / not used)
$script:Usage = [ordered]@{}
$script:AdvisorData = @{}

function Add-UsageList {
    param([string]$Key, [string]$Title, [string]$Note, [object[]]$Rows, [string]$Metric = '', [string]$Group = '')
    $clean = @($Rows | Where-Object { $null -ne $_ })
    $script:Usage[$Key] = [pscustomobject]@{ Key = $Key; Title = $Title; Note = $Note; Rows = $clean; Metric = $Metric; Group = $Group }
}

function Get-ResourceKind {
    param([string]$Type)
    if ($Type -match 'flow|workflow|automation') { return 'Flow' }
    if ($Type -match 'site|portal|website') { return 'Site' }
    if ($Type -match 'bot|agent|copilot') { return 'Agent' }
    if ($Type -match 'app') { return 'App' }
    if ($Type) { return $Type }
    return 'Other'
}

function Get-RunStart {
    param($Run)
    foreach ($p in 'startTime', 'start', 'createdOn', 'createdon', 'properties.startTime', 'properties.start', 'triggerTime') {
        $v = Get-Prop $Run $p
        if ($v) { try { return [datetime]$v } catch { Write-Verbose "Unrecognized run time '$v'" } }
    }
    return $null
}

function ConvertTo-RunList {
    param($Data)
    if ($null -eq $Data) { return @() }
    if ($Data -is [array]) { return @($Data) }
    foreach ($p in 'value', 'runs', 'objectResult') {
        $v = Get-Prop $Data $p
        if ($null -ne $v) { return @($v) }
    }
    if ($null -ne (Get-RunStart $Data)) { return @($Data) }
    return @()
}

function Get-FlowRunStats {
    param($Inv, $EnvMap)
    $flows = @(Get-OkRows $Inv.Flows | Where-Object { $_.type -eq 'microsoft.powerautomate/cloudflows' -and (Get-Prop $_ 'properties.workflowEntityId') })
    $total = $flows.Count
    $cand = @($flows | Where-Object {
            $k = ([string](Get-Prop $_ 'properties.environmentId' '')).ToLower()
            $EnvMap.ContainsKey($k) -and $EnvMap[$k].DataverseId
        } | Sort-Object { ConvertTo-SortableDate (Get-Prop $_ 'properties.lastModifiedAt' '') } -Descending | Select-Object -First $FlowRunSampleLimit)
    $stats = New-Object System.Collections.ArrayList
    $errors = 0; $consecutive = 0; $first = $null
    $since = (Get-Date).AddDays(-$UsageLookbackDays)
    foreach ($f in $cand) {
        $envId = [string](Get-Prop $f 'properties.environmentId' '')
        $wid = [string](Get-Prop $f 'properties.workflowEntityId' '')
        $r = Invoke-Api -Name "PowerAutomate: flow runs ($($f.name))" -Uri "https://$PowerPlatformApiHost/powerautomate/environments/$envId/flowRuns?workflowId=$wid&api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost"
        if (-not $r.Ok) {
            $errors++; $consecutive++
            if (-not $first) { $first = $r }
            if ($consecutive -ge 8) { break }
            continue
        }
        $consecutive = 0
        $runs = @(ConvertTo-RunList $r.Data)
        $inWindow = @($runs | Where-Object { $s = Get-RunStart $_; $s -and $s -ge $since })
        $failed = @($inWindow | Where-Object { "$(Get-Prop $_ 'status' (Get-Prop $_ 'properties.status' (Get-Prop $_ 'result' '')))" -match 'Fail' })
        $last = $null
        foreach ($x in $runs) { $s = Get-RunStart $x; if ($s -and (-not $last -or $s -gt $last)) { $last = $s } }
        [void]$stats.Add([pscustomobject]@{
                Flow = [string](Get-Prop $f 'properties.displayName' $f.name); Environment = (Get-EnvLabel $EnvMap $envId); Owner = [string](Get-Prop $f 'properties.ownerId' '')
                Trigger = [string](Get-Prop $f 'properties.trigger' ''); Runs = $inWindow.Count; Failed = $failed.Count; LastRun = $last; LastModified = [string](Get-Prop $f 'properties.lastModifiedAt' '')
            })
    }
    return [pscustomobject]@{ Stats = $stats.ToArray(); Total = $total; Sampled = $cand.Count; Errors = $errors; FirstError = $first }
}

function Get-AppReach {
    param($Inv, $EnvMap)
    $rows = New-Object System.Collections.ArrayList
    $envIds = @(Get-OkRows $Inv.Apps | Group-Object { ([string](Get-Prop $_ 'properties.environmentId' '')).ToLower() } | Sort-Object Count -Descending | Select-Object -First $MaxAppSharingEnvironments | ForEach-Object Name)
    $fails = 0
    foreach ($e in $envIds) {
        if (-not $e) { continue }
        $r = Invoke-Api -Name "PowerApps: admin apps ($(Get-EnvLabel $EnvMap $e))" -Uri "https://$PowerPlatformApiHost/powerapps/environments/$e/apps?api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost" -Paged
        if (-not $r.Ok) { $fails++; continue }
        foreach ($a in @($r.Data)) {
            $p = Get-Prop $a 'properties'
            $conns = @(Get-Prop $p 'connectionReferences' @())
            [void]$rows.Add([pscustomobject]@{
                    App = [string](Get-Prop $p 'displayName' $a.name); Environment = (Get-EnvLabel $EnvMap $e); Owner = [string](Get-Prop $p 'owner.displayName' ''); OwnerUpn = [string](Get-Prop $p 'owner.userPrincipalName' '')
                    SharedUsers = [int](Get-Prop $p 'sharedUsersCount' 0); SharedGroups = [int](Get-Prop $p 'sharedGroupsCount' 0)
                    PremiumConnectors = @($conns | Where-Object { (Get-Prop $_ 'apiTier' '') -eq 'Premium' }).Count; CustomConnectors = @($conns | Where-Object { [bool](Get-Prop $_ 'isCustomApiConnection' $false) }).Count
                    LastModified = [string](Get-Prop $p 'lastModifiedTime' ''); Created = [string](Get-Prop $p 'createdTime' '')
                })
        }
    }
    return [pscustomobject]@{ Rows = $rows.ToArray(); Environments = $envIds.Count; Failed = $fails }
}

function Test-Usage {
    param($Inv, $EnvMap, $AgentView)
    $unusedPattern = 'unused|inactive|idle|not used|dormant|no traffic|without any traffic|without traffic'
    $highPattern = 'high.?value|highly used|heavily used|most used|used by over'
    $src = 'api.powerplatform.com analytics/advisorRecommendations (usage-based scenarios)'
    $since = (Get-Date).AddDays(-$UsageLookbackDays)
    $sourceNotes = New-Object System.Collections.ArrayList

    # ---- Advisor: usage-based recommendations
    $all = New-Object System.Collections.ArrayList
    foreach ($k in @($script:AdvisorData.Keys)) {
        $d = $script:AdvisorData[$k]
        $label = "$($d.Scenario) $($d.Name)"
        foreach ($r in @($d.Resources)) {
            [void]$all.Add([pscustomobject]@{
                    Kind = (Get-ResourceKind ([string](Get-Prop $r 'resourceType' ''))); Name = [string](Get-Prop $r 'resourceName' ''); Environment = [string](Get-Prop $r 'environmentName' ''); Owner = [string](Get-Prop $r 'resourceOwner' '')
                    Users30d = Get-Prop $r 'resourceUsage' $null; LastAccessed = [string](Get-Prop $r 'lastAccessedDate' ''); LastModified = [string](Get-Prop $r 'lastModifiedDate' '')
                    Recommendation = $(if ($d.Name) { $d.Name } else { $d.Scenario }); ResourceId = [string](Get-Prop $r 'resourceId' ''); Unused = ($label -match $unusedPattern); HighValue = ($label -match $highPattern); Licensing = ($label -match 'licens|compliance')
                })
        }
    }
    [void]$sourceNotes.Add("Advisor scenarios with data: $(@($script:AdvisorData.Keys | Where-Object { @($script:AdvisorData[$_].Resources).Count -gt 0 }).Count) of $($script:AdvisorData.Count)")
    $unusedAll = @($all | Where-Object Unused)
    $unusedApps = @($unusedAll | Where-Object Kind -eq 'App')
    $unusedSites = @($unusedAll | Where-Object Kind -eq 'Site')
    $high = @($all | Where-Object HighValue)
    # A zero count is only a pass when Advisor actually returned a scenario of that kind; otherwise it is unknown.
    $unusedScenarios = @($script:AdvisorData.Values | Where-Object { "$($_.Scenario) $($_.Name)" -match $unusedPattern })
    $unusedAppScenario = @($unusedScenarios | Where-Object { "$($_.Scenario) $($_.Name)" -notmatch 'site|portal|website' }).Count -gt 0
    $unusedSiteScenario = @($unusedScenarios | Where-Object { "$($_.Scenario) $($_.Name)" -match 'site|portal|website' }).Count -gt 0
    $hasAdvisor = ($script:AdvisorData.Count -gt 0)
    if ($hasAdvisor) { Add-UsageList 'UnusedApps' "Apps not used (Advisor: unused in the last 60 days, managed environments)" 'Source: Advisor recommendation; quarantine, notify the owner, then delete.' @($unusedApps | Select-Object Name, Environment, Owner, LastAccessed, LastModified, Users30d, Recommendation) -Group 'unused' }
    if ($hasAdvisor) { Add-UsageList 'UnusedSites' 'Power Pages sites with no traffic (Advisor: last 30 days)' 'Source: Advisor recommendation; shut down sites nobody visits.' @($unusedSites | Select-Object Name, Environment, Owner, LastAccessed, LastModified, Recommendation) -Group 'unused' }
    $withId = @($all | Where-Object { $null -ne $_.Users30d })
    $top = @($withId | Group-Object { if ($_.ResourceId) { $_.ResourceId } else { $_.Name } } | ForEach-Object {
            $g = @($_.Group)
            [pscustomobject]@{ Kind = $g[0].Kind; Name = $g[0].Name; Environment = $g[0].Environment; Owner = $g[0].Owner; Users30d = [double](($g | Measure-Object Users30d -Maximum).Maximum); OpenRecommendations = (($g | ForEach-Object Recommendation | Sort-Object -Unique) -join '; ') }
        } | Sort-Object Users30d -Descending | Select-Object -First $TopN)
    if ($hasAdvisor) { Add-UsageList 'TopUsedAssets' 'Most-used assets that also have open recommendations (unique users, last 30 days)' 'Source: Advisor resources (resourceUsage). Only assets named in a recommendation appear, so this ranks what to fix first, not every popular app.' $top -Metric 'Users30d' -Group 'top' }

    $anyAdvisor = ($script:AdvisorData.Count -gt 0)
    if (-not $anyAdvisor) {
        Add-Finding -Id '18.1' -Title 'Advisor usage data' -Status Unavailable -Source $src -Detail 'No advisor recommendation data was returned. Usage-based recommendations cover managed environments only and need tenant-wide analytics turned on.' `
            -Recommendation 'Turn on tenant-wide analytics and convert environments to Managed Environments, then re-run (data can take up to 72 hours).'
    }
    else {
        $hvDefault = @($high | Where-Object { $_.Environment -match 'default' })
        Add-Finding -Id '18.2' -Title 'High-value apps (heavily used) flagged by Advisor' -Status $(if ($high.Count -gt 0) { 'Warning' } else { 'Pass' }) -Severity 'High' -Source $src -Confidence Heuristic `
            -Value "$($high.Count) high-value app(s); $($hvDefault.Count) in an environment named default" -Evidence @($high | Select-Object Name, Environment, Owner, Users30d, LastAccessed, Recommendation) `
            -Recommendation $(if ($high.Count -gt 0) { 'Move heavily used apps out of the default environment into managed, solution-based environments with ALM, an owner and a backup owner.' } else { '' })
        Add-Finding -Id '18.2' -Title 'Most-used assets that also carry open recommendations' -Status Info -Source $src -Value "$($top.Count) asset(s) listed (top by unique users in the last 30 days)" -Evidence $top `
            -Recommendation 'Fix these first: high usage multiplies the impact of any security or ownership gap.'
        $st183 = if (-not $unusedAppScenario) { 'Info' } elseif ($unusedApps.Count -gt 0) { 'Warning' } else { 'Pass' }
        $val183 = if (-not $unusedAppScenario) { "No unused-app scenario was recognized among the $($script:AdvisorData.Count) Advisor scenario(s) returned (Advisor reports managed environments with usage analytics only)" } else { "$($unusedApps.Count) unused app(s) in managed environments" }
        Add-Finding -Id '18.3' -AlsoCovers @('15.8') -Title 'Unused apps (no use in 60 days)' -Status $st183 -Severity 'High' -Source $src -Confidence Heuristic `
            -Value $val183 -Evidence @($unusedApps | Select-Object Name, Environment, Owner, LastAccessed, LastModified) `
            -Recommendation $(if ($unusedApps.Count -gt 0) { 'Notify owners, quarantine, and delete after a grace period; unused apps keep live connections and shared access.' } elseif (-not $unusedAppScenario) { 'Convert environments to Managed Environments and turn on tenant-wide analytics so Advisor can report unused apps, or review usage in PPAC analytics.' } else { '' })
        $st188 = if (-not $unusedSiteScenario) { 'Info' } elseif ($unusedSites.Count -gt 0) { 'Warning' } else { 'Pass' }
        $val188 = if (-not $unusedSiteScenario) { "No Power Pages traffic scenario was recognized among the $($script:AdvisorData.Count) Advisor scenario(s) returned" } else { "$($unusedSites.Count) site(s) with no traffic in the last 30 days" }
        Add-Finding -Id '18.8' -Title 'Power Pages sites without traffic' -Status $st188 -Source $src -Confidence Heuristic `
            -Value $val188 -Evidence @($unusedSites | Select-Object Name, Environment, Owner, LastAccessed) `
            -Recommendation $(if ($unusedSites.Count -gt 0) { 'Shut down or retire sites nobody visits; each one is an exposed endpoint.' } else { '' })
        $lic = @($all | Where-Object Licensing)
        if ($lic.Count -gt 0) {
            Add-Finding -Id '18.9' -Title 'Usage versus licensing recommendations' -Status Warning -Source $src -Confidence Heuristic -Value "$($lic.Count) resource row(s) in licensing-related recommendations" `
                -Evidence @($lic | Select-Object Kind, Name, Environment, Owner, Users30d, Recommendation) -Recommendation 'Review users and apps running without the required license in managed environments and reclaim idle licenses.'
        }
    }
    if ($unusedAppScenario) { $script:Kpi['Unused apps (Advisor, 60d)'] = $unusedApps.Count }
    if ($unusedSiteScenario) { $script:Kpi['Sites without traffic (30d)'] = $unusedSites.Count }

    # ---- Copilot credit consumption by agent
    $from = $since.ToString('yyyy-MM-dd'); $to = (Get-Date).ToString('yyyy-MM-dd')
    $c = Invoke-Api -Name 'Licensing: Copilot credit consumption by resource (MCSMessages)' -Uri "https://$PowerPlatformApiHost/licensing/entitlements/MCSMessages/resources?fromDate=$from&toDate=$to&pageSize=1000&api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost" -Paged -UseContinuationToken
    $srcC = 'api.powerplatform.com licensing/entitlements/MCSMessages/resources (entitlement insight)'
    if ($c.Ok) {
        $items = New-Object System.Collections.ArrayList
        foreach ($i in @($c.Data)) {
            $inner = Get-Prop $i 'resources'
            if ($null -ne $inner) { foreach ($x in @($inner)) { [void]$items.Add($x) } } else { [void]$items.Add($i) }
        }
        $byRes = @{}
        foreach ($i in $items) {
            $rid = ([string](Get-Prop $i 'resourceId' '')).ToLower()
            if (-not $rid) { continue }
            if (-not $byRes.ContainsKey($rid)) { $byRes[$rid] = [pscustomobject]@{ ResourceId = $rid; Consumed = 0.0; EnvironmentId = [string](Get-Prop $i 'environmentId' ''); Unit = [string](Get-Prop $i 'unit' ''); Feature = [string](Get-Prop $i 'metadata.Feature' (Get-Prop $i 'metadata.feature' '')); Product = [string](Get-Prop $i 'metadata.ProductName' (Get-Prop $i 'metadata.productName' '')) } }
            $byRes[$rid].Consumed += [double](Get-Prop $i 'consumed' 0)
        }
        $agentById = @{}
        foreach ($a in @($AgentView)) { if ($a.Id) { $agentById[([string]$a.Id).ToLower()] = $a } }
        $joined = @($byRes.Keys | Where-Object { $agentById.ContainsKey($_) })
        $rowsC = @($byRes.Values | Sort-Object Consumed -Descending | ForEach-Object {
                $ag = $agentById[$_.ResourceId]
                [pscustomobject]@{ Agent = $(if ($ag) { $ag.Agent } else { '(not matched to an agent) ' + $_.ResourceId }); Environment = $(if ($ag) { $ag.Environment } else { Get-EnvLabel $EnvMap $_.EnvironmentId }); Owner = $(if ($ag) { $ag.Owner } else { '' }); CreditsConsumed = [math]::Round($_.Consumed, 1); Unit = $_.Unit; Feature = $_.Feature; Product = $_.Product }
            })
        $script:AgentCredits = $byRes
        Add-UsageList 'TopAgents' "Agents consuming the most Copilot credits (last $UsageLookbackDays days)" 'Source: licensing entitlement insight, entitlement MCSMessages. Credits are billing consumption, a proxy for agent usage.' @($rowsC | Select-Object -First $TopN) -Metric 'CreditsConsumed' -Group 'top'
        $note = if ($items.Count -gt 0 -and $joined.Count -eq 0 -and @($AgentView).Count -gt 0) { ' None of the consumption resource IDs matched inventory agent IDs; confirm the ID mapping before trusting unused-agent results.' } else { '' }
        Add-Finding -Id '18.6' -Title 'Highest Copilot credit consumers' -Status Info -Severity 'High' -Source $srcC -Value "$($byRes.Count) resource(s) with consumption since $from; $($joined.Count) matched to inventory agents.$note" -Evidence @($rowsC | Select-Object -First $EvidenceRowLimit) `
            -Recommendation 'Confirm each top consumer has an owner, a cost center, authentication, an agent-level limit and a funded environment.'
        if ($joined.Count -gt 0) {
            $live = @($AgentView | Where-Object { $_.LastPublished })
            $idle = @($live | Where-Object { -not $byRes.ContainsKey(([string]$_.Id).ToLower()) })
            Add-UsageList 'UnusedAgents' "Published agents with no Copilot credit consumption (last $UsageLookbackDays days)" 'Source: inventory (published) compared with entitlement consumption. No consumption can also mean usage covered by a license that is not metered here.' @($idle | Select-Object Agent, Environment, Owner, Channels, LastPublished, Auth) -Group 'unused'
            Add-Finding -Id '18.7' -AlsoCovers @('15.8') -Title 'Published agents with no consumption' -Status $(if ($idle.Count -gt 0) { 'Warning' } else { 'Pass' }) -Severity 'High' -Source $srcC `
                -Value "$($idle.Count) of $($live.Count) published agents show no credit consumption since $from" -Evidence @($idle | Select-Object Agent, Environment, Owner, Channels, LastPublished, Auth) `
                -Recommendation $(if ($idle.Count -gt 0) { 'Confirm with owners, then unpublish or delete idle agents (especially any with open channels or no authentication).' } else { '' })
            $script:Kpi['Published agents with no credit use'] = $idle.Count
        }
        [void]$sourceNotes.Add("Credit consumption rows: $($items.Count)")
    }
    else {
        Add-Unavailable '18.6' 'Copilot credit consumption by agent' $c $srcC
        Add-Finding -Id '18.7' -Title 'Published agents with no consumption' -Status Unavailable -Source $srcC -Detail 'Consumption data was not available, so idle agents could not be determined. Fall back to Copilot Studio analytics or the PPAC Copilot Studio consumption report.'
    }

    # ---- Flow runs
    if ($FlowRunSampleLimit -gt 0) {
        $fr = Get-FlowRunStats -Inv $Inv -EnvMap $EnvMap
        $srcF = 'api.powerplatform.com powerautomate/environments/{id}/flowRuns?workflowId='
        if ($fr.Sampled -gt 0 -and $fr.Stats.Count -eq 0 -and $fr.FirstError) {
            Add-Unavailable '18.4' 'Flow run history' $fr.FirstError $srcF
        }
        elseif ($fr.Stats.Count -gt 0) {
            $topF = @($fr.Stats | Sort-Object Runs -Descending | Select-Object -First $TopN | Select-Object Flow, Environment, Owner, Trigger, Runs, Failed, LastRun, LastModified)
            $idleF = @($fr.Stats | Where-Object { $_.Runs -eq 0 })
            $failing = @($fr.Stats | Where-Object { $_.Runs -ge 5 -and ($_.Failed / [double]$_.Runs) -ge 0.5 })
            Add-UsageList 'TopFlows' "Flows with the most runs (last $UsageLookbackDays days, sample of $($fr.Stats.Count) of $($fr.Total))" 'Source: flow runs API for a sample of Dataverse-backed cloud flows (most recently modified first). Run counts come from the first page of run history, so very busy flows are understated.' $topF -Metric 'Runs' -Group 'top'
            Add-UsageList 'UnusedFlows' "Flows with no runs (last $UsageLookbackDays days, sample)" 'Source: flow runs API. Zero runs can also mean the flow is off or only triggered rarely.' @($idleF | Select-Object Flow, Environment, Owner, Trigger, LastRun, LastModified) -Group 'unused'
            if ($fr.Total -gt $fr.Stats.Count) { Add-Limitation 'Usage' "Flow run history was read for $($fr.Stats.Count) of $($fr.Total) cloud flows (-FlowRunSampleLimit $FlowRunSampleLimit; most recently modified first)." }
            Add-Finding -Id '18.4' -Title 'Most-run flows' -Status Info -Severity 'High' -Source $srcF -Confidence Sample -Value "Sample of $($fr.Stats.Count) of $($fr.Total) cloud flows ($($fr.Errors) call(s) failed). Busiest: $(($topF | Select-Object -First 3 | ForEach-Object { "$($_.Flow)=$($_.Runs)" }) -join ', ')" -Evidence $topF `
                -Recommendation 'For the busiest flows confirm solution-based delivery, a service identity, run-only access, error handling and licensing.'
            Add-Finding -Id '18.5' -Title 'Flows with no runs or mostly failing' -Status $(if ($idleF.Count -gt 0 -or $failing.Count -gt 0) { 'Warning' } else { 'Pass' }) -Severity 'Medium' -Source $srcF -Confidence Sample `
                -Value "No runs in $UsageLookbackDays days: $($idleF.Count); mostly failing (50% or more of 5+ runs): $($failing.Count); sampled $($fr.Stats.Count)" -Evidence @(($idleF + $failing) | Select-Object -Unique | Select-Object Flow, Environment, Owner, Runs, Failed, LastRun, LastModified) `
                -Recommendation $(if ($idleF.Count -gt 0 -or $failing.Count -gt 0) { 'Retire flows nobody triggers and fix or turn off flows that fail repeatedly; both leave connections and credentials active.' } else { '' })
            $script:Kpi['Flows with no runs (sample)'] = $idleF.Count
            [void]$sourceNotes.Add("Flow run sample: $($fr.Stats.Count) of $($fr.Total)")
        }
        elseif ($fr.Total -gt 0) {
            Add-Finding -Id '18.4' -Title 'Flow run history' -Status Info -Source $srcF -Value "No Dataverse-backed cloud flows were available to sample (flows found: $($fr.Total))."
        }
    }
    else {
        Add-Finding -Id '18.4' -Title 'Flow run history' -Status Info -Detail 'Skipped (-FlowRunSampleLimit 0).' -Source 'script'
    }
    $flowsStale = @(Get-OkRows $Inv.Flows | Where-Object { (Get-DaysSince (Get-Prop $_ 'properties.lastModifiedAt' '')) -gt $StaleDays })
    if ($flowsStale.Count -gt 0) {
        Add-Finding -Id '18.5' -Title "Flows not modified for over $StaleDays days (proxy for dormant)" -Status Info -Source 'api.powerplatform.com resourcequery' -Value "$($flowsStale.Count) flow(s); modification date is not a usage measure"
    }

    # ---- App reach (sharing) from the admin apps API
    $ar = Get-AppReach -Inv $Inv -EnvMap $EnvMap
    $srcA = 'api.powerplatform.com powerapps/environments/{id}/apps (sharing counts)'
    if ($ar.Rows.Count -gt 0) {
        $reach = @($ar.Rows | Sort-Object { $_.SharedUsers + 25 * $_.SharedGroups } -Descending | Select-Object -First $TopN | Select-Object App, Environment, Owner, SharedUsers, SharedGroups, PremiumConnectors, CustomConnectors, LastModified)
        Add-UsageList 'TopSharedApps' 'Apps with the widest sharing (reach, not usage)' 'Source: admin apps API (sharedUsersCount, sharedGroupsCount). Sharing shows potential audience; pair with Advisor usage.' $reach -Metric 'SharedUsers' -Group 'top'
        $staleShared = @($ar.Rows | Where-Object { ($_.SharedUsers + $_.SharedGroups) -ge 10 -and (Get-DaysSince $_.LastModified) -gt $StaleDays })
        $appEnvTotal = @(Get-OkRows $Inv.Apps | Group-Object { ([string](Get-Prop $_ 'properties.environmentId' '')).ToLower() }).Count
        $arConf = if ($appEnvTotal -gt $ar.Environments) { 'Sample' } else { 'Configuration' }
        if ($appEnvTotal -gt $ar.Environments) { Add-Limitation 'Usage' "App sharing counts were read for the $($ar.Environments) environments with the most apps, out of $appEnvTotal (-MaxAppSharingEnvironments $MaxAppSharingEnvironments)." }
        Add-Finding -Id '18.2' -Title 'Widely shared apps (reach)' -Status Info -Source $srcA -Confidence $arConf -Value "$($ar.Rows.Count) apps read from $($ar.Environments - $ar.Failed) environment(s). Widest: $(($reach | Select-Object -First 3 | ForEach-Object { "$($_.App)=$($_.SharedUsers)u/$($_.SharedGroups)g" }) -join ', ')" -Evidence $reach `
            -Recommendation 'Treat widely shared apps as high-value: confirm ownership, managed environment, ALM and premium licensing.'
        Add-Finding -Id '18.3' -Title "Widely shared apps not modified for over $StaleDays days" -Status $(if ($staleShared.Count -gt 0) { 'Warning' } else { 'Pass' }) -Source $srcA -Confidence $arConf -Value "$($staleShared.Count) app(s) shared with 10 or more users/groups and not modified in $StaleDays days" `
            -Evidence @($staleShared | Select-Object App, Environment, Owner, SharedUsers, SharedGroups, LastModified) -Recommendation $(if ($staleShared.Count -gt 0) { 'Confirm these are still used (Advisor or PPAC analytics) before leaving broad access in place.' } else { '' })
        [void]$sourceNotes.Add("Admin apps read: $($ar.Rows.Count)")
    }
    elseif ($ar.Environments -gt 0) {
        Add-Finding -Id '18.2' -Title 'Widely shared apps (reach)' -Status Unavailable -Source $srcA -Detail "Admin apps API returned no rows for $($ar.Environments) environment(s) ($($ar.Failed) failed)."
    }

    # ---- summary
    Add-Finding -Id '18.1' -Title 'Usage data sources available' -Status Info -Source 'derived' -Value ($sourceNotes -join '; ') `
        -Detail "Highest-used and unused lists are in the Usage and adoption section of the report and in usage-*.csv. Look-back: $UsageLookbackDays days." `
        -Recommendation 'Complement with PPAC analytics (Power Apps, Power Automate, Copilot Studio) for full per-app usage; the API exposes usage through Advisor, credit consumption and flow runs.'
    $totalUnused = $unusedApps.Count + $unusedSites.Count
    $nm = 'not measured'
    $dormantValue = "Unused apps: $(if ($unusedAppScenario) { $unusedApps.Count } else { $nm }); sites without traffic: $(if ($unusedSiteScenario) { $unusedSites.Count } else { $nm }); flows with no runs (sample): $(if ($script:Kpi.Contains('Flows with no runs (sample)')) { $script:Kpi['Flows with no runs (sample)'] } else { $nm }); agents with no credit use: $(if ($script:Kpi.Contains('Published agents with no credit use')) { $script:Kpi['Published agents with no credit use'] } else { $nm })"
    Add-Finding -Id '18.10' -Title 'Dormant asset summary' -Status $(if ($totalUnused -gt 0) { 'Warning' } else { 'Info' }) -Source 'derived' -Value $dormantValue `
        -Recommendation 'Run a monthly usage review: top 10 and bottom 10 per asset type, owner notification, quarantine, then retirement.'
}

# ------------------------------------------------------------------ deeper best-practice checks
$script:AdminPrincipalIds = @{}

$SecretJson = '(?i)"(api[-_ ]?key|apikey|secret|client[-_]?secret|password|pwd|ocp-apim-subscription-key|x-api-key|authorization|access[-_]?token)"\s*:\s*"(?![@\[])(?:Bearer\s+|Basic\s+)?[A-Za-z0-9\-_\.\/+=]{16,}"'
$SecretYaml = '(?im)^\s*(?:-\s*)?(api[-_ ]?key|apikey|secret|client[-_]?secret|password|pwd|ocp-apim-subscription-key|x-api-key|authorization|access[-_]?token)\s*:\s*["'']?(?!=)(?!Topic\.|Global\.|System\.|Env\.)(?:Bearer\s+|Basic\s+)?[A-Za-z0-9\-_\.\/+=]{16,}'
$MicrosoftHostPattern = '(microsoft|office|dynamics|sharepoint|powerapps|powerplatform|windows\.net|azure|live\.com|graph|bing|msn|skype|teams)'

function Get-DataverseTargets {
    param($EnvMap)
    $all = @($EnvMap.Values | Where-Object { $_.Url })
    $targets = @($all | Sort-Object @{ Expression = { switch ($_.Type) { 'Default' { 0 } 'Production' { 1 } 'Sandbox' { 2 } default { 3 } } } }, Name | Select-Object -First $MaxDataverseEnvironments)
    if ($all.Count -gt $targets.Count) {
        $script:StepConfidence = 'Sample'
        if (-not $script:DvLimitNoted) {
            $script:DvLimitNoted = $true
            Add-Limitation 'Dataverse' "Dataverse checks ran on $($targets.Count) of $($all.Count) environments that have a Dataverse URL (-MaxDataverseEnvironments $MaxDataverseEnvironments). Default, production and sandbox environments are scanned first."
        }
    }
    return $targets
}

function Get-DataverseHeaders { return @{ 'OData-MaxVersion' = '4.0'; 'OData-Version' = '4.0'; Prefer = 'odata.maxpagesize=100' } }

function Get-HostFromUrl {
    param([string]$Url)
    $m = [regex]::Match($Url, 'https?://([^/\s"''\)\]]+)')
    if ($m.Success) { return $m.Groups[1].Value.ToLower() }
    return ''
}

# ---- agents: topic, knowledge, trigger and tool scan (Dataverse bot and botcomponent tables)
function Test-DeepAgents {
    param($EnvMap, $AgentView)
    $targets = @(Get-DataverseTargets $EnvMap)
    if ($targets.Count -eq 0) { return }
    $src = 'Dataverse bot and botcomponent tables (detection rules per Copilot Studio agent inventory documentation)'
    $rows = New-Object System.Collections.ArrayList
    $secretRows = New-Object System.Collections.ArrayList
    $failed = 0; $scanned = 0
    $pageCap = [int][math]::Ceiling($MaxAgentComponentsPerEnvironment / 100.0)
    foreach ($e in $targets) {
        $base = $e.Url.TrimEnd('/')
        $h = Get-DataverseHeaders
        $b = Invoke-Api -Name "Dataverse: bots ($($e.Name))" -Uri "$base/api/data/v9.2/bots?`$select=botid,name,configuration,ismanaged" -Resource $base -Paged -MaxPages 20 -ExtraHeaders $h
        if (-not $b.Ok) { $b = Invoke-Api -Name "Dataverse: bots basic ($($e.Name))" -Uri "$base/api/data/v9.2/bots?`$select=botid,name" -Resource $base -Paged -MaxPages 20 -ExtraHeaders $h }
        if (-not $b.Ok) { $failed++; continue }
        $bots = @($b.Data)
        if ($b.Truncated) { Add-Limitation 'Agent deep scan' "Only the first $($bots.Count) agents were read in $($e.Name) (page cap)." }
        if ($bots.Count -eq 0) { continue }
        $c = Invoke-Api -Name "Dataverse: botcomponents ($($e.Name))" -Uri "$base/api/data/v9.2/botcomponents?`$select=botcomponentid,name,componenttype,data,_parentbotid_value" -Resource $base -Paged -MaxPages $pageCap -ExtraHeaders $h
        if (-not $c.Ok) { $failed++; continue }
        if ($c.Truncated) { Add-Limitation 'Agent deep scan' "Agent components in $($e.Name) were capped at about $MaxAgentComponentsPerEnvironment rows (-MaxAgentComponentsPerEnvironment), so some topics and knowledge sources were not scanned." }
        $scanned++
        $byBot = @{}
        foreach ($comp in @($c.Data)) { $k = ([string](Get-Prop $comp '_parentbotid_value' '')).ToLower(); if (-not $byBot.ContainsKey($k)) { $byBot[$k] = New-Object System.Collections.ArrayList }; [void]$byBot[$k].Add($comp) }
        foreach ($bot in $bots) {
            $id = ([string]$bot.botid).ToLower()
            $cfg = $null
            try { if ($bot.configuration) { $cfg = $bot.configuration | ConvertFrom-Json } } catch { Write-Verbose "Agent configuration for $id is not valid JSON." }
            $comps = if ($byBot.ContainsKey($id)) { @($byBot[$id]) } else { @() }
            $http = 0; $hosts = @{}; $dynamic = $false; $mcp = 0; $skills = 0; $triggers = @(); $sp = @{}; $pub = @{}; $classicPublic = $false; $secretComps = @()
            foreach ($comp in $comps) {
                $data = [string](Get-Prop $comp 'data' '')
                if (-not $data) { continue }
                if ($data -match 'HttpRequestAction') {
                    $http += ([regex]::Matches($data, 'HttpRequestAction')).Count
                    foreach ($m in [regex]::Matches($data, '(?im)^\s*url:\s*(.+)$')) {
                        $u = $m.Groups[1].Value.Trim().Trim('"', "'")
                        if ($u.StartsWith('=')) { $dynamic = $true } else { $hh = Get-HostFromUrl $u; if ($hh) { $hosts[$hh] = 1 } else { $dynamic = $true } }
                    }
                }
                if ($data -match 'InvokeExternalAgentTaskAction') { $mcp += ([regex]::Matches($data, 'InvokeExternalAgentTaskAction')).Count }
                if ($data -match 'InvokeSkillAction') { $skills += ([regex]::Matches($data, 'InvokeSkillAction')).Count }
                if ([string](Get-Prop $comp 'componenttype' '') -eq '17') {
                    $tt = [regex]::Match($data, '(?im)triggerConnectionType:\s*(\S+)')
                    $triggers += $(if ($tt.Success) { $tt.Groups[1].Value } else { 'external trigger' })
                }
                if ($data -match 'KnowledgeSourceConfiguration|publicdatasource|sharePointSearchDataSource|SearchAndSummarizeContent|searchAndSummarizeContent') {
                    if ($data -match 'publicdatasource') { $classicPublic = $true }
                    foreach ($m in [regex]::Matches($data, 'https?://[^\s"''\)\]]+')) {
                        $hh = Get-HostFromUrl $m.Value
                        if (-not $hh -or $hh -match 'schema|aka\.ms|json-schema') { continue }
                        if ($hh -match 'sharepoint\.com$') { $sp[($m.Value -replace '[\?#].*$', '')] = 1 } else { $pub[$hh] = 1 }
                    }
                }
                if ($data -match $SecretYaml -or $data -match $SecretJson) { $secretComps += [string](Get-Prop $comp 'name' 'component') }
            }
            $view = $AgentView | Where-Object { ([string]$_.Id).ToLower() -eq $id } | Select-Object -First 1
            # AI settings are nested under aISettings in the bot configuration JSON; older shapes kept them at the root.
            $ai = Get-Prop $cfg 'aISettings'
            [void]$rows.Add([pscustomobject]@{
                    Agent = [string]$bot.name; Environment = $e.Name; AgentId = $id
                    HttpNodes = $http; HttpHosts = (($hosts.Keys | Sort-Object) -join ', '); DynamicHttpUrl = $dynamic
                    McpActions = $mcp; Skills = $skills; Triggers = (($triggers | Sort-Object -Unique) -join ', '); Autonomous = ($triggers.Count -gt 0)
                    SharePointSites = (($sp.Keys | Sort-Object) -join '; '); PublicSites = (($pub.Keys | Sort-Object) -join ', '); ClassicPublicSource = $classicPublic
                    ModelKnowledge = [bool](Get-Prop $ai 'useModelKnowledge' (Get-Prop $cfg 'useModelKnowledge' $false)); FileAnalysis = [bool](Get-Prop $ai 'isFileAnalysisEnabled' (Get-Prop $cfg 'isFileAnalysisEnabled' $false))
                    ContentModeration = [string](Get-Prop $ai 'contentModeration' (Get-Prop $cfg 'contentModeration' ''))
                    MakerCredentialTools = $(if ($view) { @($view.Ops | Where-Object { $_.Provider -eq 'Maker' }).Count } else { 0 }); Auth = $(if ($view) { $view.Auth } else { '' })
                    SecretComponents = ($secretComps -join '; ')
                })
            if ($secretComps.Count -gt 0) { [void]$secretRows.Add([pscustomobject]@{ Agent = [string]$bot.name; Environment = $e.Name; Components = ($secretComps -join '; ') }) }
        }
    }
    $script:DeepAgentRows = $rows.ToArray()
    if ($rows.Count -eq 0) {
        Add-Finding -Id '9.7' -Title 'Agent deep scan (topics, knowledge, triggers)' -Status Unavailable -Source $src -Detail "No agents could be read from $($targets.Count) environment(s) ($failed failed). Needs a Dataverse role that can read the bot and botcomponent tables."
        return
    }
    $note = "$($rows.Count) agents in $scanned environment(s)" + $(if ($failed -gt 0) { "; $failed environment(s) not readable" } else { '' })
    $http = @($rows | Where-Object { $_.HttpNodes -gt 0 })
    $st = if (@($http | Where-Object DynamicHttpUrl).Count -gt 0) { 'Fail' } elseif ($http.Count -gt 0) { 'Warning' } else { 'Pass' }
    Add-Finding -Id '9.7' -Title 'Agents making HTTP requests from topics' -Status $st -Severity 'High' -Source $src -Value "$($http.Count) agent(s) with HTTP request nodes; $(@($http | Where-Object DynamicHttpUrl).Count) with a dynamic (unreviewable) URL; $note" `
        -Evidence @($http | Select-Object Agent, Environment, HttpNodes, HttpHosts, DynamicHttpUrl, Auth) -Recommendation $(if ($st -ne 'Pass') { 'Allow-list endpoints with connector endpoint filtering or block the HTTP connector; avoid URLs built from user input.' } else { '' })
    Add-Finding -Id '9.7' -Title 'Possible hard-coded secrets in agent topics (heuristic)' -Status $(if ($secretRows.Count -gt 0) { 'Fail' } else { 'Pass' }) -Severity 'Critical' -Source $src -Confidence Heuristic `
        -Value "$($secretRows.Count) agent(s) with a key, token or password-like literal in topic YAML (values are not recorded)" -Evidence $secretRows.ToArray() `
        -Recommendation $(if ($secretRows.Count -gt 0) { 'Move secrets to Azure Key Vault-backed environment variables or managed identity and rotate the exposed values.' } else { '' })
    $know = @($rows | Where-Object { $_.SharePointSites -or $_.PublicSites -or $_.ClassicPublicSource })
    Add-Finding -Id '10.1' -Title 'Knowledge sources referenced by agents' -Status Info -Source $src -Value "$($know.Count) of $($rows.Count) agents reference SharePoint or public websites" `
        -Evidence @($know | Select-Object Agent, Environment, SharePointSites, PublicSites, ClassicPublicSource) -Recommendation 'Review permissions and sensitivity labels on each referenced SharePoint site before agents can search it.'
    # 10.4: without sign-in, retrieval cannot be trimmed to the signed-in user, so the agent exposes whatever its connection can read.
    $unauthKnow = @($rows | Where-Object { $_.Auth -match '^None$|No authentication' -and $_.SharePointSites })
    Add-Finding -Id '10.4' -Title 'Agents grounded on SharePoint without user authentication' -Status $(if ($unauthKnow.Count -gt 0) { 'Fail' } else { 'Pass' }) -Severity 'Critical' -Source $src `
        -Value "$($unauthKnow.Count) agent(s) use SharePoint knowledge but do not require sign-in, so results cannot be trimmed to the user's permissions" `
        -Evidence @($unauthKnow | Select-Object Agent, Environment, Auth, SharePointSites) `
        -Recommendation $(if ($unauthKnow.Count -gt 0) { 'Require authentication on these agents, or remove the SharePoint knowledge source until sign-in is enforced.' } else { '' })
    $pubA = @($rows | Where-Object { $_.PublicSites -or $_.ClassicPublicSource })
    Add-Finding -Id '10.5' -Title 'Agents grounded on public websites' -Status $(if ($pubA.Count -gt 0) { 'Warning' } else { 'Pass' }) -Severity 'High' -Source $src -Value "$($pubA.Count) agent(s) reference public sites or the classic public data source" `
        -Evidence @($pubA | Select-Object Agent, Environment, PublicSites, ClassicPublicSource) -Recommendation $(if ($pubA.Count -gt 0) { 'Limit public grounding to approved domains with endpoint filtering and confirm answers are acceptable for the audience.' } else { '' })
    $mk = @($rows | Where-Object ModelKnowledge)
    Add-Finding -Id '10.8' -Title 'Agents allowed to answer from general model knowledge' -Status $(if ($mk.Count -gt 0) { 'Info' } else { 'Pass' }) -Source $src -Value "$($mk.Count) of $($rows.Count) agents have general AI knowledge enabled" `
        -Evidence @($mk | Select-Object Agent, Environment, Auth) -Recommendation 'For regulated or policy-bound scenarios, restrict answers to approved knowledge and require citations.'
    # 12.1: moderation level is only stored when it differs from the default, so "not set" means the platform default.
    $modLow = @($rows | Where-Object { $_.ContentModeration -match '^(low|minimal)$' })
    $modDist = ($rows | Group-Object { if ($_.ContentModeration) { $_.ContentModeration } else { 'default (not set)' } } | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', '
    Add-Finding -Id '12.1' -Title 'Agents with reduced content moderation' -Status $(if ($modLow.Count -gt 0) { 'Warning' } else { 'Pass' }) -Source $src `
        -Value "$($modLow.Count) of $($rows.Count) agents use a low moderation level. Distribution: $modDist" -Evidence @($modLow | Select-Object Agent, Environment, ContentModeration, Auth, Channels) `
        -Recommendation $(if ($modLow.Count -gt 0) { 'Confirm a reduced moderation level is intended for the audience and use case, especially on agents with open channels.' } else { '' })
    $auto = @($rows | Where-Object Autonomous)
    $autoMaker = @($auto | Where-Object { $_.MakerCredentialTools -gt 0 })
    $st = if ($autoMaker.Count -gt 0) { 'Fail' } elseif ($auto.Count -gt 0) { 'Warning' } else { 'Pass' }
    Add-Finding -Id '11.4' -Title 'Autonomous agents (external triggers)' -Status $st -Severity 'Critical' -Source $src `
        -Value "$($auto.Count) agent(s) run on external triggers; $($autoMaker.Count) of them also use maker-provided credentials" -Evidence @($auto | Select-Object Agent, Environment, Triggers, MakerCredentialTools, Auth) `
        -Recommendation $(if ($st -ne 'Pass') { 'Give autonomous agents a reviewed service identity, least-privilege tools, volume limits and monitoring; avoid maker credentials with broad access.' } else { '' })
    $script:Kpi['Autonomous agents'] = $auto.Count
    $mcp = @($rows | Where-Object { $_.McpActions -gt 0 })
    Add-Finding -Id '11.5' -Title 'Agents invoking MCP or external agent actions' -Status $(if ($mcp.Count -gt 0) { 'Warning' } else { 'Pass' }) -Source $src -Value "$($mcp.Count) agent(s) with MCP / external agent task actions" `
        -Evidence @($mcp | Select-Object Agent, Environment, McpActions, Auth) -Recommendation $(if ($mcp.Count -gt 0) { 'Confirm each MCP server is approved, owned and authenticated; blocking Power Platform connectors by data policy also blocks MCP tools.' } else { '' })
    $sk = @($rows | Where-Object { $_.Skills -gt 0 })
    Add-Finding -Id '11.8' -Title 'Agents invoking Azure Bot Service skills' -Status $(if ($sk.Count -gt 0) { 'Warning' } else { 'Pass' }) -Source $src -Value "$($sk.Count) agent(s)" -Evidence @($sk | Select-Object Agent, Environment, Skills) `
        -Recommendation $(if ($sk.Count -gt 0) { 'Allow-list skills or block the Skills with Copilot Studio connector.' } else { '' })
}

# ---- agents: who may chat (access control policy) and when sign-in is asked for (Dataverse bot table)
function Test-AgentAccessControl {
    param($EnvMap, $AgentView)
    $targets = @(Get-DataverseTargets $EnvMap)
    if ($targets.Count -eq 0) { return }
    $src = 'Dataverse bot table (accesscontrolpolicy, authenticationmode, authenticationtrigger)'
    $policyName = @{ 0 = 'Any'; 1 = 'Agent readers'; 2 = 'Group membership'; 3 = 'Any (multi-tenant)' }
    $modeName = @{ 0 = 'Unspecified'; 1 = 'None'; 2 = 'Integrated'; 3 = 'Custom Entra ID'; 4 = 'Generic OAuth2' }
    $triggerName = @{ 0 = 'As needed'; 1 = 'Always' }
    $label = { param($map, $code) if ($null -ne $code -and $map.ContainsKey([int]$code)) { $map[[int]$code] } else { 'Not reported' } }
    $view = @{}
    foreach ($a in @($AgentView)) { $view[([string]$a.Id).ToLower()] = $a }
    $deep = @{}
    foreach ($d in @($script:DeepAgentRows)) { $deep[([string]$d.AgentId).ToLower()] = $d }
    $rows = New-Object System.Collections.ArrayList
    $failed = 0; $read = 0
    foreach ($e in $targets) {
        $facts = $script:EnvFacts[([string]$e.Id).ToLower()]
        if ($null -ne $facts -and $facts.ContainsKey('DvAccess') -and -not [bool]$facts['DvAccess']) { continue }
        $base = $e.Url.TrimEnd('/')
        $b = Invoke-Api -Name "Dataverse: agent access settings ($($e.Name))" -Uri "$base/api/data/v9.2/bots?`$select=botid,name,accesscontrolpolicy,authenticationmode,authenticationtrigger,publishedon" -Resource $base -Paged -MaxPages 20 -ExtraHeaders (Get-DataverseHeaders)
        if (-not $b.Ok) { $failed++; continue }
        $read++
        foreach ($bot in @($b.Data)) {
            $id = ([string]$bot.botid).ToLower()
            $av = $view[$id]
            $dp = $deep[$id]
            $pol = Get-Prop $bot 'accesscontrolpolicy' $null
            $mode = Get-Prop $bot 'authenticationmode' $null
            $trg = Get-Prop $bot 'authenticationtrigger' $null
            $published = [bool](Get-Prop $bot 'publishedon' $null)
            if (-not $published -and $av -and $av.LastPublished) { $published = $true }
            $makerTools = if ($av) { @($av.Ops | Where-Object { $_.Provider -eq 'Maker' -and $_.UsedAs -ne 'Knowledge' }).Count } else { 0 }
            $spKnowledge = [bool]($dp -and $dp.SharePointSites)
            $multi = ($null -ne $pol -and [int]$pol -eq 3)
            $manual = ($null -ne $mode -and [int]$mode -in @(3, 4))
            $asNeeded = ($manual -and $null -ne $trg -and [int]$trg -eq 0)
            [void]$rows.Add([pscustomobject]@{
                    Agent = [string]$bot.name; Environment = $e.Name; AgentId = $id; Published = $(if ($published) { 'Yes' } else { 'No' })
                    AccessPolicy = (& $label $policyName $pol); Authentication = (& $label $modeName $mode); SignIn = (& $label $triggerName $trg)
                    Channels = $(if ($av) { [string]$av.Channels } else { '' }); MakerCredentialTools = $makerTools; SharePointKnowledge = $(if ($spKnowledge) { 'Yes' } else { 'No' })
                    HasPolicy = ($null -ne $pol); MultiTenant = $multi; ManualAuth = $manual; SignInAsNeeded = $asNeeded
                })
            $script:AgentAccess[$id] = @{ MultiTenant = $multi; SignInAsNeeded = $asNeeded; Published = $published }
        }
    }
    if ($rows.Count -eq 0) {
        if ($read -eq 0 -and $failed -gt 0) {
            Add-Finding -Id '9.1' -Title 'Agent access control and sign-in settings' -Status Unavailable -Severity 'Medium' -Source $src `
                -Detail "The bot table could not be read in $failed environment(s). Needs a Dataverse role that can read agents."
        }
        return
    }
    $note = "$($rows.Count) agents in $read environment(s)" + $(if ($failed -gt 0) { "; $failed environment(s) not readable" } else { '' })

    # Access control policy: Any (multi-tenant) is the policy behind Copilot Studio multitenant mode (preview).
    $withPolicy = @($rows | Where-Object HasPolicy)
    if ($withPolicy.Count -gt 0) {
        $multiRows = @($withPolicy | Where-Object MultiTenant)
        $dist = (($withPolicy | Group-Object AccessPolicy | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ', ')
        $st = if ($multiRows.Count -gt 0) { 'Warning' } else { 'Pass' }
        Add-Finding -Id '9.1' -Title 'Agents reachable from other Microsoft Entra tenants (multitenant access)' -Status $st -Severity 'High' -Source $src `
            -Value "$($multiRows.Count) of $($withPolicy.Count) agent(s) use the access control policy Any (multi-tenant). All agents: $dist; $note" `
            -Evidence @($multiRows | Select-Object Agent, Environment, Published, Authentication, Channels) `
            -Detail 'The access control policy defines which users may chat with an agent. Any (multi-tenant) matches Copilot Studio multitenant mode (preview), where users from other Microsoft Entra tenants can use an agent hosted in this tenant.' `
            -Recommendation $(if ($st -ne 'Pass') { 'Confirm each of these agents is meant to be used from other Microsoft Entra tenants and turn multitenant mode off where it is not. Turning on tenant isolation (PPAC > Security > Identity and access) also blocks multitenant use.' } else { '' })
    }

    # Sign-in trigger: with manual authentication and Require users to sign in off, the agent only asks for sign-in when a topic needs it.
    $manualRows = @($rows | Where-Object { $_.ManualAuth -and $_.SignIn -ne 'Not reported' })
    if ($manualRows.Count -gt 0) {
        $live = @($manualRows | Where-Object { $_.Published -eq 'Yes' })
        $late = @($live | Where-Object SignInAsNeeded)
        $exposed = @($late | Where-Object { $_.MakerCredentialTools -gt 0 -or $_.SharePointKnowledge -eq 'Yes' })
        $st = if ($exposed.Count -gt 0) { 'Warning' } elseif ($late.Count -gt 0) { 'Info' } else { 'Pass' }
        Add-Finding -Id '9.1' -Title 'Agents that do not ask users to sign in up front' -Status $st -Severity 'High' -Source $src `
            -Value "$($late.Count) of $($live.Count) published agent(s) with manual authentication do not ask users to sign in until a topic needs it. Among those, agents that also use maker credentials or SharePoint knowledge: $($exposed.Count); $note" `
            -Evidence @($late | Select-Object Agent, Environment, Authentication, SignIn, Channels, MakerCredentialTools, SharePointKnowledge) `
            -Detail 'With manual authentication and Require users to sign in turned off, an agent does not ask users to sign in until it reaches a topic that requires it. That suits public content but not agents that reach sensitive or restricted information.' `
            -Recommendation $(if ($st -ne 'Pass') { 'Turn on Require users to sign in for agents that reach sensitive or restricted information (Copilot Studio > Settings > Security > Authentication). Leave it off only for agents that are meant to be public.' } else { '' })
    }
}

# ---- flows: definition scan (Dataverse workflows)
function Test-DeepFlows {
    param($EnvMap)
    $targets = @(Get-DataverseTargets $EnvMap)
    if ($targets.Count -eq 0) { return }
    $src = 'Dataverse workflows table (cloud flow definitions)'
    $httpTrig = New-Object System.Collections.ArrayList; $secrets = New-Object System.Collections.ArrayList; $ext = New-Object System.Collections.ArrayList; $susp = New-Object System.Collections.ArrayList
    $scanned = 0; $total = 0; $failed = 0
    $pageCap = [int][math]::Ceiling($MaxFlowDefinitionsPerEnvironment / 50.0)
    foreach ($e in $targets) {
        $base = $e.Url.TrimEnd('/')
        $h = Get-DataverseHeaders; $h['Prefer'] = 'odata.maxpagesize=50'
        $r = Invoke-Api -Name "Dataverse: cloud flow definitions ($($e.Name))" -Uri "$base/api/data/v9.2/workflows?`$select=workflowid,name,statecode,clientdata,modifiedon&`$filter=category eq 5 and type eq 1" -Resource $base -Paged -MaxPages $pageCap -ExtraHeaders $h
        if (-not $r.Ok) { $failed++; continue }
        if ($r.Truncated) { Add-Limitation 'Flow definition scan' "Flow definitions in $($e.Name) were capped at about $MaxFlowDefinitionsPerEnvironment (-MaxFlowDefinitionsPerEnvironment), so some flows were not scanned." }
        $scanned++
        foreach ($f in @($r.Data)) {
            $total++
            $cd = [string](Get-Prop $f 'clientdata' '')
            $name = [string](Get-Prop $f 'name' '')
            if ([string](Get-Prop $f 'statecode' '') -eq '2') { [void]$susp.Add([pscustomobject]@{ Flow = $name; Environment = $e.Name; Modified = [string](Get-Prop $f 'modifiedon' '') }) }
            if (-not $cd) { continue }
            if ($cd -match '"kind"\s*:\s*"Http"') {
                $am = [regex]::Match($cd, '"triggerAuthenticationType"\s*:\s*"(\w+)"')
                $setting = if ($am.Success) { $am.Groups[1].Value } else { '' }
                $who = switch -Regex ($setting) { '^$' { 'Not stated in the definition' } '^(All|Anonymous|Anyone)$' { 'Anyone' } '^Tenant$' { 'Any user in my tenant' } default { $setting } }
                $flowState = switch ([string](Get-Prop $f 'statecode' '')) { '0' { 'Off' } '1' { 'On' } '2' { 'Suspended' } default { '' } }
                [void]$httpTrig.Add([pscustomobject]@{ Flow = $name; Environment = $e.Name; State = $flowState; WhoCanTrigger = $who; Setting = $setting })
            }
            if ($cd -match $SecretJson) { [void]$secrets.Add([pscustomobject]@{ Flow = $name; Environment = $e.Name }) }
            $hosts = @{}
            foreach ($m in [regex]::Matches($cd, '"uri"\s*:\s*"(https?://[^"/]+)')) {
                $hh = Get-HostFromUrl $m.Groups[1].Value
                if ($hh -and $hh -notmatch $MicrosoftHostPattern) { $hosts[$hh] = 1 }
            }
            if ($hosts.Count -gt 0) { [void]$ext.Add([pscustomobject]@{ Flow = $name; Environment = $e.Name; ExternalHosts = (($hosts.Keys | Sort-Object) -join ', ') }) }
        }
    }
    if ($scanned -eq 0) {
        Add-Finding -Id '8.2' -Title 'Flow definition scan' -Status Unavailable -Source $src -Detail "Workflows could not be read in any of $($targets.Count) environment(s). Needs a Dataverse role that can read the workflow table."
        return
    }
    $note = "$total flow(s) scanned in $scanned environment(s) (cap $MaxFlowDefinitionsPerEnvironment per environment)" + $(if ($failed -gt 0) { "; $failed not readable" } else { '' })
    $open = @($httpTrig | Where-Object { $_.Setting -match '^(All|Anonymous|Anyone)$' })
    $restricted = @($httpTrig | Where-Object { $_.Setting -match '^(Tenant|Specific)$' })
    $unconfirmed = @($httpTrig | Where-Object { $_.Setting -notmatch '^(All|Anonymous|Anyone|Tenant|Specific)$' })
    $st = if ($open.Count -gt 0) { 'Fail' } elseif ($unconfirmed.Count -gt 0) { 'Warning' } else { 'Pass' }
    $httpSorted = @($httpTrig | Sort-Object @{ Expression = { switch -Regex ($_.Setting) { '^(All|Anonymous|Anyone)$' { 0 } '^(Tenant|Specific)$' { 2 } default { 1 } } } }, Environment, Flow)
    Add-Finding -Id '8.2' -Title 'Flows started by an HTTP request trigger' -Status $st -Severity 'Critical' -Source $src `
        -Value "$($httpTrig.Count) flow(s) with an HTTP request trigger: $($open.Count) set to Anyone, $($unconfirmed.Count) with no recognized setting (verify in the designer), $($restricted.Count) restricted to signed-in tenant users; $note" -Evidence $httpSorted `
        -Detail 'The setting Who can trigger the flow? is stored as triggerAuthenticationType in the flow definition (All is Anyone, Tenant is Any user in my tenant). Microsoft documents Anyone as the legacy setting: anyone who has the URL can call the flow. When the setting is missing from a definition this script cannot confirm what the designer shows, so those flows are listed to verify rather than counted as open or restricted. Flows that are Off cannot be triggered; the State column shows which flows are on.' `
        -Recommendation $(if ($st -ne 'Pass') { 'Set Who can trigger the flow? to Any user in my tenant or Specific users in my tenant on each flow, validate the input and treat the URL as a secret; review flows set to Anyone first.' } else { '' })
    Add-Finding -Id '8.3' -Title 'Possible hard-coded secrets in flow definitions (heuristic)' -Status $(if ($secrets.Count -gt 0) { 'Fail' } else { 'Pass' }) -Severity 'Critical' -Source $src -Confidence Heuristic -Value "$($secrets.Count) flow(s); values are not recorded" -Evidence $secrets.ToArray() `
        -Recommendation $(if ($secrets.Count -gt 0) { 'Move secrets to Key Vault-backed environment variables or managed identity and rotate exposed values.' } else { '' })
    Add-Finding -Id '8.6' -Title 'Flows calling external (non-Microsoft) hosts' -Status $(if ($ext.Count -gt 0) { 'Warning' } else { 'Pass' }) -Severity 'High' -Source $src -Confidence Heuristic -Value "$($ext.Count) flow(s) with a URI to a non-Microsoft host" -Evidence @($ext | Select-Object -First $EvidenceRowLimit) `
        -Recommendation $(if ($ext.Count -gt 0) { 'Confirm each destination is approved and covered by connector endpoint filtering.' } else { '' })
    Add-Finding -Id '8.8' -Title 'Suspended flows' -Status $(if ($susp.Count -gt 0) { 'Warning' } else { 'Pass' }) -Severity 'Medium' -Source $src -Value "$($susp.Count) suspended flow(s)" -Evidence $susp.ToArray() `
        -Recommendation $(if ($susp.Count -gt 0) { 'Fix or retire suspended flows; Power Automate suspends flows after repeated failures.' } else { '' })
}

# ---- production least privilege
function Test-DataverseAccess {
    param($EnvMap)
    $targets = @(Get-DataverseTargets $EnvMap)
    if ($targets.Count -eq 0) { return }
    $src = 'Dataverse security roles and users per environment'
    $makers = New-Object System.Collections.ArrayList; $guests = New-Object System.Collections.ArrayList; $appAdmins = New-Object System.Collections.ArrayList
    $viewers = New-Object System.Collections.ArrayList
    $ok = 0; $viewersRead = 0; $viewersNoTeams = 0
    $tvUsers = 'systemuserroles_association($select=fullname,domainname,isdisabled,accessmode,applicationid)'
    $tvTeams = 'teamroles_association($select=name,teamtype,azureactivedirectoryobjectid)'
    foreach ($e in $targets) {
        $base = $e.Url.TrimEnd('/'); $h = Get-DataverseHeaders
        $uri = "$base/api/data/v9.2/roles?`$select=name&`$filter=name eq 'Environment Maker' or name eq 'System Customizer' or name eq 'System Administrator'&`$expand=systemuserroles_association(`$select=fullname,domainname,isdisabled,accessmode,applicationid)"
        $r = Invoke-Api -Name "Dataverse: privileged role members ($($e.Name))" -Uri $uri -Resource $base -ExtraHeaders $h
        if ($r.Ok) {
            $ok++
            foreach ($role in @(Get-Prop $r.Data 'value' @())) {
                foreach ($u in @(Get-Prop $role 'systemuserroles_association' @())) {
                    if ($u.isdisabled) { continue }
                    $isApp = ($u.applicationid -or $u.accessmode -eq 4)
                    if ($role.name -eq 'System Administrator' -and $isApp) { [void]$appAdmins.Add([pscustomobject]@{ Environment = $e.Name; Type = $e.Type; ApplicationUser = $u.fullname; ApplicationId = [string]$u.applicationid }) }
                    elseif ($role.name -in @('Environment Maker', 'System Customizer') -and -not $isApp) { [void]$makers.Add([pscustomobject]@{ Environment = $e.Name; Type = $e.Type; Role = $role.name; User = $u.fullname; Upn = $u.domainname }) }
                }
            }
        }
        $g = Invoke-Api -Name "Dataverse: guest users ($($e.Name))" -Uri ("$base/api/data/v9.2/systemusers?`$select=fullname,domainname&`$filter=isdisabled eq false and contains(domainname,'" + [uri]::EscapeDataString('#EXT#') + "')&`$top=200") -Resource $base -ExtraHeaders $h
        if ($g.Ok) { foreach ($u in @(Get-Prop $g.Data 'value' @())) { [void]$guests.Add([pscustomobject]@{ Environment = $e.Name; Type = $e.Type; Guest = $u.fullname; Upn = $u.domainname }) } }
        # Users and teams that hold the Bot Transcript Viewer role. Teams are expanded because role assignment through group teams is the recommended practice.
        $tv = Invoke-Api -Name "Dataverse: transcript viewers ($($e.Name))" -Uri "$base/api/data/v9.2/roles?`$select=name&`$filter=name eq 'Bot Transcript Viewer'&`$expand=$tvUsers,$tvTeams" -Resource $base -ExtraHeaders $h
        $teamsRead = $true
        if (-not $tv.Ok -and $tv.Status -eq 400) {
            $teamsRead = $false
            $tv = Invoke-Api -Name "Dataverse: transcript viewers, users only ($($e.Name))" -Uri "$base/api/data/v9.2/roles?`$select=name&`$filter=name eq 'Bot Transcript Viewer'&`$expand=$tvUsers" -Resource $base -ExtraHeaders $h
        }
        if ($tv.Ok) {
            $viewersRead++
            if (-not $teamsRead) { $viewersNoTeams++ }
            $seen = @{}
            foreach ($role in @(Get-Prop $tv.Data 'value' @())) {
                foreach ($u in @(Get-Prop $role 'systemuserroles_association' @())) {
                    if ($null -eq $u -or $u.isdisabled) { continue }
                    $key = [string]$u.domainname; if (-not $key) { $key = [string]$u.fullname }
                    if ($seen.ContainsKey("U|$key")) { continue }
                    $seen["U|$key"] = 1
                    $holder = if ($u.applicationid -or $u.accessmode -eq 4) { 'Application user' } else { 'User' }
                    [void]$viewers.Add([pscustomobject]@{ Environment = $e.Name; Type = $e.Type; Holder = $holder; Name = [string]$u.fullname; Account = [string]$u.domainname })
                }
                foreach ($tm in @(Get-Prop $role 'teamroles_association' @())) {
                    if ($null -eq $tm) { continue }
                    $key = [string]$tm.name
                    if ($seen.ContainsKey("T|$key")) { continue }
                    $seen["T|$key"] = 1
                    $kind = switch ([string]$tm.teamtype) { '0' { 'Owner team' } '1' { 'Access team' } '2' { 'Entra security group team' } '3' { 'Entra Microsoft 365 group team' } default { 'Team' } }
                    [void]$viewers.Add([pscustomobject]@{ Environment = $e.Name; Type = $e.Type; Holder = $kind; Name = $key; Account = [string]$tm.azureactivedirectoryobjectid })
                }
            }
        }
    }
    if ($viewersRead -gt 0) {
        $viewerUsers = @($viewers | Where-Object { $_.Holder -in @('User', 'Application user') })
        $viewerTeams = @($viewers | Where-Object { $_.Holder -notin @('User', 'Application user') })
        $teamNote = if ($viewersNoTeams -gt 0) { " Team assignments could not be read in $viewersNoTeams environment(s), so only direct user assignments are listed there." } else { '' }
        Add-Finding -Id '6.5' -AlsoCovers @('9.8') -Title 'Who can read conversation transcripts (Bot Transcript Viewer role)' -Status $(if ($viewers.Count -gt 0) { 'Info' } else { 'Pass' }) -Severity 'Medium' -Source $src `
            -Value "$($viewerUsers.Count) user(s) and $($viewerTeams.Count) team(s) hold the Bot Transcript Viewer role in $viewersRead environment(s) read" `
            -Evidence @($viewers | Select-Object -First $EvidenceRowLimit) `
            -Detail ('The role lets its holders read conversation transcripts. System Administrators can also read every transcript (see the System Administrator count in 6.1).' + $teamNote) `
            -Recommendation $(if ($viewers.Count -gt 0) { 'Recommended: keep this role to the people who review conversations, assign it through a group team, and review the membership regularly. Transcripts can hold personal data and anything users typed.' } else { '' })
    }
    if ($ok -eq 0) { Add-Finding -Id '3.3' -Title 'Production least privilege' -Status Unavailable -Source $src -Detail 'Role membership could not be read in any target environment.'; return }
    $prodMakers = @($makers | Where-Object Type -eq 'Production')
    Add-Finding -Id '3.3' -Title 'Makers and customizers holding build roles in production' -Status $(if ($prodMakers.Count -gt 0) { 'Warning' } else { 'Pass' }) -Severity 'High' -Source $src `
        -Value "$($prodMakers.Count) user/role assignment(s) of Environment Maker or System Customizer in production environments (all targeted environments: $($makers.Count))" -Evidence @($prodMakers | Select-Object -First $EvidenceRowLimit) `
        -Recommendation $(if ($prodMakers.Count -gt 0) { 'Remove build roles from production; makers should work in development environments and deploy through pipelines.' } else { '' })
    $prodGuests = @($guests | Where-Object { $_.Type -in @('Production', 'Default', 'Sandbox') })
    Add-Finding -Id '5.7' -Title 'Guest users present in Dataverse environments' -Status $(if ($prodGuests.Count -gt 0) { 'Warning' } else { 'Pass' }) -Severity 'High' -Source $src `
        -Value "$($guests.Count) enabled guest user(s) in targeted environments ($($prodGuests.Count) in production, sandbox or default; list capped at 200 per environment)" -Evidence @($guests | Select-Object -First $EvidenceRowLimit) `
        -Recommendation $(if ($guests.Count -gt 0) { 'Review guest access with the business owner and restrict guest access on the environment.' } else { '' })
    Add-Finding -Id '5.4' -Title 'Application users holding System Administrator' -Status $(if ($appAdmins.Count -gt 0) { 'Warning' } else { 'Pass' }) -Severity 'Critical' -Source $src `
        -Value "$($appAdmins.Count) application user(s) with System Administrator" -Evidence $appAdmins.ToArray() `
        -Recommendation $(if ($appAdmins.Count -gt 0) { 'Replace with a least-privilege custom role; check each app registration for owners and secret or certificate expiry.' } else { '' })
}

# ---- Copilot credit allocation and overage controls per environment
function Test-CreditControls {
    param($EnvMap)
    $allDv = @($EnvMap.Values | Where-Object { $_.DataverseId })
    $targets = @($allDv | Select-Object -First $MaxEntitlementEnvironments)
    if ($targets.Count -eq 0) { return }
    if ($allDv.Count -gt $targets.Count) {
        Add-Limitation 'Copilot credits' "Credit entitlements were read for $($targets.Count) of $($allDv.Count) Dataverse environments (-MaxEntitlementEnvironments $MaxEntitlementEnvironments)."
        $script:StepConfidence = 'Sample'
    }
    $src = 'api.powerplatform.com licensing/environments/{id}/entitlements (MCSMessages = Copilot credits)'
    $rows = New-Object System.Collections.ArrayList; $failed = 0
    foreach ($e in $targets) {
        $r = Invoke-Api -Name "Licensing: environment entitlements ($($e.Name))" -Uri "https://$PowerPlatformApiHost/licensing/environments/$($e.Id)/entitlements?api-version=$ApiVersion" -Resource "https://$PowerPlatformApiHost"
        if (-not $r.Ok) { $failed++; continue }
        $list = if ($r.Data -is [array]) { @($r.Data) } else { @(Get-Prop $r.Data 'value' @($r.Data)) }
        $m = @($list | Where-Object { [string](Get-Prop $_ 'entitlementId' '') -eq 'MCSMessages' } | Select-Object -First 1)
        if ($m.Count -eq 0) { continue }
        $cap = Get-Prop $m[0] 'entitlement.capacity'
        $rules = @(Get-Prop $cap 'enforcementRules' @())
        $tp = @($rules | Where-Object { [string]$_.ruleType -eq 'TenantPool' -and [bool]$_.enabled }).Count -gt 0
        $pg = (@($rules | Where-Object { [string]$_.ruleType -eq 'PayGo' -and [bool]$_.enabled }).Count -gt 0) -or ([double](Get-Prop $m[0] 'entitlement.payGo.consumed.value' 0) -gt 0)
        Add-EnvFact $e.Id 'CreditPool' $tp
        Add-EnvFact $e.Id 'CreditAllocated' ([double](Get-Prop $cap 'allocated.value' 0))
        [void]$rows.Add([pscustomobject]@{
                Environment = $e.Name; Type = $e.Type; Allocated = [double](Get-Prop $cap 'allocated.value' 0); Consumed = [double](Get-Prop $cap 'consumed.value' 0)
                DrawsFromTenantPool = $tp; PayAsYouGo = $pg; Status = [string](Get-Prop $cap 'status' ''); Rules = (($rules | ForEach-Object { "$($_.ruleType)=$($_.enabled)" }) -join '; ')
            })
    }
    if ($rows.Count -eq 0) {
        Add-Finding -Id '15.2' -Title 'Copilot credit controls per environment' -Status Unavailable -Source $src -Detail "No MCSMessages entitlement returned ($failed call(s) failed). The environment entitlements endpoint may be unavailable for this tenant or role."
        return
    }
    $pool = @($rows | Where-Object DrawsFromTenantPool)
    $explore = @($rows | Where-Object { $_.Type -in @('Developer', 'Trial', 'Sandbox') -and $_.Consumed -gt 0 })
    $over = @($rows | Where-Object { $_.Status -match 'Overage' })
    $pg = @($rows | Where-Object PayAsYouGo)
    $unbounded = @($rows | Where-Object { $_.DrawsFromTenantPool -and $_.Allocated -eq 0 -and $_.Type -in @('Developer', 'Trial', 'Sandbox', 'Default') })
    $st = if ($over.Count -gt 0 -or $unbounded.Count -gt 0) { 'Warning' } else { 'Pass' }
    Add-Finding -Id '15.2' -Title 'Copilot credit boundaries by environment' -Status $st -Severity 'High' -Source $src `
        -Value "$($rows.Count) environments with a credit entitlement: drawing from tenant pool $($pool.Count); pay-as-you-go $($pg.Count); in overage $($over.Count); non-production drawing from the pool with no allocation $($unbounded.Count)" -Evidence @($rows | Sort-Object Consumed -Descending | Select-Object -First $EvidenceRowLimit) `
        -Recommendation $(if ($st -ne 'Pass') { 'Allocate defined credits to exploration and test environments and turn off tenant-pool draw; use agent-level limits where a hard stop is needed.' } else { '' })
    Add-Finding -Id '15.2' -Title 'Exploration and test environments consuming credits' -Status $(if ($explore.Count -gt 0) { 'Info' } else { 'Pass' }) -Source $src -Value "$($explore.Count) developer, trial or sandbox environment(s) have consumed credits" -Evidence @($explore | Select-Object Environment, Type, Allocated, Consumed, DrawsFromTenantPool, PayAsYouGo)
    $script:Kpi['Environments drawing on the credit tenant pool'] = $pool.Count
}

# ---- shadow environments: who created environments recently
function Test-ShadowEnvironments {
    param($EnvMap)
    $src = 'api.powerplatform.com environmentmanagement (createdBy, state, adminMode)'
    $envs = @($EnvMap.Values | Where-Object { $_.InMgmtApi })
    if ($envs.Count -eq 0) { return }
    $recent = @($envs | Where-Object { $null -ne (Get-DaysSince $_.CreatedAt) -and (Get-DaysSince $_.CreatedAt) -le 90 -and $_.Type -notin @('Default') })
    $haveAdmins = ($script:AdminPrincipalIds.Count -gt 0)
    $byUser = @($recent | Where-Object { $_.CreatedByType -match 'User' -and $_.CreatedById })
    $nonAdmin = if ($haveAdmins) { @($byUser | Where-Object { -not $script:AdminPrincipalIds.ContainsKey($_.CreatedById) }) } else { @() }
    $nonDev = @($byUser | Where-Object { $_.Type -notin @('Developer') })
    $subject = @(if ($haveAdmins) { $nonAdmin } else { $nonDev })
    $st = if ($subject.Count -gt 0) { 'Warning' } else { 'Pass' }
    $basis = if ($haveAdmins) { 'created by a user who does not currently hold an active Global, Power Platform or Dynamics 365 Administrator assignment (an admin who is only PIM-eligible and has not activated the role is listed too)' } else { 'created by a user (admin roles not read; run without -SkipEntra to filter admins)' }
    Add-Finding -Id '2.4' -Title 'Environments created by non-admins in the last 90 days' -Status $st -Severity 'High' -Source $src `
        -Value "$($subject.Count) environment(s) $basis; $($recent.Count) environment(s) created in the last 90 days in total" `
        -Evidence @($subject | Select-Object Name, Type, CreatedAt, CreatedById, IsManaged | Select-Object -First $EvidenceRowLimit) `
        -Recommendation $(if ($st -ne 'Pass') { 'Restrict environment creation to admins and route new environments through your request process; investigate how these were created.' } else { '' })
    $teams = @($envs | Where-Object Type -eq 'Teams')
    $adm = @($envs | Where-Object { $_.AdminMode -match '^(Enabled|true)$' })
    Add-Finding -Id '3.9' -Title 'Teams environments and environments in admin mode' -Status $(if ($adm.Count -gt 0) { 'Warning' } else { 'Info' }) -Source $src -Value "Teams environments: $($teams.Count); admin mode enabled: $($adm.Count)" `
        -Evidence @(($teams + $adm) | Select-Object -Unique | Select-Object Name, Type, State, AdminMode) -Recommendation 'Review Dataverse for Teams environments for upgrade or retirement, and confirm why any environment is left in admin mode.'
}

# ------------------------------------------------------------------ report
# ------------------------------------------------------------------ accepted risks (exceptions file)
# A customer can accept a risk on purpose (framework item 1.5). Each accepted risk needs a reason, and should have an owner and an
# expiry date. A finding that is a Fail or Warning and matches an unexpired row becomes Accepted: it leaves the score, Fix these first
# and the roadmap, and stays visible in its own report section. Rows match on Id and Title because the finding Key is not stable between runs.
function ConvertTo-ExceptionDate {
    param($Value, [string]$Column, $Problems)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.Date }
    $t = ([string]$Value).Trim()
    if (-not $t) { return $null }
    $fmt = $null
    if ($t -match '^(\d{4})-(\d{1,2})-(\d{1,2})(?:[T ].*)?$') { $t = "$($Matches[1])-$($Matches[2])-$($Matches[3])"; $fmt = 'yyyy-M-d' }
    elseif ($t -match '^\d{1,2}/\d{1,2}/\d{4}$') { $fmt = 'M/d/yyyy' }
    $d = [datetime]::MinValue
    if ($fmt -and [datetime]::TryParseExact($t, $fmt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$d)) { return $d.Date }
    [void]$Problems.Add("$Column '$t' is not a date; use yyyy-MM-dd")
    return $null
}

function Format-ExceptionDate {
    param($Date)
    if ($null -eq $Date) { return '' }
    return $Date.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Test-ExceptionTitle {
    param([string]$Title, [string]$Pattern)
    if (-not $Pattern) { return $true }
    if ($Pattern -match '[*?]') { return ($Title -like $Pattern) }
    return ($Title -eq $Pattern)
}

# Reads the exceptions file (CSV, or JSON when the extension is .json) and validates each row. Nothing is applied here.
function Read-ExceptionFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "The exceptions file was not found: $Path" }
    $raw = New-Object System.Collections.ArrayList
    try {
        if ([System.IO.Path]::GetExtension($Path).ToLowerInvariant() -eq '.json') {
            $parsed = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($x in $parsed) { if ($null -ne $x) { [void]$raw.Add($x) } }
        }
        else { foreach ($x in @(Import-Csv -LiteralPath $Path -Encoding UTF8)) { [void]$raw.Add($x) } }
    }
    catch { throw "The exceptions file could not be read ($Path): $($_.Exception.Message)" }
    $rows = New-Object System.Collections.ArrayList
    $n = 0
    foreach ($r in $raw) {
        if (-not (@($r.PSObject.Properties | Where-Object { ([string]$_.Value).Trim() -ne '' }).Count)) { continue }
        $n++
        $problems = New-Object System.Collections.ArrayList
        $id = ([string](Get-Prop $r 'Id' '')).Trim()
        $reason = ([string](Get-Prop $r 'Reason' '')).Trim()
        if ($id -notmatch '^\d+\.\d+$') { [void]$problems.Add("Id '$id' is not a check ID such as 9.1") }
        if (-not $reason) { [void]$problems.Add('Reason is required') }
        [void]$rows.Add([pscustomobject]@{
                Row = $n; Id = $id; Title = ([string](Get-Prop $r 'Title' '')).Trim(); Reason = $reason
                Owner = ([string](Get-Prop $r 'Owner' '')).Trim(); ApprovedBy = ([string](Get-Prop $r 'ApprovedBy' '')).Trim()
                Approved = (ConvertTo-ExceptionDate (Get-Prop $r 'Approved' $null) 'Approved' $problems)
                Reviewed = (ConvertTo-ExceptionDate (Get-Prop $r 'Reviewed' $null) 'Reviewed' $problems)
                Expires = (ConvertTo-ExceptionDate (Get-Prop $r 'Expires' $null) 'Expires' $problems)
                Problems = @($problems); State = ''; Notes = @(); Applied = 0; ReviewDue = $false; DaysToExpiry = $null
                Findings = ''; Was = ''; Severity = ''
            })
    }
    return $rows.ToArray()
}

# Matches each row to this run's findings and marks the open ones (Fail or Warning) as Accepted. Expired and invalid rows are never applied.
function Resolve-AcceptedRisk {
    param($Rows)
    $today = (Get-Date).Date
    foreach ($ex in @($Rows)) {
        if (@($ex.Problems).Count -gt 0) { $ex.State = 'Invalid'; $ex.Notes = @($ex.Problems); continue }
        $notes = New-Object System.Collections.ArrayList
        $found = @($script:Findings | Where-Object { $_.Id -eq $ex.Id -and (Test-ExceptionTitle $_.Title $ex.Title) })
        $open = @($found | Where-Object { $_.Status -in @('Fail', 'Warning') })
        $expired = ($null -ne $ex.Expires -and $ex.Expires -lt $today)
        if ($null -ne $ex.Expires) { $ex.DaysToExpiry = [int]($ex.Expires - $today).TotalDays }
        $ref = if ($null -ne $ex.Reviewed) { $ex.Reviewed } else { $ex.Approved }
        if ($null -eq $ref) { [void]$notes.Add('No approval or review date') }
        elseif (($today - $ref).TotalDays -gt $ExceptionReviewDays) { $ex.ReviewDue = $true; [void]$notes.Add("Review due: last approved or reviewed on $(Format-ExceptionDate $ref)") }
        if (-not $ex.Owner) { [void]$notes.Add('No owner') }
        if ($null -eq $ex.Expires) { [void]$notes.Add('No expiry date (permanent)') }
        $ex.Findings = (@($found | ForEach-Object { "$($_.Id) $($_.Title)" }) -join ' | ')
        $ex.Was = (@($open | ForEach-Object { $_.Status } | Select-Object -Unique) -join ', ')
        $ex.Severity = (@($open | ForEach-Object { $_.Severity } | Select-Object -Unique) -join ', ')
        if ($expired) {
            $ex.State = 'Expired'
            [void]$notes.Insert(0, "Expired on $(Format-ExceptionDate $ex.Expires)" + $(if ($open.Count -gt 0) { '; the finding is open again' } else { '' }))
        }
        elseif ($found.Count -eq 0) {
            $ex.State = 'No match'
            [void]$notes.Insert(0, 'No finding in this run has this Id and title (fixed, not run or mistyped)')
        }
        elseif ($open.Count -eq 0) {
            $ex.State = 'Nothing to accept'
            $first = $found | Select-Object -First 1
            [void]$notes.Insert(0, $(if ($first.Status -eq 'Accepted') { 'Already covered by an earlier row' } else { "The matching finding is $($first.Status), so there is no open gap to accept" }))
        }
        else {
            $ex.State = 'Active'
            if ($null -ne $ex.DaysToExpiry -and $ex.DaysToExpiry -le $ExceptionExpiringDays) { $ex.State = 'Expiring soon'; [void]$notes.Insert(0, "Expires in $($ex.DaysToExpiry) day(s)") }
            foreach ($f in $open) {
                $f.AcceptedFrom = $f.Status
                $f.Status = 'Accepted'
                $f.Acceptance = [pscustomobject]@{
                    Reason = $ex.Reason; Owner = $ex.Owner; ApprovedBy = $ex.ApprovedBy; Approved = (Format-ExceptionDate $ex.Approved)
                    Reviewed = (Format-ExceptionDate $ex.Reviewed); Expires = (Format-ExceptionDate $ex.Expires); Notes = ($notes -join '; ')
                }
                $ex.Applied++
            }
        }
        $ex.Notes = @($notes)
    }
}

function Add-ExceptionFinding {
    param($Rows)
    $all = @($Rows)
    $active = @($all | Where-Object { $_.State -in @('Active', 'Expiring soon') })
    $soon = @($all | Where-Object { $_.State -eq 'Expiring soon' })
    $expired = @($all | Where-Object { $_.State -eq 'Expired' })
    $invalid = @($all | Where-Object { $_.State -eq 'Invalid' })
    $noMatch = @($all | Where-Object { $_.State -in @('No match', 'Nothing to accept') })
    $noExpiry = @($active | Where-Object { $null -eq $_.Expires })
    $noOwner = @($active | Where-Object { -not $_.Owner })
    $due = @($active | Where-Object { $_.ReviewDue })
    $accepted = 0
    foreach ($a in $all) { $accepted += [int]$a.Applied }
    $problems = $expired.Count + $invalid.Count + $noExpiry.Count + $noOwner.Count + $due.Count
    $st = if ($all.Count -eq 0) { 'Info' } elseif ($problems -gt 0) { 'Warning' } else { 'Pass' }
    $bits = New-Object System.Collections.ArrayList
    [void]$bits.Add("$($all.Count) exception row(s): $($active.Count) active, covering $accepted finding(s)")
    if ($soon.Count -gt 0) { [void]$bits.Add("$($soon.Count) expire within $ExceptionExpiringDays days") }
    if ($expired.Count -gt 0) { [void]$bits.Add("$($expired.Count) expired") }
    if ($invalid.Count -gt 0) { [void]$bits.Add("$($invalid.Count) invalid and not applied") }
    if ($noMatch.Count -gt 0) { [void]$bits.Add("$($noMatch.Count) matched no open finding") }
    if ($noExpiry.Count -gt 0) { [void]$bits.Add("$($noExpiry.Count) with no expiry date") }
    if ($noOwner.Count -gt 0) { [void]$bits.Add("$($noOwner.Count) with no owner") }
    if ($due.Count -gt 0) { [void]$bits.Add("$($due.Count) due for review (over $ExceptionReviewDays days)") }
    $evidence = @($all | Where-Object { $_.State -ne 'Active' -or @($_.Notes).Count -gt 0 } | ForEach-Object {
            [pscustomobject]@{ Row = $_.Row; Id = $_.Id; Title = $_.Title; State = $_.State; Owner = $_.Owner; Expires = (Format-ExceptionDate $_.Expires); Notes = (@($_.Notes) -join '; ') }
        })
    Add-Finding -Id '1.5' -Title 'Exception register (accepted risks)' -Status $st -Source ('Exceptions file: ' + [System.IO.Path]::GetFileName($ExceptionsPath)) `
        -Value ($bits -join '; ') -Evidence $evidence `
        -Detail 'The script reads only this file. It cannot see exceptions granted elsewhere, for example data policy exemptions in the Power Platform admin center, so compare them with the file. Accepted findings are not scored; each one stays listed under Accepted risks until it expires.' `
        -Recommendation $(if ($st -eq 'Warning') { 'Renew or remove expired exceptions, give every exception an owner and an expiry date, and review each one at least every quarter.' } else { '' })
}

function Format-Html { param($s) return [System.Net.WebUtility]::HtmlEncode([string]$s) }

function Save-Evidence {
    param([string]$Dir)
    foreach ($f in $script:Findings) {
        if ($f.EvidenceCount -gt 0) {
            $slug = ((Protect-Text $f.Title) -replace '[^A-Za-z0-9]+', '-').Trim('-')
            if ($slug.Length -gt 50) { $slug = $slug.Substring(0, 50) }
            $name = "$($f.Key)-$($f.Id)-$slug.csv"
            try {
                $flat = $f.Evidence | ForEach-Object {
                    $o = [ordered]@{}
                    foreach ($p in $_.PSObject.Properties) { $o[$p.Name] = if ($p.Value -is [System.Collections.IEnumerable] -and $p.Value -isnot [string]) { (@($p.Value) -join '; ') } else { $p.Value } }
                    [pscustomobject]$o
                }
                Export-SafeCsv -Rows @($flat) -Path (Join-Path $Dir $name)
                $f.EvidenceFile = "evidence/$name"
            }
            catch { Add-Limitation 'Evidence files' "Could not write evidence file $name for finding $($f.Key): $($_.Exception.Message)" }
        }
    }
}

# ------------------------------------------------------------------ report model: scoring, priorities, roadmap
function Get-StatusCounts {
    param($Findings)
    $c = [ordered]@{ Fail = 0; Warning = 0; Pass = 0; Info = 0; Unavailable = 0; Accepted = 0 }
    foreach ($f in @($Findings)) { $c[[string]$f.Status] = 1 + [int]$c[[string]$f.Status] }
    return $c
}

# Framework scoring: Pass = 2, Warning = 1, Fail = 0, Info and Unavailable excluded; score = points / (2 x scored checks).
function Get-MaturityScore {
    param($Findings)
    $items = @($Findings)
    $p = @($items | Where-Object Status -eq 'Pass').Count
    $w = @($items | Where-Object Status -eq 'Warning').Count
    $x = @($items | Where-Object Status -eq 'Fail').Count
    $den = $p + $w + $x
    if ($den -eq 0) { return $null }
    return [int][math]::Round(100 * ($p + 0.5 * $w) / $den, 0)
}

# Bands from the framework: below 40 At risk, 40-69 Developing, 70-89 Established, 90 and above Leading.
# A result cannot be rated above Developing while it still has a Critical gap.
function Get-MaturityBand {
    param($Score, [int]$CriticalGaps = 0)
    if ($null -eq $Score) { return [pscustomobject]@{ Name = 'Not rated'; Key = 'none'; Capped = $false } }
    $name = if ($Score -ge 90) { 'Leading' } elseif ($Score -ge 70) { 'Established' } elseif ($Score -ge 40) { 'Developing' } else { 'At risk' }
    $capped = $false
    if ($CriticalGaps -gt 0 -and ($name -eq 'Leading' -or $name -eq 'Established')) { $name = 'Developing'; $capped = $true }
    return [pscustomobject]@{ Name = $name; Key = ($name -replace '\s', '').ToLower(); Capped = $capped }
}

function Get-AreaStats {
    $areas = foreach ($t in 1..18) {
        $fs = @($script:Findings | Where-Object { $_.Topic -eq $t })
        $counts = Get-StatusCounts $fs
        $score = Get-MaturityScore $fs
        $crit = @($fs | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'Critical' }).Count
        $band = Get-MaturityBand $score $crit
        [pscustomobject]@{
            Topic = $t; Name = $TopicNames[$t]; Section = $TopicSection[$t]; Why = $TopicWhy[$t]; Total = $fs.Count
            Fail = $counts.Fail; Warning = $counts.Warning; Pass = $counts.Pass; Info = $counts.Info; Unavailable = $counts.Unavailable; Accepted = $counts.Accepted
            Score = $score; Band = $band.Name; BandKey = $band.Key; Capped = $band.Capped; CriticalGaps = $crit
            ChecklistItems = @($script:Checklist.Values | Where-Object { [string]$_.Topic -eq [string]$t }).Count
        }
    }
    return @($areas)
}

function Get-OverallStats {
    $all = @($script:Findings)
    $counts = Get-StatusCounts $all
    $score = Get-MaturityScore $all
    $crit = @($all | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'Critical' }).Count
    $scored = $counts.Pass + $counts.Warning + $counts.Fail
    $unav = $counts.Unavailable
    # Too few scored checks cannot support a rating; many unverified checks make the rating provisional.
    $rated = $scored -ge $MinScoredChecks
    $prov = $rated -and (($unav / [double]($scored + $unav)) -ge 0.25)
    if (-not $rated) { $score = $null }
    return [pscustomobject]@{
        Counts = $counts; Total = $all.Count; Score = $score; Band = (Get-MaturityBand $score $crit); CriticalFail = $crit
        Scored = $scored; UnverifiedAll = $unav; Rated = $rated; Provisional = $prov
        HighFail = @($all | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'High' }).Count
        CriticalWarn = @($all | Where-Object { $_.Status -eq 'Warning' -and $_.Severity -eq 'Critical' }).Count
        Unverified = @($all | Where-Object { $_.Status -eq 'Unavailable' -and $_.Severity -in @('Critical', 'High') }).Count
        Accepted = $counts.Accepted
        AcceptedCritical = @($all | Where-Object { $_.Status -eq 'Accepted' -and $_.Severity -eq 'Critical' }).Count
        AcceptedHigh = @($all | Where-Object { $_.Status -eq 'Accepted' -and $_.Severity -eq 'High' }).Count
    }
}

# Critical gap first, then critical partial, then high gap, and so on.
function Get-PriorityRank {
    param($Finding)
    $sev = switch ($Finding.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } default { 3 } }
    $st = if ($Finding.Status -eq 'Fail') { 0 } else { 1 }
    return ($sev * 2 + $st)
}

# Everything that needs action or verification, ranked; findings that describe the same root cause are rolled into one entry.
function Get-ActionList {
    $act = @($script:Findings | Where-Object { $_.Status -in @('Fail', 'Warning') -or ($_.Status -eq 'Unavailable' -and $_.Severity -in @('Critical', 'High')) })
    $ordered = @($act | Sort-Object @{ Expression = { Get-PriorityRank $_ } }, Topic, @{ Expression = { [version]($_.Id + '.0') } }, Key)
    $seen = @{}
    $out = New-Object System.Collections.ArrayList
    foreach ($f in $ordered) {
        $k = if ($f.RollupKey) { $f.RollupKey } else { $f.Key }
        if ($seen.ContainsKey($k)) { $seen[$k].Related += $f.Id; continue }
        $entry = [pscustomobject]@{ Finding = $f; Rank = (Get-PriorityRank $f); Related = @($f.Id) }
        $seen[$k] = $entry
        [void]$out.Add($entry)
    }
    return $out.ToArray()
}

# 30/60/90 roadmap from the framework: Contain, Standardize, Automate and measure, Optimize.
function Get-RoadmapBuckets {
    $b = [ordered]@{ Contain = @(); Standardize = @(); Automate = @(); Optimize = @() }
    foreach ($e in @(Get-ActionList)) {
        $f = $e.Finding
        $bucket = switch ($f.Severity) {
            'Critical' { 'Contain' }
            'High' { 'Standardize' }
            'Medium' { if ($f.Status -eq 'Fail') { 'Standardize' } else { 'Automate' } }
            default { if ($f.Status -eq 'Fail') { 'Automate' } else { 'Optimize' } }
        }
        $b[$bucket] += $e
    }
    return $b
}

# The framework's highest-value checks, each rolled up from the findings that map to it.
function Get-StartHereRows {
    $rows = foreach ($s in $StartHere) {
        $ids = @($s.Ids)
        $fs = @($script:Findings | Where-Object { ($ids -contains $_.Id) -or (@($_.AlsoCovers | Where-Object { $ids -contains $_ }).Count -gt 0) })
        $manualIds = @($ids | Where-Object { $i = $_; @($fs | Where-Object { $_.Id -eq $i -or (@($_.AlsoCovers) -contains $i) }).Count -eq 0 })
        $nFail = @($fs | Where-Object Status -eq 'Fail').Count
        $nWarn = @($fs | Where-Object Status -eq 'Warning').Count
        $nPass = @($fs | Where-Object Status -eq 'Pass').Count
        $nUnav = @($fs | Where-Object Status -eq 'Unavailable').Count
        $nAcc = @($fs | Where-Object Status -eq 'Accepted').Count
        $status = if ($fs.Count -eq 0) { 'Manual' } elseif ($nFail -gt 0) { 'Fail' } elseif ($nWarn -gt 0) { 'Warning' } elseif ($nAcc -gt 0) { 'Accepted' } elseif ($nPass -gt 0) { 'Pass' } elseif ($nUnav -gt 0) { 'Unavailable' } else { 'Info' }
        $worst = @($fs | Sort-Object @{ Expression = { switch ($_.Status) { 'Fail' { 0 } 'Warning' { 1 } 'Unavailable' { 2 } 'Accepted' { 3 } 'Pass' { 4 } default { 5 } } } }, @{ Expression = { Get-PriorityRank $_ } }, @{ Expression = 'EvidenceCount'; Descending = $true } | Select-Object -First 1)
        [pscustomobject]@{
            N = $s.N; Check = $s.Check; Question = $s.Question; Area = $s.Area; Ids = $ids; Status = $status; Worst = $(if ($worst.Count -gt 0) { $worst[0] } else { $null })
            Linked = $fs.Count; Unverified = $nUnav; ManualIds = $manualIds
        }
    }
    return @($rows)
}

# ------------------------------------------------------------------ report model: agent risk register and environment profile
# Transparent additive scoring from signals the script already collected. Each signal is listed so the score can be challenged.
function Get-AgentRiskRegister {
    $view = @($script:AgentView)
    if ($view.Count -eq 0) { return @() }
    $deep = @{}
    foreach ($d in @($script:DeepAgentRows)) { $deep[([string]$d.AgentId).ToLower()] = $d }
    $orphan = @{}
    foreach ($o in @($script:OrphanedAssets)) { if ($o.Kind -eq 'Agent' -and $o.Id) { $orphan[([string]$o.Id).ToLower()] = $true } }
    $openChannel = 'Demo|Custom website|Direct Line|WhatsApp|Facebook|Telephony|Twilio|Slack|Telegram|\bLine\b|GroupMe'
    $rows = foreach ($a in $view) {
        $id = ([string]$a.Id).ToLower()
        $d = $deep[$id]
        $sigs = New-Object System.Collections.ArrayList
        $isNone = [bool]($a.Auth -match '^None$|No authentication')
        $published = [bool]$a.LastPublished
        $open = [bool]($a.Channels -match $openChannel)
        if ($isNone) {
            [void]$sigs.Add([pscustomobject]@{ P = $(if ($published) { 35 } else { 10 }); T = $(if ($published) { 'No authentication (published)' } else { 'No authentication (draft)' }) })
            if ($open) { [void]$sigs.Add([pscustomobject]@{ P = 15; T = 'Unauthenticated on an open channel' }) }
        }
        elseif ($open) { [void]$sigs.Add([pscustomobject]@{ P = 8; T = 'Open web or external channel' }) }
        if ($a.EntireTenant) { [void]$sigs.Add([pscustomobject]@{ P = 12; T = 'Shared with the entire tenant' }) }
        $acc = $script:AgentAccess[$id]
        if ($acc -and $acc.MultiTenant) { [void]$sigs.Add([pscustomobject]@{ P = 12; T = 'Usable from other Microsoft Entra tenants' }) }
        if ($acc -and $acc.SignInAsNeeded -and $acc.Published) { [void]$sigs.Add([pscustomobject]@{ P = 6; T = 'Asks for sign-in only when a topic needs it' }) }
        if (($a.EditorUsers + $a.EditorGroups) -gt 5) { [void]$sigs.Add([pscustomobject]@{ P = 4; T = 'More than 5 co-authors' }) }
        $maker = @($a.Ops | Where-Object { $_.Provider -eq 'Maker' -and $_.UsedAs -ne 'Knowledge' })
        if ($maker.Count -gt 0) { [void]$sigs.Add([pscustomobject]@{ P = 8; T = "Maker credentials on $($maker.Count) tool operation(s)" }) }
        $makerWrite = @($maker | Where-Object { $_.Operation -match $WriteLikeOperation })
        if ($makerWrite.Count -gt 0) { [void]$sigs.Add([pscustomobject]@{ P = 14; T = "$($makerWrite.Count) write-like action(s) run as the maker" }) }
        if (@($a.Ops | Where-Object { $ExternalDataConnectors.ContainsKey($_.Connector) }).Count -gt 0) { [void]$sigs.Add([pscustomobject]@{ P = 6; T = 'External-service connector' }) }
        if ($a.WebSearch) { [void]$sigs.Add([pscustomobject]@{ P = 4; T = 'Web search grounding' }) }
        if ($orphan.ContainsKey($id)) { [void]$sigs.Add([pscustomobject]@{ P = 8; T = 'Owner deleted or disabled' }) }
        if ($d) {
            if ($d.Autonomous) {
                [void]$sigs.Add([pscustomobject]@{ P = 8; T = 'Autonomous (external trigger)' })
                if ($d.MakerCredentialTools -gt 0) { [void]$sigs.Add([pscustomobject]@{ P = 14; T = 'Autonomous with maker credentials' }) }
            }
            if ($d.DynamicHttpUrl) { [void]$sigs.Add([pscustomobject]@{ P = 10; T = 'HTTP node with a dynamic URL' }) }
            elseif ($d.HttpNodes -gt 0) { [void]$sigs.Add([pscustomobject]@{ P = 4; T = 'HTTP request nodes' }) }
            if ($d.McpActions -gt 0) { [void]$sigs.Add([pscustomobject]@{ P = 5; T = 'MCP or external agent actions' }) }
            if ($d.Skills -gt 0) { [void]$sigs.Add([pscustomobject]@{ P = 4; T = 'Bot Service skills' }) }
            if ($d.PublicSites -or $d.ClassicPublicSource) { [void]$sigs.Add([pscustomobject]@{ P = 6; T = 'Public website knowledge' }) }
            if ($d.ModelKnowledge) { [void]$sigs.Add([pscustomobject]@{ P = 2; T = 'General model knowledge' }) }
            if ($d.SecretComponents) { [void]$sigs.Add([pscustomobject]@{ P = 25; T = 'Possible hard-coded secret' }) }
            if ($isNone -and $d.SharePointSites) { [void]$sigs.Add([pscustomobject]@{ P = 20; T = 'SharePoint knowledge without sign-in' }) }
            if ($d.ContentModeration -match '^(low|minimal)$') { [void]$sigs.Add([pscustomobject]@{ P = 4; T = 'Low content moderation' }) }
        }
        $pts = 0; foreach ($s in $sigs) { $pts += $s.P }
        $score = [Math]::Min(100, $pts)
        $rating = if ($score -ge 60) { 'Critical' } elseif ($score -ge 35) { 'High' } elseif ($score -ge 15) { 'Medium' } elseif ($score -gt 0) { 'Low' } else { 'None' }
        $credits = $null
        if ($script:AgentCredits.ContainsKey($id)) { $credits = [math]::Round([double]$script:AgentCredits[$id].Consumed, 0) }
        [pscustomobject]@{
            Agent = $a.Agent; Environment = $a.Environment; Owner = (Resolve-OwnerLabel $a.Owner); Authentication = $(if ($a.Auth) { $a.Auth } else { 'not reported' }); Channels = $a.Channels
            Published = $(if ($published) { 'Yes' } else { 'No' }); RiskScore = $score; Rating = $rating; Signals = (($sigs | ForEach-Object { $_.T }) -join '; ')
            Credits30d = $credits; OwnerId = $a.Owner; AgentId = $a.Id; EnvironmentId = $a.EnvironmentId
        }
    }
    return @($rows | Sort-Object @{ Expression = 'RiskScore'; Descending = $true }, @{ Expression = { if ($null -ne $_.Credits30d) { $_.Credits30d } else { -1 } }; Descending = $true }, Agent)
}

function Get-EnvironmentProfile {
    $envs = @($script:EnvMap.Values)
    if ($envs.Count -eq 0) { return @() }
    $unauth = @{}; $makerAg = @{}
    function AddFlag($p, $t) { [void]$flags.Add([pscustomobject]@{ P = $p; T = $t }) }
    foreach ($a in @($script:AgentView)) {
        $k = ([string]$a.EnvironmentId).ToLower()
        if ($a.Auth -match '^None$|No authentication' -and $a.LastPublished) { $unauth[$k] = 1 + [int]$unauth[$k] }
        if (@($a.Ops | Where-Object { $_.Provider -eq 'Maker' -and $_.UsedAs -ne 'Knowledge' }).Count -gt 0) { $makerAg[$k] = 1 + [int]$makerAg[$k] }
    }
    $rows = foreach ($e in ($envs | Sort-Object Type, Name)) {
        $k = ([string]$e.Id).ToLower()
        $facts = $script:EnvFacts[$k]
        $flags = New-Object System.Collections.ArrayList
        $assets = $e.Apps + $e.Flows + $e.Agents + $e.Sites
        $isProd = $e.Type -in @('Production', 'Default')
        if ($e.Type -eq 'Teams') { AddFlag 3 'Dataverse for Teams (deprecated)' }
        elseif (-not $e.IsManaged) {
            switch ($e.Type) {
                'Default' { AddFlag 10 'Default environment is not managed (recommended)' }
                'Production' { AddFlag 10 'Production environment is not managed (recommended)' }
                'Developer' { AddFlag 10 'Unmanaged developer environment (deprecation)' }
                'Sandbox' { AddFlag 4 'Sandbox is not managed (recommended)' }
                default { AddFlag 3 "Unmanaged $($e.Type) environment" }
            }
        }
        if ($e.DataverseId -and -not $e.SecurityGroupId) {
            if ($e.Type -in @('Production', 'Sandbox')) { AddFlag 12 'No security group restricts access' } elseif ($e.Type -eq 'Trial') { AddFlag 3 'No security group' }
        }
        if ($null -ne $facts -and $facts.ContainsKey('ConvAudit') -and $null -ne $facts['ConvAudit'] -and -not [bool]$facts['ConvAudit']) { AddFlag 10 'Conversation audit logging is off' }
        if ($null -ne $facts -and $facts.ContainsKey('DvAudit') -and -not [bool]$facts['DvAudit']) { AddFlag $(if ($isProd) { 15 } else { 6 }) 'Dataverse auditing is off' }
        if ($null -ne $facts -and $facts.ContainsKey('GuestRestricted') -and -not [bool]$facts['GuestRestricted'] -and $isProd) { AddFlag 8 'Guest access to Dataverse is allowed' }
        if ($e.Type -eq 'Production' -and $e.Retention -eq 'P7D') { AddFlag 5 'Production backups kept 7 days' }
        if ($e.Type -eq 'Default' -and $assets -gt $DefaultEnvironmentAssetWarnThreshold) { AddFlag 15 "$assets assets live in the default environment" }
        if ($unauth.ContainsKey($k)) { AddFlag ([Math]::Min(20, 10 * [int]$unauth[$k])) "$($unauth[$k]) published agent(s) with no authentication" }
        if ($makerAg.ContainsKey($k)) { AddFlag ([Math]::Min(9, 3 * [int]$makerAg[$k])) "$($makerAg[$k]) agent(s) use maker credentials" }
        if ($null -ne $facts -and $facts.ContainsKey('SysAdmins')) { $sa = [int]$facts['SysAdmins']; if ($sa -gt 10) { AddFlag 15 "$sa System Administrators" } elseif ($sa -gt 5) { AddFlag 8 "$sa System Administrators" } }
        if ($null -ne $facts -and $facts.ContainsKey('CreditPool') -and [bool]$facts['CreditPool'] -and [double]$facts['CreditAllocated'] -eq 0 -and $e.Type -in @('Developer', 'Trial', 'Sandbox', 'Default')) { AddFlag 5 'Draws on the credit pool with no allocation' }
        if ($e.State -and $e.State -notin @('Ready', 'Succeeded', 'Enabled')) { AddFlag 8 "State: $($e.State)" }
        if ($e.Type -in @('Production', 'Sandbox', 'Trial') -and $assets -eq 0 -and $null -ne (Get-DaysSince $e.CreatedAt) -and (Get-DaysSince $e.CreatedAt) -gt 90) { AddFlag 3 'No assets after 90 days' }
        $pts = 0; foreach ($f in $flags) { $pts += $f.P }
        $score = [Math]::Min(100, $pts)
        $rating = if ($score -ge 50) { 'Critical' } elseif ($score -ge 30) { 'High' } elseif ($score -ge 15) { 'Medium' } elseif ($score -gt 0) { 'Low' } else { 'None' }
        $onOff = { param($v) if ($null -eq $v) { 'n/a' } elseif ([bool]$v) { 'On' } else { 'Off' } }
        [pscustomobject]@{
            Environment = $e.Name; Type = $e.Type; Managed = $(if ($e.Type -eq 'Teams') { 'n/a' } elseif ($e.IsManaged) { 'Yes' } else { 'No' }); Group = $e.Group
            SecurityGroup = $(if (-not $e.DataverseId) { 'n/a' } elseif ($e.SecurityGroupId) { 'Yes' } else { 'No' }); Geo = $(if ($e.Geo) { $e.Geo } else { $e.Location }); Retention = $e.Retention; State = $e.State
            Apps = $e.Apps; Flows = $e.Flows; Agents = $e.Agents; Sites = $e.Sites
            ConversationAudit = $(if ($null -ne $facts -and $facts.ContainsKey('ConvAudit')) { & $onOff $facts['ConvAudit'] } else { 'n/a' })
            DataverseAudit = $(if ($null -ne $facts -and $facts.ContainsKey('DvAudit')) { & $onOff $facts['DvAudit'] } else { 'n/a' })
            SystemAdmins = $(if ($null -ne $facts -and $facts.ContainsKey('SysAdmins')) { $facts['SysAdmins'] } else { $null })
            RiskScore = $score; Rating = $rating; Flags = (($flags | ForEach-Object { $_.T }) -join '; '); EnvironmentId = $e.Id
        }
    }
    return @($rows | Sort-Object @{ Expression = 'RiskScore'; Descending = $true }, Environment)
}

# ------------------------------------------------------------------ report model: data collection health, baseline comparison
function Get-FailureCause {
    param($Status)
    $s = [int]$Status
    if ($s -eq 0) { return 'No token or no response' }
    if ($s -eq 401) { return 'Not signed in or token rejected (401)' }
    if ($s -eq 403) { return 'Permission denied (403)' }
    if ($s -eq 404) { return 'Endpoint or feature not available (404)' }
    if ($s -eq 429) { return 'Throttled (429)' }
    if ($s -ge 500) { return 'Service error (5xx)' }
    return "HTTP $s"
}

function Get-ApiHostClass {
    param([string]$Endpoint)
    $h = ''
    try { $h = ([uri]$Endpoint).Host } catch { Write-Verbose "Endpoint '$Endpoint' is not a valid URI." }
    if ($h -match '\.dynamics\.com$') { return 'Dataverse (per environment)' }
    if ($h) { return $h }
    return 'local'
}

function Get-FailureHint {
    param([string]$HostName, $Status)
    $s = [int]$Status
    if ($s -eq 429) { return 'Throttled. Re-run later or lower the scan caps.' }
    if ($HostName -like 'Dataverse*') { if ($s -eq 401 -or $s -eq 403) { return 'Add the signed-in user to a security role in the environment, or lower -MaxDataverseEnvironments.' } }
    if ($HostName -like 'graph*') { if ($s -eq 401 -or $s -eq 403) { return 'Needs directory read rights (for example Global Reader). Use -SkipEntra to skip these checks.' } }
    if ($HostName -like '*bap*') { return 'Best-effort fallback with no api.powerplatform.com equivalent. Use -SkipLegacyApis to skip it.' }
    if ($HostName -like '*powerplatform*') {
        if ($s -eq 401 -or $s -eq 403) { return 'Needs the Power Platform Administrator role (or equivalent) in the tenant.' }
        if ($s -eq 404) { return 'Preview endpoint not available in this tenant or region yet.' }
    }
    if ($s -eq 0) { return 'No token for this resource (AuthMethod Token only covers api.powerplatform.com) or no response.' }
    return ''
}

function Get-ApiHealth {
    $log = @($script:ApiLog)
    $byHost = @($log | Group-Object { Get-ApiHostClass $_.Endpoint } | Sort-Object Count -Descending | ForEach-Object {
            $g = @($_.Group); $bad = @($g | Where-Object { -not $_.Ok }).Count
            [pscustomobject]@{ Host = $_.Name; Calls = $g.Count; Succeeded = ($g.Count - $bad); Failed = $bad; SuccessRate = $(if ($g.Count -gt 0) { [int][math]::Round(100 * ($g.Count - $bad) / $g.Count, 0) } else { 100 }) }
        })
    $failed = @($log | Where-Object { -not $_.Ok })
    $causes = @($failed | Group-Object { "$(Get-ApiHostClass $_.Endpoint)|$($_.Status)" } | Sort-Object Count -Descending | ForEach-Object {
            $g = @($_.Group); $first = $g[0]; $hostName = Get-ApiHostClass $first.Endpoint
            [pscustomobject]@{ Host = $hostName; Cause = (Get-FailureCause $first.Status); Calls = $g.Count; Example = $first.Name; Error = $first.Error; WhatToDo = (Get-FailureHint $hostName $first.Status); RequestId = $first.RequestId }
        })
    $slow = @($log | Sort-Object { [double]$_.Ms } -Descending | Select-Object -First 5 | ForEach-Object { [pscustomobject]@{ Call = $_.Name; Ms = $_.Ms; Status = $_.Status } })
    return [pscustomobject]@{ Total = $log.Count; Ok = ($log.Count - $failed.Count); Failed = $failed.Count; Hosts = $byHost; Causes = $causes; Slowest = $slow }
}

# Compares this run with a previous run folder (or its findings.json): new, resolved, improved, regressed.
function Get-BaselineDiff {
    param([string]$Path)
    if (-not $Path) { return $null }
    $file = $Path
    if (Test-Path -LiteralPath $Path -PathType Container) { $file = Join-Path $Path 'findings.json' }
    if (-not (Test-Path -LiteralPath $file)) { Add-Limitation 'Baseline' "Baseline findings.json was not found at $Path, so no comparison is shown."; return $null }
    # foreach unrolls the array that Windows PowerShell 5.1 returns as a single object; @() alone does not.
    try { $base = @(); foreach ($x in (Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json)) { $base += $x } }
    catch { Add-Limitation 'Baseline' "Baseline could not be read: $($_.Exception.Message)"; return $null }
    # A baseline from an unredacted run can name things that no longer exist (for example a deleted data policy), so register those names before the report is redacted.
    if ($script:Redaction.Active -and $script:Redaction.Ready) {
        foreach ($b in $base) { if ([string]$b.Id -eq '4.3' -and [string]$b.Title -match '^Default group for new connectors: (.+)$') { [void](Add-RedactionValue $Matches[1] 'Policy') } }
    }
    $sumFile = Join-Path (Split-Path -Parent $file) 'run-summary.json'
    $baseSummary = $null
    if (Test-Path -LiteralPath $sumFile) { try { $baseSummary = Get-Content -LiteralPath $sumFile -Raw -Encoding UTF8 | ConvertFrom-Json } catch { Write-Verbose "Baseline run-summary.json could not be read: $($_.Exception.Message)" } }
    $keyOf = { param($f) "$($f.Id)|$($f.Title)" }
    $bm = @{}; foreach ($b in $base) { $bm[(& $keyOf $b)] = $b }
    $cm = @{}; foreach ($c in $script:Findings) { $cm[(& $keyOf $c)] = $c }
    $value = @{ Pass = 2; Warning = 1; Fail = 0 }
    $new = New-Object System.Collections.ArrayList; $resolved = New-Object System.Collections.ArrayList
    $improved = New-Object System.Collections.ArrayList; $regressed = New-Object System.Collections.ArrayList; $gone = New-Object System.Collections.ArrayList; $accepted = New-Object System.Collections.ArrayList
    $unchanged = 0
    foreach ($k in $cm.Keys) {
        $c = $cm[$k]
        if (-not $bm.ContainsKey($k)) { if ($c.Status -in @('Fail', 'Warning')) { [void]$new.Add([pscustomobject]@{ Id = $c.Id; Title = $c.Title; Was = ''; Now = $c.Status; Severity = $c.Severity; Key = $c.Key }) }; continue }
        $b = $bm[$k]
        if ($b.Status -eq $c.Status) { $unchanged++; continue }
        $row = [pscustomobject]@{ Id = $c.Id; Title = $c.Title; Was = $b.Status; Now = $c.Status; Severity = $c.Severity; Key = $c.Key }
        # An accepted risk is a decision, not a fix: list it on its own, and treat a lapsed acceptance as a regression.
        if ($c.Status -eq 'Accepted') { [void]$accepted.Add($row); continue }
        if ($b.Status -eq 'Accepted') {
            if ($c.Status -in @('Fail', 'Warning')) { [void]$regressed.Add($row) }
            elseif ($c.Status -eq 'Pass') { [void]$resolved.Add($row) }
            continue
        }
        if ($value.ContainsKey([string]$b.Status) -and $value.ContainsKey([string]$c.Status)) {
            if ($value[[string]$c.Status] -gt $value[[string]$b.Status]) { if ($c.Status -eq 'Pass') { [void]$resolved.Add($row) } else { [void]$improved.Add($row) } }
            else { [void]$regressed.Add($row) }
        }
    }
    foreach ($k in $bm.Keys) { if (-not $cm.ContainsKey($k) -and $bm[$k].Status -in @('Fail', 'Warning')) { [void]$gone.Add([pscustomobject]@{ Id = $bm[$k].Id; Title = $bm[$k].Title; Was = $bm[$k].Status; Now = 'not reported'; Severity = $bm[$k].Severity; Key = '' }) } }
    $kpi = @()
    if ($baseSummary -and $baseSummary.Kpis) {
        foreach ($p in $baseSummary.Kpis.PSObject.Properties) {
            if (-not $script:Kpi.Contains($p.Name)) { continue }
            $now = $script:Kpi[$p.Name]
            $change = ''
            $bv = 0.0; $nv = 0.0
            $inv = [System.Globalization.CultureInfo]::InvariantCulture
            if ([double]::TryParse([string]$p.Value, [System.Globalization.NumberStyles]::Float, $inv, [ref]$bv) -and [double]::TryParse([string]$now, [System.Globalization.NumberStyles]::Float, $inv, [ref]$nv)) {
                $delta = [math]::Round($nv - $bv, 1)
                if ($delta -ne 0) { $change = $(if ($delta -gt 0) { '+' } else { '' }) + $delta.ToString($inv) }
            }
            $kpi += [pscustomobject]@{ Metric = $p.Name; Before = $p.Value; Now = $now; Change = $change }
        }
    }
    $when = ''
    if ($baseSummary -and $baseSummary.GeneratedAt) { $when = Format-IsoDate $baseSummary.GeneratedAt }
    elseif (Test-Path -LiteralPath $file) { $when = (Get-Item -LiteralPath $file).LastWriteTime.ToString('yyyy-MM-dd HH:mm') }
    $beforeScore = $null
    if ($baseSummary -and $baseSummary.Scores -and $null -ne $baseSummary.Scores.Overall) { $beforeScore = [int]$baseSummary.Scores.Overall }
    return [pscustomobject]@{
        Path = $file; When = $when; BeforeScore = $beforeScore; New = $new.ToArray(); Resolved = $resolved.ToArray(); Improved = $improved.ToArray()
        Regressed = $regressed.ToArray(); Gone = $gone.ToArray(); Accepted = $accepted.ToArray(); Unchanged = $unchanged; Kpis = $kpi
    }
}

# Good / bad direction for each governance KPI, used to color the tiles.
function Get-KpiClass {
    param([string]$Name, $Value)
    $rules = @{
        'Environments in a group %' = @{ Dir = 'high'; Good = 80; Warn = 40 }
        'Highest Dataverse capacity use %' = @{ Dir = 'low'; Good = 70; Warn = 85 }
        'Unauthenticated agents' = @{ Dir = 'zero' }
        'Agents shared with entire tenant' = @{ Dir = 'zero' }
        'Orphaned assets' = @{ Dir = 'zero' }
        'Agents using maker credentials' = @{ Dir = 'zero' }
        'Unused apps (Advisor, 60d)' = @{ Dir = 'zerowarn' }
        'Sites without traffic (30d)' = @{ Dir = 'zerowarn' }
        'Published agents with no credit use' = @{ Dir = 'zerowarn' }
        'Flows with no runs (sample)' = @{ Dir = 'zerowarn' }
        'Environments drawing on the credit tenant pool' = @{ Dir = 'zerowarn' }
    }
    $v = 0.0
    if (-not [double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v)) { return 'neutral' }
    if (-not $rules.ContainsKey($Name)) { return 'neutral' }
    $r = $rules[$Name]
    switch ($r.Dir) {
        'zero' { if ($v -eq 0) { return 'good' } else { return 'bad' } }
        'zerowarn' { if ($v -eq 0) { return 'good' } else { return 'warn' } }
        'high' { if ($v -ge $r.Good) { return 'good' } elseif ($v -ge $r.Warn) { return 'warn' } else { return 'bad' } }
        'low' { if ($v -le $r.Good) { return 'good' } elseif ($v -le $r.Warn) { return 'warn' } else { return 'bad' } }
    }
    return 'neutral'
}

function Get-Coverage {
    $rows = New-Object System.Collections.ArrayList
    foreach ($id in ($script:Checklist.Keys | Sort-Object { [version]($_ + '.0') })) {
        $c = $script:Checklist[$id]
        $fs = @($script:Findings | Where-Object { $_.Id -eq $id -or @($_.AlsoCovers) -contains $id })
        $auto = @($fs | Where-Object { $_.Status -ne 'Unavailable' })
        $cov = if ($auto.Count -gt 0) { 'Automated (verify remaining aspects)' } elseif ($fs.Count -gt 0) { 'Attempted, unavailable' } else { 'Manual' }
        [void]$rows.Add([pscustomobject]@{ Id = $id; Topic = [int]$c.Topic; Priority = $c.Priority; Feature = $c.Feature; Coverage = $cov; Check = $c.Check; Verify = $c.Verify; Target = $c.Target })
    }
    return $rows.ToArray()
}

# ------------------------------------------------------------------ report: HTML building blocks
function Get-ReportCss {
    return @'
:root{--bg:#f3f6fa;--card:#fff;--ink:#14202e;--muted:#52606f;--line:#dbe3ec;--soft:#eaf1f9;--brand:#0f5fa8;--brand2:#0f6cbd;
--fail:#b42318;--fail-bg:#fde8e6;--warn:#8f4300;--warn-bg:#fdeed3;--pass:#05683f;--pass-bg:#d9f3e4;--info:#0b6a74;--info-bg:#d7f0f2;--na:#475467;--na-bg:#e8ebf0;--man:#6a35a8;--man-bg:#ece3f7;--acc:#2f3f8f;--acc-bg:#e3e8fa;
--c-fail:#d92d20;--c-warn:#f79009;--c-pass:#12b76a;--c-info:#1b9aaa;--c-na:#98a2b3;--c-acc:#6b7fd7;--high:#8f4300;--med:#44506b;--low:#667085;
--shadow:0 1px 2px rgba(20,32,46,.06),0 6px 18px rgba(20,32,46,.05)}
@media (prefers-color-scheme:dark){:root{--bg:#0b1522;--card:#111f31;--ink:#e6eef8;--muted:#9fb1c5;--line:#25384f;--soft:#182a41;--brand:#6cb6ff;--brand2:#4da3ff;
--fail:#ff9a90;--fail-bg:#3d1714;--warn:#ffbc66;--warn-bg:#3a2a10;--pass:#6fdca0;--pass-bg:#10301f;--info:#5fd3de;--info-bg:#0e3238;--na:#b3bccb;--na-bg:#262b36;--man:#c9aef5;--man-bg:#2a2147;--acc:#b4c0ff;--acc-bg:#1f2547;
--high:#ffbc66;--med:#b3bccb;--low:#9aa3b2;--shadow:none}}
*{box-sizing:border-box}
html{scroll-behavior:smooth;scroll-padding-top:64px}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Helvetica,Arial,sans-serif}
a{color:var(--brand2)}
.wrap{max-width:1360px;margin:0 auto;padding:0 28px}
.hero{background:linear-gradient(120deg,#00264d,#0067b8);color:#fff;padding:26px 0 22px}
.hero h1{margin:2px 0 4px;font-size:28px;font-weight:650}
.hero .sub{margin:0;color:#cfe4fa;font-size:13px;letter-spacing:.3px;text-transform:uppercase}
.hero .meta{display:flex;flex-wrap:wrap;gap:6px 24px;margin-top:12px;font-size:12.5px;color:#e3eefb}
.hero .meta b{color:#fff;font-weight:600;margin-right:4px}
.hero .conf{margin-top:12px;display:inline-block;background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.28);border-radius:8px;padding:5px 11px;font-size:12px}
.hero .conf.red{background:#fff3c4;border-color:#f5c542;color:#4a3500}
nav.top{position:sticky;top:0;z-index:30;background:var(--card);border-bottom:1px solid var(--line);box-shadow:var(--shadow)}
nav.top .wrap{display:flex;gap:12px;padding-top:6px;padding-bottom:6px;align-items:center}
nav.top .links{display:flex;flex:1 1 auto;flex-wrap:wrap;justify-content:center;gap:4px 2px;min-width:0}
nav.top a{text-align:center;white-space:nowrap;text-decoration:none;color:var(--muted);padding:6px 9px;border-radius:18px;font-weight:600;font-size:13px}
nav.top a:hover{background:var(--soft);color:var(--ink)}
nav.top a.on{background:var(--brand);color:#fff}
nav.top .tools{display:flex;flex:none;gap:4px;padding-left:12px;border-left:1px solid var(--line)}
nav.top .tool{margin:0;padding:6px 12px;font-size:13px;white-space:nowrap}
main{padding:22px 0 60px}
section.panel{background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);padding:22px 24px;margin:0 0 20px}
section.panel>h2{margin:0 0 2px;font-size:20px}
section.panel>.lead{margin:0 0 16px;color:var(--muted);max-width:980px}
h3{margin:22px 0 8px;font-size:15px}
.small{color:var(--muted);font-size:12px}
.grid{display:grid;gap:16px}
.grid>*{min-width:0}
.g3{grid-template-columns:1.25fr 1fr 1.15fr}
.g2{grid-template-columns:1fr 1fr}
.g4{grid-template-columns:repeat(4,1fr)}
@media (max-width:1100px){.g3,.g4{grid-template-columns:1fr 1fr}}
@media (max-width:720px){.g2,.g3,.g4{grid-template-columns:1fr}.wrap{padding:0 14px}.verdict{gap:14px}.verdict .big{font-size:26px}nav.top{position:static}nav.top .wrap{flex-direction:column;align-items:stretch;gap:6px}nav.top .tools{justify-content:center;padding-left:0;border-left:0}}
.box{border:1px solid var(--line);border-radius:12px;padding:16px 18px;background:var(--card)}
.box h3{margin:0 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted)}
.verdict{display:flex;gap:18px;align-items:center}
.verdict .big{font-size:30px;font-weight:700;line-height:1.1}
.verdict .cap{margin-top:6px;font-size:12px;color:var(--muted)}
.b-atrisk{--bc:var(--c-fail);--bt:var(--fail)}.b-developing{--bc:var(--c-warn);--bt:#b54708}.b-established{--bc:var(--c-info);--bt:var(--info)}.b-leading{--bc:var(--c-pass);--bt:var(--pass)}.b-none{--bc:var(--c-na);--bt:var(--na)}
.ring{--p:0;width:112px;height:112px;flex:none;border-radius:50%;background:conic-gradient(var(--bc,var(--c-na)) calc(var(--p)*1%),var(--line) 0);display:grid;place-items:center;position:relative}
.ring:before{content:"";position:absolute;inset:11px;border-radius:50%;background:var(--card)}
.ring span{position:relative;font-size:25px;font-weight:700}
.bandtxt{color:var(--bt,var(--bc))}
.headline{margin:12px 0 0;font-size:14px}
.donutbox{display:flex;gap:16px;align-items:center}
.donut{width:136px;height:136px;flex:none}.donut-n{font-size:26px;font-weight:700;fill:var(--ink)}.donut-l{font-size:11px;fill:var(--muted)}
.legend{list-style:none;margin:0;padding:0;font-size:13px}.legend li{display:flex;align-items:center;gap:8px;margin:3px 0}
.legend i{width:11px;height:11px;border-radius:3px;display:inline-block}.legend b{min-width:28px;display:inline-block;text-align:right}
.i-fail{background:var(--c-fail)}.i-warn{background:var(--c-warn)}.i-pass{background:var(--c-pass)}.i-info{background:var(--c-info)}.i-na{background:var(--c-na)}.i-acc{background:var(--c-acc)}
table.matrix{border-collapse:collapse;width:100%;font-size:13px}
table.matrix th{font-weight:600;color:var(--muted);text-align:center;padding:4px 6px;font-size:12px}
table.matrix td{text-align:center;padding:7px 6px;border-top:1px solid var(--line)}
table.matrix td:first-child,table.matrix th:first-child{text-align:left}
table.matrix td.h1{background:var(--fail-bg);color:var(--fail);font-weight:700}table.matrix td.h2{background:var(--warn-bg);color:var(--warn);font-weight:700}table.matrix td.h3{background:var(--na-bg);color:var(--na);font-weight:700}table.matrix td.h0{color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px;margin-top:16px}
.tile{border:1px solid var(--line);border-left:5px solid var(--c-na);border-radius:10px;padding:11px 14px;background:var(--card)}
.tile b{display:block;font-size:24px;line-height:1.15}.tile span{font-size:12px;color:var(--muted)}
.tile.good{border-left-color:var(--c-pass)}.tile.warn{border-left-color:var(--c-warn)}.tile.bad{border-left-color:var(--c-fail)}
.tile .delta{font-size:11.5px;font-weight:600;margin-left:6px}.delta.up{color:var(--pass)}.delta.down{color:var(--fail)}
.fixlist{display:grid;gap:10px;margin:0;padding:0;list-style:none;counter-reset:fx}
.fixlist li{display:grid;grid-template-columns:34px 1fr;gap:12px;border:1px solid var(--line);border-radius:10px;padding:11px 14px;background:var(--card)}
.fixlist .n{width:30px;height:30px;border-radius:50%;background:var(--brand);color:#fff;display:grid;place-items:center;font-weight:700;font-size:13px}
.fixlist .t{font-weight:650}.fixlist .v{color:var(--muted);font-size:13px;margin-top:2px}.fixlist .a{margin-top:4px;font-size:13px}
.fixlist .a:before{content:"Do: ";font-weight:650;color:var(--brand2)}
.fixlist .w{margin-top:2px;font-size:13px;color:var(--muted)}.fixlist .w:before{content:"Why: ";font-weight:650;color:var(--brand2)}
.why{margin-top:-4px;font-size:12.5px;color:var(--muted)}.why b{color:var(--brand2)}
.route{font-size:12.5px;color:var(--muted)}.route b{color:var(--brand2)}
.fixlist .rt{margin-top:2px;font-size:13px;color:var(--muted)}.fixlist .rt b{font-weight:650;color:var(--brand2)}
.chip{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:650;line-height:1.5;white-space:nowrap}
.s-Fail{background:var(--fail-bg);color:var(--fail)}.s-Warning{background:var(--warn-bg);color:var(--warn)}.s-Pass{background:var(--pass-bg);color:var(--pass)}
.s-Info{background:var(--info-bg);color:var(--info)}.s-Unavailable{background:var(--na-bg);color:var(--na)}.s-Manual{background:var(--man-bg);color:var(--man)}.s-Accepted{background:var(--acc-bg);color:var(--acc)}
.sev-Critical,.r-Critical{background:#b42318;color:#fff}
.sev-High,.r-High{background:var(--warn-bg);color:var(--high);box-shadow:inset 0 0 0 1px var(--high)}
.sev-Medium,.r-Medium{background:var(--soft);color:var(--med);box-shadow:inset 0 0 0 1px var(--line)}
.sev-Low,.r-Low{background:transparent;color:var(--low);box-shadow:inset 0 0 0 1px var(--line)}
.r-None{background:var(--pass-bg);color:var(--pass)}
.bd{background:var(--bc,var(--c-na));color:#fff}.b-developing .bd{color:#2d1a00}.b-established .bd,.b-leading .bd,.b-none .bd{color:#0b1b33}
.stack{display:flex;height:9px;border-radius:6px;overflow:hidden;background:var(--line)}
.stack i{display:block}.stack .fail{background:var(--c-fail)}.stack .warn{background:var(--c-warn)}.stack .pass{background:var(--c-pass)}.stack .info{background:var(--c-info)}.stack .na{background:var(--c-na)}.stack .acc{background:var(--c-acc)}
.sechead{display:flex;align-items:baseline;gap:10px;margin:22px 0 10px}.sechead h3{margin:0}.sechead span{color:var(--muted);font-size:12px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:12px}
.acard{border:1px solid var(--line);border-top:4px solid var(--bc,var(--c-na));border-radius:10px;padding:12px 14px;background:var(--card);display:flex;flex-direction:column;gap:7px}
.acard .h{display:flex;gap:8px;align-items:flex-start;justify-content:space-between}.acard .h b{font-size:14px}
.acard .num{display:inline-grid;place-items:center;min-width:24px;height:24px;border-radius:7px;background:var(--soft);color:var(--brand);font-weight:700;font-size:12px;margin-right:6px}
.acard .counts{font-size:12px;color:var(--muted)}.acard p{margin:0;font-size:12px;color:var(--muted)}
.acard a.go{font-size:12px;font-weight:600;text-decoration:none;margin-top:auto}
.road{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
@media (max-width:1100px){.road{grid-template-columns:1fr 1fr}}@media (max-width:720px){.road{grid-template-columns:1fr}}
.rcol{border:1px solid var(--line);border-radius:12px;padding:12px 14px;background:var(--card)}
.rcol h3{margin:0;font-size:14px}.rcol .when{color:var(--muted);font-size:12px;margin-bottom:8px}
.rcol ul{list-style:none;margin:0;padding:0;display:grid;gap:7px}.rcol li{font-size:13px;line-height:1.35;display:grid;grid-template-columns:minmax(0,1fr) 5.5rem;gap:8px;align-items:start}
.rcol li .chip{text-align:center;font-size:11.5px;line-height:1.4;padding:2px 6px}
.rcol li a{text-decoration:none;color:var(--ink);font-weight:600}.rcol li .id{color:var(--muted);font-size:12px;margin-right:4px}.rcol li .rt{color:var(--muted);font-size:11.5px;margin-top:1px}
.rcol details summary{cursor:pointer;color:var(--brand2);font-size:12.5px;margin-top:8px}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
table.data{border-collapse:collapse;width:100%;font-size:12.5px;background:var(--card)}
table.data th{background:var(--brand);color:#fff;text-align:left;padding:7px 10px;position:sticky;top:0;white-space:nowrap}
@media (prefers-color-scheme:dark){table.data th{color:#06182b}}
table.data.sortable th{cursor:pointer}table.data th[aria-sort=ascending]:after{content:" \25B2";font-size:10px}table.data th[aria-sort=descending]:after{content:" \25BC";font-size:10px}
table.data td{padding:7px 10px;border-top:1px solid var(--line);vertical-align:top;overflow-wrap:break-word}
table.data td.wide{min-width:260px}
table.data.narrow{max-width:760px}
table.data.st td:first-child{white-space:nowrap}
.found a.go{font-size:12px;margin-left:6px;white-space:nowrap}
table.data tr:hover td{background:var(--soft)}
table.data tr.xrow{display:none}
table.data td.barcell{min-width:150px}.barcell .bar{display:inline-block;width:70px;height:8px;border-radius:5px;background:var(--line);vertical-align:middle;margin-right:8px}.barcell .bar i{display:block;height:8px;border-radius:5px;background:var(--brand2)}
.ev table.data th{position:static}
button.more{margin:8px 0 0;border:1px solid var(--line);background:var(--card);color:var(--brand2);border-radius:8px;padding:4px 12px;font-size:12px;cursor:pointer}
.chipbtn,.tool{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:18px;padding:5px 13px;margin:2px;cursor:pointer;font-size:12.5px;font-weight:600}
.chipbtn.on{background:var(--brand);color:#fff;border-color:var(--brand)}
@media (prefers-color-scheme:dark){.chipbtn.on,nav.top a.on,.fixlist .n,.anum,.verdict .n{color:#06182b}.sev-Critical,.r-Critical{background:#ff9a90;color:#2a0b08}.bd{color:#06182b}.b-atrisk .bd{color:#fff}.b-developing{--bt:var(--warn)}}
.chipbtn span{opacity:.75;font-weight:500;margin-left:3px}.chipbtn.on span{opacity:1}
.filters{display:flex;flex-wrap:wrap;gap:6px 18px;align-items:center;margin:6px 0 14px;padding:12px 14px;background:var(--soft);border-radius:12px}
.filters label{font-size:12px;color:var(--muted);font-weight:600;margin-right:4px}
.filters input,.filters select{padding:6px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink);font-size:13px}.filters input[type=search]{min-width:230px}
details.area,details.marea{border:1px solid var(--line);border-radius:12px;margin:0 0 12px;background:var(--card)}
details.area>summary,details.marea>summary{display:flex;gap:12px;align-items:center;flex-wrap:wrap;cursor:pointer;padding:12px 16px;list-style:none;border-radius:12px}
details.area>summary::-webkit-details-marker,details.marea>summary::-webkit-details-marker{display:none}
details.area>summary:before,details.marea>summary:before{content:"\25B8";color:var(--muted);transition:transform .15s}details.area[open]>summary:before,details.marea[open]>summary:before{transform:rotate(90deg)}
details.area>summary:hover,details.marea>summary:hover{background:var(--soft)}
.anum{display:inline-grid;place-items:center;min-width:26px;height:26px;border-radius:8px;background:var(--brand);color:#fff;font-weight:700;font-size:12.5px}
@media (prefers-color-scheme:dark){.anum{color:#06182b}}
.aname{font-weight:650;font-size:15px}.asum{display:flex;gap:6px;flex-wrap:wrap;margin-left:auto}
.why{margin:0 16px 10px;color:var(--muted);font-size:13px;max-width:1000px}
.areabody{padding:0 16px 14px;display:grid;gap:10px}
.finding{border:1px solid var(--line);border-left:5px solid var(--c-na);border-radius:10px;padding:11px 14px;background:var(--card)}
.finding.st-Fail{border-left-color:var(--c-fail)}.finding.st-Warning{border-left-color:var(--c-warn)}.finding.st-Pass{border-left-color:var(--c-pass)}.finding.st-Info{border-left-color:var(--c-info)}.finding.st-Accepted{border-left-color:var(--c-acc)}
.finding[hidden]{display:none}.finding.flash{animation:fl 1.6s ease}@keyframes fl{0%{box-shadow:0 0 0 4px var(--c-warn)}100%{box-shadow:none}}
.f-top{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.f-top .ft{flex:1;min-width:200px;margin:0;font-size:14.5px}
.fid{font:600 12px/1 ui-monospace,Consolas,monospace;color:var(--muted);background:var(--soft);padding:4px 7px;border-radius:6px}
.ctag{font-size:11px;padding:2px 8px;border-radius:6px;border:1px solid var(--line);color:var(--muted)}.ctag.c-Heuristic{border-color:var(--c-warn);color:var(--warn)}.ctag.c-NotVerified{border-color:var(--c-na)}
a.perma{text-decoration:none;color:var(--muted);font-weight:700;padding:0 4px}a.perma:hover{color:var(--brand2)}
.f-body{display:grid;grid-template-columns:1.1fr 1fr;gap:6px 24px;margin-top:8px}.f-body.one{grid-template-columns:1fr}
@media (max-width:900px){.f-body{grid-template-columns:1fr}}
.lbl{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);font-weight:700;margin-bottom:2px}
.f-body p{margin:0 0 4px}
.f-meta{margin-top:8px;font-size:11.5px;color:var(--muted)}
.finding details{margin-top:8px}.finding summary{cursor:pointer;color:var(--brand2);font-size:12.5px;font-weight:600}
.ctl dl{margin:6px 0 0;display:grid;grid-template-columns:150px 1fr;gap:4px 14px;font-size:12.5px}.ctl dt{color:var(--muted);font-weight:600}.ctl dd{margin:0}
.note{background:var(--warn-bg);border-left:5px solid var(--c-warn);border-radius:8px;padding:10px 14px;margin:0 0 14px;font-size:13px}
.note.info{background:var(--info-bg);border-left-color:var(--c-info)}
.accnote{background:var(--acc-bg);border-left:4px solid var(--c-acc);border-radius:8px;padding:8px 12px;margin:8px 0 0;font-size:12.5px}.accnote b{color:var(--acc)}
.scope ul{margin:0;padding-left:18px;font-size:13px}.scope li{margin:3px 0}
.meter{display:grid;gap:9px}.meter .row{display:grid;grid-template-columns:170px 1fr 70px;gap:10px;align-items:center;font-size:12.5px}.meter .row b{text-align:right}
.mbar{height:10px;border-radius:6px;background:var(--line);overflow:hidden}.mbar i{display:block;height:100%;background:var(--brand2)}
.two{columns:2;column-gap:28px}@media (max-width:900px){.two{columns:1}}
.legendtbl{width:100%;border-collapse:collapse;font-size:13px}.legendtbl td,.legendtbl th{border-top:1px solid var(--line);padding:7px 8px;vertical-align:top;text-align:left}
.diffgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:12px}
.mini{border:1px solid var(--line);border-radius:10px;padding:10px 14px}.mini b{font-size:24px;display:block}.mini span{font-size:12px;color:var(--muted)}
footer.page{color:var(--muted);font-size:12px;text-align:center;padding:10px 0 30px}
.about-body{display:grid;gap:14px}
.learn{display:flex;flex-wrap:wrap;align-items:baseline;gap:4px 12px;margin-top:10px;font-size:12.5px}
.learn .lbl{margin:0}.learn ul{display:flex;flex-wrap:wrap;gap:4px 14px;list-style:none;margin:0;padding:0}
.learn a{color:var(--brand2);font-weight:600;text-decoration:none}.learn a:hover{text-decoration:underline}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.about-id{display:flex;gap:16px;align-items:center}
.avatar{width:64px;height:64px;flex:none;border-radius:50%;background:linear-gradient(135deg,#00264d,#0f6cbd);color:#fff;display:grid;place-items:center;font-weight:700;font-size:22px;letter-spacing:1px}
.about-name{font-size:18px;font-weight:700;color:var(--ink)}
.about-role{color:var(--muted);font-size:13px;margin-bottom:6px}
.about-links{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:13px}
.related{background:var(--soft);border-left:4px solid var(--brand2);border-radius:8px;padding:11px 14px;font-size:12.5px;line-height:1.5;color:var(--ink);text-align:left}.related a{color:var(--brand2);font-weight:600;text-decoration:none}.related a:hover{text-decoration:underline}
.panel p.small a{color:var(--brand2);font-weight:600;text-decoration:none}.panel p.small a:hover{text-decoration:underline}
.alink{display:inline-flex;align-items:center;gap:6px;color:var(--brand2);text-decoration:none;font-weight:600}.alink:hover{text-decoration:underline}
.disclaimer{background:var(--soft);border-left:4px solid var(--brand2);border-radius:8px;padding:11px 14px;font-size:12.5px;line-height:1.5;color:var(--ink);text-align:left}
.aboutcard{max-width:760px;margin:6px auto 16px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px;text-align:left;box-shadow:var(--shadow)}
dialog.about{border:0;border-radius:16px;padding:20px 22px;width:min(560px,calc(100% - 28px));background:var(--card);color:var(--ink);box-shadow:0 20px 60px rgba(0,20,40,.35)}
dialog.about::backdrop{background:rgba(0,20,40,.55)}
.about-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}.about-head h2{margin:0;font-size:17px}
@media print{
nav.top,.filters,button.more,.tool,a.perma{display:none!important}
body{background:#fff;color:#000;font-size:11px}.hero{background:#00264d!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
section.panel{box-shadow:none;break-inside:auto}.finding,.acard,.rcol,.box{break-inside:avoid}
table.data tr.xrow{display:table-row}details.area>summary:before{display:none}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
'@
}

function Get-ReportJs {
    return @'
(function(){
'use strict';
var $=function(s,r){return (r||document).querySelector(s)};
var $$=function(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))};
var links=$$('nav.top a[href^="#"]');
var secs=links.map(function(a){return document.getElementById(a.getAttribute('href').slice(1))}).filter(Boolean);
function onScroll(){var y=window.scrollY+110,cur=secs[0];secs.forEach(function(s){if(s.offsetTop<=y)cur=s});links.forEach(function(a){a.classList.toggle('on',!!cur&&a.getAttribute('href')==='#'+cur.id)})}
window.addEventListener('scroll',onScroll,{passive:true});onScroll();
function applyLimit(t){var lim=parseInt(t.getAttribute('data-limit')||'0',10);if(!lim)return;var open=t.classList.contains('open');$$('tr',t.tBodies[0]).forEach(function(r,i){r.classList.toggle('xrow',!open&&i>=lim)})}
function sortTable(t,i,th){var tb=t.tBodies[0],rows=$$('tr',tb),dir=th.getAttribute('aria-sort')==='ascending'?'descending':'ascending';
$$('th',t).forEach(function(x){x.removeAttribute('aria-sort')});th.setAttribute('aria-sort',dir);
var num=/^-?\d+(\.\d+)?$/;var key=function(r){var c=r.cells[i];if(!c)return '';var v=c.getAttribute('data-v');return v===null?c.textContent.trim():v};
rows.sort(function(a,b){var x=key(a),y=key(b),r;if(num.test(x)&&num.test(y))r=parseFloat(x)-parseFloat(y);else r=x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'});return dir==='ascending'?r:-r});
rows.forEach(function(r){tb.appendChild(r)});applyLimit(t)}
$$('table.sortable').forEach(function(t){$$('th',t).forEach(function(th,i){th.tabIndex=0;th.addEventListener('click',function(){sortTable(t,i,th)});th.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();sortTable(t,i,th)}})})});
$$('button.more').forEach(function(b){b.addEventListener('click',function(){var t=b.previousElementSibling&&b.previousElementSibling.querySelector('table');if(!t)return;var open=t.classList.toggle('open');applyLimit(t);b.textContent=open?'Show fewer':'Show all '+b.getAttribute('data-more')+' '+(b.getAttribute('data-label')||'rows')})});
var state={status:'all',sev:'all',area:'all',owner:'all',q:''};
function applyFilters(){var filtered=state.status!=='all'||state.sev!=='all'||state.area!=='all'||state.owner!=='all'||state.q!=='';
$$('.finding').forEach(function(f){var ok=(state.status==='all'||f.getAttribute('data-status')===state.status)&&(state.sev==='all'||f.getAttribute('data-sev')===state.sev)&&(state.area==='all'||f.getAttribute('data-area')===state.area)&&(state.owner==='all'||f.getAttribute('data-owner')===state.owner)&&(!state.q||f.textContent.toLowerCase().indexOf(state.q)>=0);f.hidden=!ok});
$$('details.area').forEach(function(d){var n=$$('.finding:not([hidden])',d).length;d.hidden=n===0;var c=$('.vis',d);if(c)c.textContent=n;if(filtered&&n>0)d.open=true});
var el=$('#visCount');if(el)el.textContent=$$('.finding:not([hidden])').length+' of '+$$('.finding').length+' findings shown'}
$$('.chipbtn[data-k]').forEach(function(b){b.addEventListener('click',function(){var k=b.getAttribute('data-k');state[k]=b.getAttribute('data-v');$$('.chipbtn[data-k="'+k+'"]').forEach(function(x){x.classList.toggle('on',x===b)});applyFilters()})});
var q=$('#q');if(q)q.addEventListener('input',function(){state.q=q.value.toLowerCase().trim();applyFilters()});
var af=$('#areaFilter');if(af)af.addEventListener('change',function(){state.area=af.value;applyFilters()});
var ex=$('#expandAll');if(ex)ex.addEventListener('click',function(){$$('details.area').forEach(function(d){d.open=true})});
var co=$('#collapseAll');if(co)co.addEventListener('click',function(){$$('details.area').forEach(function(d){d.open=false})});
var rs=$('#resetFilters');if(rs)rs.addEventListener('click',function(){state={status:'all',sev:'all',area:'all',owner:'all',q:''};if(q)q.value='';if(af)af.value='all';$$('.chipbtn[data-k]').forEach(function(x){x.classList.toggle('on',x.getAttribute('data-v')==='all')});applyFilters()});
$$('a.perma').forEach(function(a){a.addEventListener('click',function(e){var url=location.href.split('#')[0]+a.getAttribute('href');if(navigator.clipboard&&navigator.clipboard.writeText){e.preventDefault();navigator.clipboard.writeText(url).then(function(){a.textContent='\u2713';setTimeout(function(){a.textContent='#'},1200)},function(){})}})});
function openTarget(){var h=location.hash.slice(1);if(!h)return;var el=document.getElementById(h);if(!el)return;var d=el.closest('details');while(d){d.open=true;d=d.parentElement?d.parentElement.closest('details'):null}
if(el.hidden){el.hidden=false}el.scrollIntoView({block:'center'});if(el.classList.contains('finding')){el.classList.remove('flash');void el.offsetWidth;el.classList.add('flash')}}
window.addEventListener('hashchange',openTarget);openTarget();
var was=[];window.addEventListener('beforeprint',function(){was=$$('details').map(function(d){return d.open});$$('details').forEach(function(d){d.open=true});$$('table[data-limit]').forEach(function(t){t.classList.add('open');applyLimit(t)})});
window.addEventListener('afterprint',function(){$$('details').forEach(function(d,i){d.open=was[i]});$$('table[data-limit]').forEach(function(t){t.classList.remove('open');applyLimit(t)})});
var ad=$('#aboutDlg'),ab=$('#aboutBtn'),ac=$('#aboutClose');
if(ad&&ab){ab.addEventListener('click',function(){if(ad.showModal)ad.showModal();else ad.setAttribute('open','')});
if(ac)ac.addEventListener('click',function(){if(ad.close)ad.close();else ad.removeAttribute('open')});
ad.addEventListener('click',function(e){if(e.target===ad&&ad.close)ad.close()})}
var pb=$('#printBtn');if(pb)pb.addEventListener('click',function(){window.print()});
$$('table[data-limit]').forEach(applyLimit);applyFilters();
})();
'@
}

function Resolve-OwnerLabel {
    param($Id)
    $s = [string]$Id
    if ($s.Length -eq 36 -and $s -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        $k = $s.ToLower()
        if ($script:OwnerNames.ContainsKey($k)) { return $script:OwnerNames[$k] }
    }
    return $s
}

function ConvertTo-CellText {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { return $(if ($Value) { 'Yes' } else { 'No' }) }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd') }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { return (@($Value | ForEach-Object { ConvertTo-CellText $_ }) -join '; ') }
    $s = ConvertTo-IsoText ([string]$Value)
    if ($s -match '^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}') { return $s.Substring(0, 10) }
    return (Resolve-OwnerLabel $s)
}

function Format-StatusChip {
    param([string]$Status)
    $label = switch ($Status) { 'Unavailable' { 'Not verified' } 'Accepted' { 'Accepted risk' } default { $Status } }
    return "<span class='chip s-$Status'>$(Format-Html $label)</span>"
}

function Format-SeverityChip {
    param([string]$Severity)
    return "<span class='chip sev-$Severity' title='Severity if this is a gap'>$(Format-Html $Severity)</span>"
}

function Format-StackedBar {
    param($Fail, $Warning, $Pass, $Info, $Unavailable, $Accepted = 0)
    $total = [int]$Fail + [int]$Warning + [int]$Pass + [int]$Info + [int]$Unavailable + [int]$Accepted
    if ($total -eq 0) { return "<div class='stack'></div>" }
    $seg = { param($n, $cls, $label) if ([int]$n -gt 0) { "<i class='$cls' style='flex:$([int]$n)' title='$($label): $([int]$n)'></i>" } else { '' } }
    return "<div class='stack' role='img' aria-label='Fail $Fail, warning $Warning, pass $Pass, info $Info, not verified $Unavailable, accepted $Accepted'>$(& $seg $Fail 'fail' 'Fail')$(& $seg $Warning 'warn' 'Warning')$(& $seg $Pass 'pass' 'Pass')$(& $seg $Info 'info' 'Info')$(& $seg $Unavailable 'na' 'Not verified')$(& $seg $Accepted 'acc' 'Accepted risk')</div>"
}

function Format-DonutSvg {
    param($Counts, [int]$Total)
    $r = 52
    $circ = 2 * [math]::PI * $r
    $map = [ordered]@{ Fail = 'var(--c-fail)'; Warning = 'var(--c-warn)'; Pass = 'var(--c-pass)'; Info = 'var(--c-info)'; Unavailable = 'var(--c-na)'; Accepted = 'var(--c-acc)' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<svg class='donut' viewBox='0 0 140 140' role='img' aria-label='Findings by status'><circle cx='70' cy='70' r='$r' fill='none' stroke='var(--line)' stroke-width='18'/>")
    $offset = 0.0
    foreach ($s in $map.Keys) {
        $n = [int]$Counts[$s]
        if ($n -le 0 -or $Total -le 0) { continue }
        $len = [math]::Round($circ * $n / $Total, 2)
        $gap = [math]::Round($circ - $len, 2)
        $off = [math]::Round(-$offset, 2)
        $label = switch ($s) { 'Unavailable' { 'Not verified' } 'Accepted' { 'Accepted risk' } default { $s } }
        [void]$sb.Append("<circle cx='70' cy='70' r='$r' fill='none' stroke='$($map[$s])' stroke-width='18' stroke-dasharray='$len $gap' stroke-dashoffset='$off' transform='rotate(-90 70 70)'><title>$($label): $n</title></circle>")
        $offset += $circ * $n / $Total
    }
    [void]$sb.Append("<text x='70' y='68' text-anchor='middle' class='donut-n'>$Total</text><text x='70' y='85' text-anchor='middle' class='donut-l'>findings</text></svg>")
    return $sb.ToString()
}

# Generic sortable table. Rows are objects; Columns picks and orders properties. BarColumn draws an in-cell bar; ChipColumn renders rating chips.
function Format-HtmlTable {
    param($Rows, [string[]]$Columns, [string]$Class = '', [int]$Limit = 0, [string]$BarColumn = '', [string[]]$ChipColumns = @(), [string[]]$WideColumns = @(), [string]$MoreLabel = 'rows')
    $items = @($Rows | Where-Object { $null -ne $_ })
    if ($items.Count -eq 0) { return '' }
    if (-not $Columns -or $Columns.Count -eq 0) { $Columns = @($items[0].PSObject.Properties.Name) }
    $max = 0.0
    if ($BarColumn) {
        foreach ($r in $items) { $v = 0.0; if ([double]::TryParse([string]$r.$BarColumn, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v) -and $v -gt $max) { $max = $v } }
    }
    $limited = ($Limit -gt 0 -and $items.Count -gt $Limit)
    $lim = if ($limited) { " data-limit='$Limit'" } else { '' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<div class='tablewrap'><table class='data sortable $Class'$lim><thead><tr>")
    foreach ($c in $Columns) { [void]$sb.Append("<th scope='col'>$(Format-Html $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    $i = 0
    foreach ($r in $items) {
        $i++
        $x = if ($limited -and $i -gt $Limit) { " class='xrow'" } else { '' }
        [void]$sb.Append("<tr$x>")
        foreach ($c in $Columns) {
            $raw = $r.$c
            $txt = ConvertTo-CellText $raw
            if ($BarColumn -and $c -eq $BarColumn -and $max -gt 0) {
                $v = 0.0
                [void][double]::TryParse([string]$raw, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v)
                $pct = [int][math]::Round(100 * $v / $max, 0)
                if ($v -gt 0 -and $pct -lt 3) { $pct = 3 }
                [void]$sb.Append("<td class='barcell' data-v='$v'><span class='bar'><i style='width:$pct%'></i></span><b>$(Format-Html $txt)</b></td>")
            }
            elseif ($ChipColumns -contains $c -and $txt) { [void]$sb.Append("<td><span class='chip r-$(Format-Html $txt)'>$(Format-Html $txt)</span></td>") }
            elseif ($WideColumns -contains $c) { [void]$sb.Append("<td class='wide'>$(Format-Html $txt)</td>") }
            else { [void]$sb.Append("<td>$(Format-Html $txt)</td>") }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    if ($limited) { [void]$sb.Append("<button type='button' class='more' data-more='$($items.Count)' data-label='$MoreLabel'>Show all $($items.Count) $MoreLabel</button>") }
    return $sb.ToString()
}

# ------------------------------------------------------------------ Why it is recommended
# One plain sentence per control. First matching rule wins; Title is an optional extra filter.
$WhyRules = @(
    @{ Id = '^1\.3$'; Title = 'welcome content'; Why = 'Welcome content tells new makers where to build, what data is allowed and who to ask, before they create anything.' }
    @{ Id = '^1\.3$'; Why = 'Environment group rules apply governance consistently to every environment in the group instead of one at a time.' }
    @{ Id = '^1\.5$'; Why = 'Time-boxed, owned exceptions keep accepted risk visible and reviewed, so a temporary exemption cannot quietly become a permanent, undocumented one.' }
    @{ Id = '^1\.[67]$'; Why = 'You cannot govern what you cannot see, so a current inventory of apps, flows and agents is the baseline for every other control.' }
    @{ Id = '^2\.1$'; Why = 'Standing admin accounts are the highest-value targets in the tenant, so fewer of them means less damage if one is compromised.' }
    @{ Id = '^2\.2$'; Why = 'Just-in-time activation through PIM limits how long admin rights exist and adds approval, MFA and an audit trail.' }
    @{ Id = '^2\.3$'; Why = 'Tenant settings decide who can create environments, share broadly and share data with Microsoft, so they set the baseline for everything else.' }
    @{ Id = '^2\.4$'; Why = 'Uncontrolled environment creation produces sprawl outside data policies, ownership and monitoring.' }
    @{ Id = '^2\.5$'; Why = 'Without tenant isolation, connectors can move data to and from other tenants outside your control.' }
    @{ Id = '^2\.6$'; Why = 'Advisor already detected these exposures (broad sharing, idle assets, heavily used apps in the default environment), so they are cheap to confirm and fix.' }
    @{ Id = '^3\.1$'; Why = 'Every licensed user can build in the default environment, so unless it is hardened it becomes where shadow apps and data pile up.' }
    @{ Id = '^3\.2$'; Why = 'Knowing every environment, its type and its owner is the starting point for applying the right controls to each one.' }
    @{ Id = '^3\.3$'; Why = 'Build roles in production let people change live apps outside change control; makers should build in development and deploy through pipelines.' }
    @{ Id = '^3\.4$'; Why = 'Managed Environments adds sharing limits, usage insights and solution checks. It is a recommendation, and each customer decides how far to roll it out.' }
    @{ Id = '^3\.5$'; Why = 'Microsoft documents a deprecation for unmanaged developer environments, so ones you want to keep need a plan before the deadline.' }
    @{ Id = '^3\.6$'; Why = 'Environment routing sends new makers to their own governed developer environments instead of the shared default environment.' }
    @{ Id = '^3\.7$'; Why = 'Grouping environments lets you apply rules in bulk and keep production separate from experimentation.' }
    @{ Id = '^3\.8$'; Why = 'A security group limits who can enter a Dataverse environment, so access is intentional rather than tenant-wide.' }
    @{ Id = '^3\.9$'; Why = 'Empty, trial or unhealthy environments use capacity and widen the attack surface without delivering value.' }
    @{ Id = '^4\.2$'; Why = 'Consumer and external-service connectors in the Business group let business data flow to personal or untrusted services.' }
    @{ Id = '^4\.3$'; Why = 'The default group decides how every new connector is treated, and Blocked or Non-business is the safer default.' }
    @{ Id = '^4\.6$'; Title = 'HTTP'; Why = 'The HTTP connector can send data to any endpoint, so block it or limit it to approved endpoints.' }
    @{ Id = '^4\.6$'; Why = 'Custom and third-party connectors reach outside Microsoft services and need review for authentication and ownership.' }
    @{ Id = '^4\.7$'; Why = 'The unauthenticated chat connector lets agents answer anyone who finds them, and blocking it enforces sign-in tenant-wide.' }
    @{ Id = '^4\.8$'; Why = 'Classifying the connectors that agents use controls where agent data and triggers can flow.' }
    @{ Id = '^4\.12$'; Why = 'Desktop flows can touch local apps and data, so data policies should cover them too.' }
    @{ Id = '^4\.'; Why = 'Data policies stop business data from flowing to consumer or untrusted services, and a tenant baseline covers new environments automatically.' }
    @{ Id = '^5\.1$'; Why = 'MFA and Conditional Access protect makers, admins and agent users from stolen or phished credentials.' }
    @{ Id = '^5\.3$'; Why = 'Authentication rules make sure every agent in the group requires users to sign in.' }
    @{ Id = '^5\.4$'; Why = 'Application users with System Administrator hold powerful non-interactive access that is easy to forget and hard to audit.' }
    @{ Id = '^5\.7$'; Title = 'Guest access to Dataverse'; Why = 'Restricting guest access keeps external B2B users out of Dataverse data and apps in that environment, which matters most in production.' }
    @{ Id = '^5\.7$'; Why = 'Guest users can reach business data, so each one should be intentional and reviewed.' }
    @{ Id = '^5\.8$'; Why = 'Assets owned by deleted or disabled people have no one accountable and often keep running with stale connections.' }
    @{ Id = '^6\.1$'; Why = 'Many System Administrators means many people who can read all data and change security, so least privilege reduces risk.' }
    @{ Id = '^6\.4$'; Why = 'Auditing is the evidence trail for who accessed or changed data, and it has to be on before an incident happens.' }
    @{ Id = '^6\.5$'; Title = 'Bot Transcript Viewer'; Why = 'Holders of this role can read conversation transcripts, which can contain personal data, so the group should stay small and reviewed.' }
    @{ Id = '^6\.5$'; Why = 'Conversation transcripts can hold personal data, so retention and access should be limited to what the business needs.' }
    @{ Id = '^6\.6$'; Title = 'IP firewall'; Why = 'The IP firewall rejects Dataverse requests, and replayed tokens, that come from outside the IP ranges you approve.' }
    @{ Id = '^6\.6$'; Title = 'cookie binding'; Why = 'Binding the session cookie to the sign-in IP address stops a stolen cookie from being replayed from another network.' }
    @{ Id = '^6\.6$'; Title = 'Content security policy'; Why = 'A content security policy limits what scripts, frames and connections apps can use, which reduces cross-site scripting and clickjacking risk.' }
    @{ Id = '^6\.6$'; Title = 'Session'; Why = 'Session and inactivity timeouts limit how long an unattended or hijacked session stays usable.' }
    @{ Id = '^6\.6$'; Why = 'These environment settings narrow who can reach Dataverse and for how long, which limits the damage from stolen credentials or sessions.' }
    @{ Id = '^6\.7$'; Why = 'Virtual network injection keeps Dataverse and connector traffic on your private network.' }
    @{ Id = '^6\.8$'; Why = 'Customer-managed keys give you control over the encryption keys protecting regulated data.' }
    @{ Id = '^6\.9$'; Why = 'Longer backup retention gives you more recovery options after accidental deletion or corruption of production data.' }
    @{ Id = '^7\.1$'; Title = 'default environment'; Why = 'Sharing limits keep apps in the default environment from spreading across the tenant without review.' }
    @{ Id = '^7\.1$'; Title = 'solution checker'; Why = 'Managed Environments add sharing limits and solution checker enforcement, which control what makers can share and what reaches production.' }
    @{ Id = '^7\.[12]$'; Why = 'Sharing with Everyone exposes apps and connections to the whole organization, including guests where allowed.' }
    @{ Id = '^7\.4$'; Why = 'Unowned or long-unchanged apps keep live connections and access without anyone maintaining them.' }
    @{ Id = '^7\.5$'; Why = 'Code apps run custom code outside the low-code guardrails, so they need review and an allow-list.' }
    @{ Id = '^7\.6$'; Title = 'enforcement'; Why = 'Enforcement turns solution checker from advice into a gate, so risky solutions are caught on import instead of in production.' }
    @{ Id = '^7\.6$'; Why = 'Solution checker finds security and quality issues before solutions reach production.' }
    @{ Id = '^7\.9$'; Why = 'Anonymous Power Pages sites are exposed to the internet, so site visibility and table permissions must be deliberate.' }
    @{ Id = '^8\.1$'; Title = 'Orphaned'; Why = 'Flows owned by deleted or disabled accounts can fail or keep running with no one accountable.' }
    @{ Id = '^8\.1$'; Title = 'rule'; Why = 'Flow rules in the environment group apply the same automation limits to every environment in it.' }
    @{ Id = '^8\.1$'; Why = 'Business-critical flows in the default environment lack ownership, isolation and lifecycle control.' }
    @{ Id = '^8\.2$'; Why = 'A flow started by an HTTP request can be called by anyone who has the URL, so access and input need to be restricted.' }
    @{ Id = '^8\.3$'; Why = 'Secrets stored in flow definitions can be read by anyone with access to the flow and are hard to rotate.' }
    @{ Id = '^8\.6$'; Why = 'Flows and apps that send data to external services can move business data outside approved boundaries.' }
    @{ Id = '^8\.8$'; Why = 'A suspended flow usually means repeated failures, so the process it automates is silently not running.' }
    @{ Id = '^9\.1$'; Title = 'multitenant'; Why = 'An agent open to other Microsoft Entra tenants can be used by people outside your organization, so each one should be a deliberate choice.' }
    @{ Id = '^9\.1$'; Title = 'sign.in'; Why = 'When sign-in waits until a topic asks for it, anyone can start a conversation, so agents that reach sensitive data should require sign-in first.' }
    @{ Id = '^9\.1$'; Why = 'Agents without authentication answer anyone, so they must not be able to reach internal knowledge or actions.' }
    @{ Id = '^9\.[23]$'; Why = 'Open and website channels expose agents to the internet, where an unauthenticated agent can leak data or be abused.' }
    @{ Id = '^9\.4$'; Title = 'sharing limits'; Why = 'Sharing limits control how widely an agent spreads and whether owners can add editors without an admin.' }
    @{ Id = '^9\.4$'; Why = 'Sharing an agent tenant-wide puts it in front of every user, guests included.' }
    @{ Id = '^9\.6$'; Why = 'Environment group rules for Copilot settings enforce one standard for agent behavior.' }
    @{ Id = '^9\.7$'; Title = 'secret'; Why = 'Secrets written into agent topics can be read by anyone who can edit or export the agent and are hard to rotate.' }
    @{ Id = '^9\.7$'; Why = 'HTTP requests from topics send data to external endpoints that data policies may not govern.' }
    @{ Id = '^9\.9$'; Why = 'Drafts, stale publishes and orphaned agents are unmanaged risk, so retire or reassign them.' }
    @{ Id = '^10\.4$'; Why = 'SharePoint knowledge without user authentication can expose internal content to anonymous users.' }
    @{ Id = '^10\.5$'; Why = 'Public websites and web search let agents answer from content nobody on your side has vetted.' }
    @{ Id = '^10\.8$'; Why = 'Allowing general model knowledge can produce answers that are not grounded in your approved content.' }
    @{ Id = '^10\.'; Why = 'Knowledge sources decide what an agent can reveal, so each one should be approved and access-controlled.' }
    @{ Id = '^11\.2$'; Title = 'Computer use'; Why = 'Computer use with stored credentials or shared machines can act with broad rights on desktops.' }
    @{ Id = '^11\.2$'; Why = 'A tool that runs as the maker gives every user of the agent the maker''s access, which breaks least privilege.' }
    @{ Id = '^11\.3$'; Why = 'Write-like actions that run as the maker or without user consent can change data without the user approving it.' }
    @{ Id = '^11\.4$'; Why = 'Autonomous agents act without a person present, so they need a reviewed identity, limits and monitoring.' }
    @{ Id = '^11\.5$'; Why = 'MCP servers and external agents extend an agent''s reach into systems you may not control.' }
    @{ Id = '^11\.8$'; Why = 'Connected agents and skills pass data between agents, so each hop needs to be trusted.' }
    @{ Id = '^11\.'; Why = 'Tools let an agent take actions, so credential mode, scope and approval decide how much damage a bad prompt can do.' }
    @{ Id = '^12\.'; Why = 'Weaker content moderation raises the chance of harmful or off-topic responses.' }
    @{ Id = '^13\.'; Why = 'Managed solutions deployed through pipelines give repeatable, reviewable releases instead of untracked changes in production.' }
    @{ Id = '^14\.1$'; Why = 'Conversation audit logging records what agents said and did, which investigations and compliance reviews depend on.' }
    @{ Id = '^14\.3$'; Why = 'The weekly admin digest keeps new risks in front of admins without anyone having to go looking.' }
    @{ Id = '^14\.8$'; Why = 'Tracking these indicators over time shows whether governance is improving.' }
    @{ Id = '^15\.3$'; Why = 'Running out of Dataverse capacity blocks new data and can stop apps from working.' }
    @{ Id = '^15\.'; Why = 'Credit boundaries stop one agent or environment from draining the shared pool or causing unexpected cost.' }
    @{ Id = '^16\.1$'; Title = 'sharing'; Why = 'Sharing data with Microsoft for AI features is optional and should be a deliberate decision.' }
    @{ Id = '^16\.1$'; Title = 'CrossGeo'; Why = 'Cross-geography data movement for AI features can conflict with data-residency requirements.' }
    @{ Id = '^16\.1$'; Why = 'Where data is stored and processed affects privacy and data-residency obligations.' }
    @{ Id = '^16\.6$'; Why = 'Agents that use consumer or external connectors can send business data outside the organization.' }
    @{ Id = '^17\.6$'; Why = 'Deprecated connectors lose support, which eventually breaks the apps and flows that depend on them.' }
    @{ Id = '^17\.7$'; Title = 'rule'; Why = 'Lifecycle rules keep environments and assets from lingering after they stop being used.' }
    @{ Id = '^17\.7$'; Why = 'Quarantine lets you isolate a risky app, flow or agent quickly while you investigate.' }
    @{ Id = '^18\.[67]$'; Why = 'Credit consumption shows which agents cost money and which are idle but still exposed.' }
    @{ Id = '^18\.'; Why = 'Usage shows where risk and value meet: heavily used assets deserve stronger controls, and unused ones are risk with no benefit.' }
)

function Get-WhyText {
    param($F)
    foreach ($r in $WhyRules) {
        if ([string]$F.Id -notmatch $r.Id) { continue }
        if ($r.ContainsKey('Title') -and [string]$F.Title -notmatch $r.Title) { continue }
        return [string]$r.Why
    }
    $cl = $script:Checklist[[string]$F.Id]
    if ($cl -and $cl.PSObject.Properties['Why'] -and $cl.Why) { return [string]$cl.Why }
    if ($TopicWhy.ContainsKey([int]$F.Topic)) { return (Get-FirstSentence ([string]$TopicWhy[[int]$F.Topic]) 220) }
    return ''
}

# ------------------------------------------------------------------ Microsoft Learn references
# Every URL below was checked and returned HTTP 200 on learn.microsoft.com when this list was written.
$LearnRoot = 'https://learn.microsoft.com/en-us/'
$Learn = @{
    AdminBP        = @('Power Platform governance overview and strategy', 'power-platform/guidance/adoption/admin-best-practices')
    GovernScale    = @('Manage Power Platform adoption at scale', 'power-platform/guidance/adoption/govern-at-scale')
    AdminRoles     = @('Use service admin roles to manage your tenant', 'power-platform/admin/use-service-admin-role-manage-tenant')
    PIM            = @('Use Entra Privileged Identity Management in the admin center', 'power-platform/admin/manage-high-privileged-admin-roles')
    EntraRoleBP    = @('Best practices for Microsoft Entra roles', 'entra/identity/role-based-access-control/best-practices')
    CA             = @('Microsoft Entra Conditional Access overview', 'entra/identity/conditional-access/overview')
    CATemplates    = @('Conditional Access templates', 'entra/identity/conditional-access/concept-conditional-access-policy-common')
    TenantSettings = @('Tenant settings', 'power-platform/admin/tenant-settings')
    CrossTenant    = @('Restrict cross-tenant inbound and outbound access', 'power-platform/admin/cross-tenant-restrictions')
    Advisor        = @('Actions overview (Advisor recommendations)', 'power-platform/admin/power-platform-advisor')
    Inventory      = @('Power Platform inventory', 'power-platform/admin/power-platform-inventory')
    InventoryApi   = @('Power Platform inventory API', 'power-platform/admin/inventory-api')
    EnvOverview    = @('Power Platform environments overview', 'power-platform/admin/environments-overview')
    EnvStrategy    = @('Develop a tenant environment strategy', 'power-platform/guidance/adoption/environment-strategy')
    SecureDefault  = @('Secure the default environment', 'power-platform/guidance/adoption/secure-default-environment')
    EnvCreate      = @('Control who can create and manage environments', 'power-platform/admin/control-environment-creation')
    EnvGroups      = @('Environment groups', 'power-platform/admin/environment-groups')
    EnvGroupRules  = @('Rules for environment groups', 'power-platform/admin/environment-groups-rules')
    Routing        = @('Environment routing', 'power-platform/admin/default-environment-routing')
    ManagedOverview = @('Managed Environments overview', 'power-platform/admin/managed-environment-overview')
    ManagedEnable  = @('Enable Managed Environments', 'power-platform/admin/managed-environment-enable')
    SharingLimits  = @('Limit sharing in Managed Environments', 'power-platform/admin/managed-environment-sharing-limits')
    UsageInsights  = @('Usage insights', 'power-platform/admin/managed-environment-usage-insights')
    SolutionChecker = @('Solution checker enforcement', 'power-platform/admin/managed-environment-solution-checker')
    DLP            = @('Data policies', 'power-platform/admin/wp-data-loss-prevention')
    DlpStrategy    = @('Implement a data policy strategy', 'power-platform/guidance/adoption/dlp-strategy')
    ConnClass      = @('Connector classification', 'power-platform/admin/dlp-connector-classification')
    CustomConn     = @('Data policies for custom connectors', 'power-platform/admin/dlp-custom-connector-parity')
    EndpointFilter = @('Connector endpoint filtering', 'power-platform/admin/connector-endpoint-filtering')
    SecOverview    = @('Power Platform security overview', 'power-platform/admin/security/security-overview')
    SecRoles       = @('Security roles for Dataverse', 'power-platform/admin/database-security')
    Auditing       = @('Manage Dataverse auditing', 'power-platform/admin/manage-dataverse-auditing')
    AdminLogs      = @('View admin activity logs in Microsoft Purview', 'power-platform/admin/activity-logging-auditing/activity-logs-power-platform-admin')
    CMK            = @('Manage your customer-managed encryption key', 'power-platform/admin/customer-managed-key')
    VNet           = @('Azure Virtual Network support', 'power-platform/admin/vnet-support-overview')
    Backup         = @('Back up and restore environments', 'power-platform/admin/backup-restore-environments')
    Capacity       = @('Dataverse capacity-based storage', 'power-platform/admin/capacity-storage')
    Regions        = @('Choose the region when setting up an environment', 'power-platform/admin/regions-overview')
    DataShare      = @('FAQ: optional data sharing for Copilot AI features', 'power-platform/faqs-copilot-data-sharing')
    CopilotRegions = @('Move data across regions for Copilots and AI agents', 'power-platform/admin/geographical-availability-copilot')
    ALM            = @('Solution concepts for ALM', 'power-platform/alm/solution-concepts-alm')
    Pipelines      = @('Pipelines in Power Platform', 'power-platform/alm/pipelines')
    ShareApp       = @('Share a canvas app', 'power-apps/maker/canvas-apps/share-app')
    CodeApps       = @('Power Apps code apps', 'power-apps/developer/code-apps/overview')
    PagesSecurity  = @('Power Pages security', 'power-pages/security/power-pages-security')
    SiteVisibility = @('Site visibility in Power Pages', 'power-pages/security/site-visibility')
    PagesBP        = @('Power Pages security best practices', 'power-pages/security/security-best-practices')
    PagesAdmin     = @('Manage website security from the admin center', 'power-pages/admin/admin-center-security')
    HttpAuth       = @('Add OAuth authentication for HTTP request triggers', 'power-automate/oauth-authentication')
    SecureInputs   = @('Secure data used in cloud flows', 'power-automate/guidance/coding-guidelines/use-secure-inputs-outputs-triggers')
    FlowLimits     = @('Limits of automated, scheduled, and instant flows', 'power-automate/limits-and-config')
    KeyVaultEnv    = @('Environment variables for Azure Key Vault secrets', 'power-apps/maker/data-platform/environmentvariables-azure-key-vault-secrets')
    Secrets        = @('Recommendations for protecting application secrets', 'power-platform/well-architected/security/application-secrets')
    CSSecurity     = @('Copilot Studio security and governance', 'microsoft-copilot-studio/security-and-governance')
    CSGuidance     = @('Manage your Copilot Studio projects', 'microsoft-copilot-studio/guidance/sec-gov-intro')
    CSAuth         = @('Configure user authentication', 'microsoft-copilot-studio/configuration-end-user-authentication')
    CSWeb          = @('Configure web and Direct Line channel security', 'microsoft-copilot-studio/configure-web-security')
    CSChannels     = @('Publish and deploy your agent: key concepts', 'microsoft-copilot-studio/publication-fundamentals-publish-channels')
    CSDlp          = @('Configure data policies for agents', 'microsoft-copilot-studio/admin-data-loss-prevention')
    CSShare        = @('Share agents with other users', 'microsoft-copilot-studio/admin-share-bots')
    CSKnowledge    = @('Knowledge sources summary', 'microsoft-copilot-studio/knowledge-copilot-studio')
    CSSharePoint   = @('Add SharePoint as a knowledge source', 'microsoft-copilot-studio/knowledge-add-sharepoint')
    CSPublicWeb    = @('Add a public website as a knowledge source', 'microsoft-copilot-studio/knowledge-add-public-website')
    CSGenAnswers   = @('FAQ for generative answers', 'microsoft-copilot-studio/faqs-generative-answers')
    CSTools        = @('Add tools to custom agents', 'microsoft-copilot-studio/add-tools-custom-agent')
    CSMcp          = @('Connect an agent to an MCP server', 'microsoft-copilot-studio/mcp-add-existing-server-to-agent')
    CSComputerUse  = @('Computer use in Copilot Studio', 'microsoft-copilot-studio/computer-use')
    CSTriggers     = @('Event trigger overview', 'microsoft-copilot-studio/authoring-triggers-about')
    CSOtherAgents  = @('Add other agents overview', 'microsoft-copilot-studio/authoring-add-other-agents')
    CSQuarantine   = @('Quarantine agents with the Power Platform API', 'microsoft-copilot-studio/admin-api-quarantine')
    CSTranscripts  = @('Control transcript access and retention', 'microsoft-copilot-studio/admin-transcript-controls')
    CSAnalytics    = @('Monitor agent performance', 'microsoft-copilot-studio/analytics-overview')
    CSSolutions    = @('Create and manage custom solutions', 'microsoft-copilot-studio/authoring-solutions-overview')
    CSCredits      = @('Manage Copilot Credits and capacity', 'power-platform/admin/manage-copilot-studio-copilot-credits-capacity')
    CSBilling      = @('Billing rates and management', 'microsoft-copilot-studio/requirements-messages-management')
    CSGovernCredit = @('Govern Copilot Credit consumption', 'microsoft-copilot-studio/guidance/govern-credit-consumption')
    CSDataMove     = @('Configure data movement across geographic locations', 'microsoft-copilot-studio/manage-data-movement-outside-us')
    IpFirewall     = @('IP firewall in Power Platform environments', 'power-platform/admin/ip-firewall')
    CookieBinding  = @('Safeguard Dataverse sessions with IP cookie binding', 'power-platform/admin/block-cookie-replay-attack')
    GuestAccess    = @('Control guest access in Power Platform environments', 'power-platform/admin/security/guest-access')
    CSP            = @('Content security policy', 'power-platform/admin/content-security-policy')
    SessionMgmt    = @('Security enhancements for user sessions and access management', 'power-platform/admin/user-session-management')
    PrivacySecurity = @('Manage privacy and security settings', 'power-platform/admin/settings-privacy-security')
    IdentityAccess = @('Identity and access management', 'power-platform/admin/security/identity-access-management')
    ReactiveGov    = @('Implement reactive governance controls', 'power-platform/guidance/adoption/reactive-governance')
    WelcomeContent = @('Maker welcome content', 'power-platform/admin/welcome-content')
    CSMultitenant  = @('Multitenant mode in Copilot Studio (preview)', 'microsoft-copilot-studio/multi-tenant-overview')
}

# First matching rule wins (checked in order); Title is an optional extra filter. Topic defaults fill up to three links.
$LearnRules = @(
    @{ Id = '^1\.3$'; Title = 'welcome content'; Links = 'WelcomeContent', 'ReactiveGov', 'EnvGroupRules' }
    @{ Id = '^1\.3$'; Links = 'EnvGroupRules', 'EnvGroups' }
    @{ Id = '^1\.5$'; Links = 'GovernScale', 'AdminBP' }
    @{ Id = '^1\.[67]$'; Links = 'Inventory', 'InventoryApi', 'CSGuidance' }
    @{ Id = '^2\.[12]$'; Links = 'AdminRoles', 'PIM', 'EntraRoleBP' }
    @{ Id = '^2\.3$'; Links = 'TenantSettings', 'AdminBP' }
    @{ Id = '^2\.4$'; Links = 'EnvCreate', 'TenantSettings', 'EnvStrategy' }
    @{ Id = '^2\.5$'; Links = 'CrossTenant', 'TenantSettings' }
    @{ Id = '^2\.6$'; Links = 'Advisor', 'ManagedOverview' }
    @{ Id = '^3\.1$'; Links = 'SecureDefault', 'EnvStrategy', 'Routing' }
    @{ Id = '^3\.2$'; Links = 'EnvOverview', 'Inventory' }
    @{ Id = '^3\.3$'; Links = 'SecRoles', 'ALM', 'Pipelines' }
    @{ Id = '^3\.[45]$'; Links = 'ManagedOverview', 'ManagedEnable', 'EnvStrategy' }
    @{ Id = '^3\.6$'; Links = 'Routing', 'SecureDefault' }
    @{ Id = '^3\.7$'; Links = 'EnvGroups', 'EnvGroupRules' }
    @{ Id = '^3\.[89]$'; Links = 'EnvOverview', 'EnvCreate', 'EnvStrategy' }
    @{ Id = '^4\.6$'; Title = 'HTTP'; Links = 'EndpointFilter', 'DLP', 'ConnClass' }
    @{ Id = '^4\.6$'; Links = 'CustomConn', 'ConnClass', 'DLP' }
    @{ Id = '^4\.[78]$'; Links = 'CSDlp', 'ConnClass', 'DLP' }
    @{ Id = '^4\.'; Links = 'DLP', 'DlpStrategy', 'ConnClass' }
    @{ Id = '^5\.1$'; Links = 'CA', 'CATemplates', 'SecOverview' }
    @{ Id = '^5\.3$'; Links = 'EnvGroupRules', 'CSAuth' }
    @{ Id = '^5\.8$'; Links = 'Inventory', 'InventoryApi', 'CSQuarantine' }
    @{ Id = '^5\.7$'; Title = 'Guest access to Dataverse'; Links = 'GuestAccess', 'IdentityAccess' }
    @{ Id = '^5\.[47]$'; Links = 'SecOverview', 'SecRoles' }
    @{ Id = '^6\.1$'; Links = 'SecRoles', 'SecOverview' }
    @{ Id = '^6\.4$'; Links = 'Auditing', 'AdminLogs' }
    @{ Id = '^6\.5$'; Links = 'CSTranscripts', 'SecRoles' }
    @{ Id = '^6\.6$'; Title = 'IP firewall'; Links = 'IpFirewall', 'IdentityAccess', 'ManagedOverview' }
    @{ Id = '^6\.6$'; Title = 'cookie binding'; Links = 'CookieBinding', 'IdentityAccess', 'ManagedOverview' }
    @{ Id = '^6\.6$'; Title = 'Content security policy'; Links = 'CSP', 'PrivacySecurity' }
    @{ Id = '^6\.6$'; Title = 'Session'; Links = 'SessionMgmt', 'PrivacySecurity' }
    @{ Id = '^6\.6$'; Links = 'PrivacySecurity', 'IdentityAccess' }
    @{ Id = '^6\.7$'; Links = 'VNet', 'SecOverview' }
    @{ Id = '^6\.8$'; Links = 'CMK', 'SecOverview' }
    @{ Id = '^6\.9$'; Links = 'Backup', 'EnvOverview' }
    @{ Id = '^7\.1$'; Title = 'default environment'; Links = 'SharingLimits', 'SecureDefault', 'ReactiveGov' }
    @{ Id = '^7\.1$'; Title = 'solution checker'; Links = 'ManagedOverview', 'SharingLimits', 'SolutionChecker' }
    @{ Id = '^7\.[12]$'; Links = 'SharingLimits', 'ShareApp', 'EnvGroupRules' }
    @{ Id = '^7\.4$'; Links = 'Inventory', 'UsageInsights', 'ManagedOverview' }
    @{ Id = '^7\.5$'; Links = 'CodeApps', 'ManagedOverview' }
    @{ Id = '^7\.6$'; Title = 'enforcement'; Links = 'SolutionChecker', 'ReactiveGov', 'ALM' }
    @{ Id = '^7\.6$'; Links = 'SolutionChecker', 'ALM', 'EnvGroupRules' }
    @{ Id = '^7\.9$'; Links = 'PagesSecurity', 'SiteVisibility', 'PagesBP' }
    @{ Id = '^8\.1$'; Title = 'default environment'; Links = 'SecureDefault', 'EnvStrategy' }
    @{ Id = '^8\.1$'; Title = 'rule'; Links = 'EnvGroupRules', 'EnvGroups' }
    @{ Id = '^8\.1$'; Links = 'Inventory', 'SecureDefault' }
    @{ Id = '^8\.2$'; Links = 'HttpAuth', 'SecureInputs' }
    @{ Id = '^8\.3$'; Links = 'KeyVaultEnv', 'Secrets', 'SecureInputs' }
    @{ Id = '^8\.6$'; Links = 'DlpStrategy', 'EndpointFilter', 'ConnClass' }
    @{ Id = '^8\.8$'; Links = 'FlowLimits', 'Advisor' }
    @{ Id = '^8\.'; Links = 'SecureInputs', 'DLP' }
    @{ Id = '^9\.1$'; Title = 'multitenant'; Links = 'CSMultitenant', 'CrossTenant', 'CSAuth' }
    @{ Id = '^9\.1$'; Links = 'CSAuth', 'CSSecurity' }
    @{ Id = '^9\.[23]$'; Links = 'CSChannels', 'CSWeb', 'CSAuth' }
    @{ Id = '^9\.4$'; Title = 'sharing limits'; Links = 'SharingLimits', 'CSShare', 'SecureDefault' }
    @{ Id = '^9\.4$'; Links = 'CSShare', 'CSSecurity' }
    @{ Id = '^9\.6$'; Links = 'EnvGroupRules', 'CSSecurity' }
    @{ Id = '^9\.7$'; Title = 'secret'; Links = 'KeyVaultEnv', 'Secrets', 'CSSecurity' }
    @{ Id = '^9\.7$'; Links = 'CSDlp', 'EndpointFilter', 'CSSecurity' }
    @{ Id = '^9\.9$'; Title = 'Orphaned'; Links = 'Inventory', 'CSQuarantine' }
    @{ Id = '^9\.9$'; Links = 'CSQuarantine', 'CSSolutions', 'CSSecurity' }
    @{ Id = '^10\.4$'; Links = 'CSSharePoint', 'CSAuth', 'CSKnowledge' }
    @{ Id = '^10\.5$'; Links = 'CSPublicWeb', 'CSKnowledge' }
    @{ Id = '^10\.8$'; Links = 'CSGenAnswers', 'CSKnowledge' }
    @{ Id = '^10\.'; Links = 'CSKnowledge', 'CSSecurity' }
    @{ Id = '^11\.2$'; Title = 'Computer use'; Links = 'CSComputerUse', 'CSTools' }
    @{ Id = '^11\.4$'; Links = 'CSTriggers', 'CSTools', 'CSSecurity' }
    @{ Id = '^11\.5$'; Links = 'CSMcp', 'CSOtherAgents', 'CSTools' }
    @{ Id = '^11\.8$'; Links = 'CSOtherAgents', 'CSTools', 'CSSecurity' }
    @{ Id = '^11\.'; Links = 'CSTools', 'CSDlp', 'CSSecurity' }
    @{ Id = '^12\.'; Links = 'CSGenAnswers', 'CSSecurity' }
    @{ Id = '^13\.1$'; Title = 'Agents'; Links = 'CSSolutions', 'ALM' }
    @{ Id = '^13\.'; Links = 'ALM', 'Pipelines', 'CSSolutions' }
    @{ Id = '^14\.1$'; Links = 'AdminLogs', 'CSTranscripts', 'CSAnalytics' }
    @{ Id = '^14\.3$'; Links = 'TenantSettings', 'EnvGroupRules' }
    @{ Id = '^14\.8$'; Links = 'GovernScale', 'AdminBP' }
    @{ Id = '^15\.3$'; Links = 'Capacity', 'TenantSettings' }
    @{ Id = '^15\.'; Links = 'CSCredits', 'CSGovernCredit', 'CSBilling' }
    @{ Id = '^16\.1$'; Title = 'sharing'; Links = 'DataShare', 'CopilotRegions' }
    @{ Id = '^16\.1$'; Title = 'CrossGeo'; Links = 'CopilotRegions', 'CSDataMove', 'EnvGroupRules' }
    @{ Id = '^16\.1$'; Links = 'Regions', 'CopilotRegions', 'CSDataMove' }
    @{ Id = '^16\.6$'; Links = 'ConnClass', 'DLP', 'DlpStrategy' }
    @{ Id = '^17\.6$'; Links = 'ConnClass', 'DLP' }
    @{ Id = '^17\.7$'; Title = 'rule'; Links = 'EnvGroupRules', 'EnvGroups' }
    @{ Id = '^17\.7$'; Links = 'CSQuarantine', 'Inventory' }
    @{ Id = '^18\.[67]$'; Links = 'CSCredits', 'CSAnalytics', 'CSGovernCredit' }
    @{ Id = '^18\.'; Links = 'Advisor', 'UsageInsights', 'Inventory' }
)

$LearnTopicDefaults = @{
    1 = 'AdminBP', 'GovernScale'; 2 = 'AdminRoles', 'TenantSettings'; 3 = 'EnvOverview', 'ManagedOverview'; 4 = 'DLP', 'DlpStrategy'
    5 = 'CA', 'SecOverview'; 6 = 'SecRoles', 'Auditing'; 7 = 'SharingLimits', 'PagesSecurity'; 8 = 'SecureInputs', 'DLP'
    9 = 'CSSecurity', 'CSAuth'; 10 = 'CSKnowledge', 'CSSecurity'; 11 = 'CSTools', 'CSSecurity'; 12 = 'CSSecurity', 'CSGenAnswers'
    13 = 'ALM', 'Pipelines'; 14 = 'AdminLogs', 'CSAnalytics'; 15 = 'Capacity', 'CSCredits'; 16 = 'Regions', 'SecOverview'
    17 = 'EnvOverview', 'CSQuarantine'; 18 = 'Advisor', 'UsageInsights'
}

function Get-LearnLinks {
    param($F, [int]$Max = 3)
    $keys = New-Object System.Collections.ArrayList
    foreach ($r in $LearnRules) {
        if ([string]$F.Id -notmatch $r.Id) { continue }
        if ($r.ContainsKey('Title') -and [string]$F.Title -notmatch $r.Title) { continue }
        foreach ($k in $r.Links) { if (-not $keys.Contains($k)) { [void]$keys.Add($k) } }
        break
    }
    if ($keys.Count -lt 2 -and $LearnTopicDefaults.ContainsKey([int]$F.Topic)) {
        foreach ($k in $LearnTopicDefaults[[int]$F.Topic]) { if (-not $keys.Contains($k)) { [void]$keys.Add($k) } }
    }
    return @($keys | Where-Object { $Learn.ContainsKey($_) } | Select-Object -First $Max | ForEach-Object {
            [pscustomobject]@{ Title = $Learn[$_][0]; Url = $LearnRoot + $Learn[$_][1] }
        })
}

# ------------------------------------------------------------------ Owner routing: who fixes it and how much work it is
# Every finding gets a suggested role and an effort level, so the report can be handed to the people who act on it.
# Effort is one of: Quick win (a setting), Policy or process change, Project.
# First matching rule wins; Title is an optional extra filter, so Title-specific rules come before the generic rule for the same Id.
$OwnerRoles = @('Power Platform admin', 'Entra / identity admin', 'Security and compliance', 'Environment admin', 'Maker or asset owner', 'Governance lead')
$OwnerRules = @(
    @{ Id = '.'; Title = '^Check failed'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '.'; Title = '^Environment group rule:'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '.'; Title = '^Orphaned '; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^1\.3$'; Title = 'welcome content'; Role = 'Governance lead'; Effort = 'Policy or process change' }
    @{ Id = '^1\.3$'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^1\.[67]$'; Role = 'Governance lead'; Effort = 'Policy or process change' }
    @{ Id = '^2\.[12]$'; Role = 'Entra / identity admin'; Effort = 'Policy or process change' }
    @{ Id = '^2\.3$'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^2\.4$'; Title = 'created by non-admins'; Role = 'Governance lead'; Effort = 'Policy or process change' }
    @{ Id = '^2\.4$'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^2\.5$'; Title = 'Cross-tenant'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^2\.5$'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^2\.6$'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^3\.1$'; Title = 'renamed'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^3\.1$'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^3\.2$'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^3\.3$'; Role = 'Environment admin'; Effort = 'Policy or process change' }
    @{ Id = '^3\.4$'; Role = 'Power Platform admin'; Effort = 'Project' }
    @{ Id = '^3\.5$'; Role = 'Environment admin'; Effort = 'Policy or process change' }
    @{ Id = '^3\.6$'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^3\.7$'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^3\.8$'; Role = 'Environment admin'; Effort = 'Quick win' }
    @{ Id = '^3\.9$'; Role = 'Environment admin'; Effort = 'Policy or process change' }
    @{ Id = '^4\.(3|7|12)$'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^4\.6$'; Title = 'HTTP'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^4\.'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^5\.1$'; Role = 'Entra / identity admin'; Effort = 'Policy or process change' }
    @{ Id = '^5\.3$'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^5\.4$'; Role = 'Environment admin'; Effort = 'Policy or process change' }
    @{ Id = '^5\.7$'; Title = 'Guests cannot create'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^5\.7$'; Title = 'Guest users present'; Role = 'Environment admin'; Effort = 'Policy or process change' }
    @{ Id = '^5\.7$'; Role = 'Environment admin'; Effort = 'Quick win' }
    @{ Id = '^5\.8$'; Title = 'Owner lookup'; Role = 'Entra / identity admin'; Effort = 'Quick win' }
    @{ Id = '^5\.8$'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^6\.1$'; Role = 'Environment admin'; Effort = 'Policy or process change' }
    @{ Id = '^6\.4$'; Title = 'Dataverse checks'; Role = 'Environment admin'; Effort = 'Quick win' }
    @{ Id = '^6\.4$'; Role = 'Security and compliance'; Effort = 'Quick win' }
    @{ Id = '^6\.5$'; Title = 'Who can read'; Role = 'Environment admin'; Effort = 'Policy or process change' }
    @{ Id = '^6\.5$'; Role = 'Security and compliance'; Effort = 'Policy or process change' }
    @{ Id = '^6\.6$'; Title = 'IP firewall'; Role = 'Environment admin'; Effort = 'Policy or process change' }
    @{ Id = '^6\.6$'; Role = 'Environment admin'; Effort = 'Quick win' }
    @{ Id = '^6\.7$'; Role = 'Power Platform admin'; Effort = 'Project' }
    @{ Id = '^6\.8$'; Role = 'Security and compliance'; Effort = 'Project' }
    @{ Id = '^6\.9$'; Role = 'Environment admin'; Effort = 'Quick win' }
    @{ Id = '^7\.[126]$'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^7\.4$'; Title = 'inventory'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^7\.4$'; Role = 'Maker or asset owner'; Effort = 'Policy or process change' }
    @{ Id = '^7\.5$'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^7\.9$'; Title = 'creation limited|non-production'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^7\.9$'; Role = 'Maker or asset owner'; Effort = 'Policy or process change' }
    @{ Id = '^8\.1$'; Title = 'inventory'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^8\.1$'; Title = 'default environment'; Role = 'Maker or asset owner'; Effort = 'Project' }
    @{ Id = '^8\.1$'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^8\.2$'; Title = 'definition scan'; Role = 'Environment admin'; Effort = 'Quick win' }
    @{ Id = '^8\.2$'; Role = 'Maker or asset owner'; Effort = 'Quick win' }
    @{ Id = '^8\.3$'; Role = 'Maker or asset owner'; Effort = 'Policy or process change' }
    @{ Id = '^8\.6$'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^8\.8$'; Role = 'Maker or asset owner'; Effort = 'Quick win' }
    @{ Id = '^9\.1$'; Title = '^Copilot Studio agent'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^9\.1$'; Title = '^Agent access control'; Role = 'Environment admin'; Effort = 'Quick win' }
    @{ Id = '^9\.4$'; Title = 'sharing limits'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^9\.[1-5]$'; Role = 'Maker or asset owner'; Effort = 'Quick win' }
    @{ Id = '^9\.6$'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^9\.[79]$'; Role = 'Maker or asset owner'; Effort = 'Policy or process change' }
    @{ Id = '^10\.1$'; Role = 'Governance lead'; Effort = 'Policy or process change' }
    @{ Id = '^10\.'; Role = 'Maker or asset owner'; Effort = 'Quick win' }
    @{ Id = '^11\.1$'; Role = 'Governance lead'; Effort = 'Policy or process change' }
    @{ Id = '^11\.2$'; Title = 'Computer use'; Role = 'Environment admin'; Effort = 'Quick win' }
    @{ Id = '^11\.[234]$'; Role = 'Maker or asset owner'; Effort = 'Policy or process change' }
    @{ Id = '^11\.[58]$'; Title = 'Connected agents and code interpreter'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^11\.[58]$'; Role = 'Security and compliance'; Effort = 'Policy or process change' }
    @{ Id = '^12\.'; Role = 'Maker or asset owner'; Effort = 'Quick win' }
    @{ Id = '^13\.'; Title = 'Production environments'; Role = 'Environment admin'; Effort = 'Policy or process change' }
    @{ Id = '^13\.'; Role = 'Maker or asset owner'; Effort = 'Project' }
    @{ Id = '^14\.1$'; Title = 'management settings'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^14\.1$'; Role = 'Security and compliance'; Effort = 'Quick win' }
    @{ Id = '^14\.3$'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^14\.'; Role = 'Governance lead'; Effort = 'Policy or process change' }
    @{ Id = '^15\.3$'; Title = 'Storage warning'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^15\.'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^16\.1$'; Title = 'Model data sharing'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^16\.'; Role = 'Security and compliance'; Effort = 'Policy or process change' }
    @{ Id = '^17\.6$'; Role = 'Maker or asset owner'; Effort = 'Project' }
    @{ Id = '^17\.'; Role = 'Power Platform admin'; Effort = 'Policy or process change' }
    @{ Id = '^18\.1$'; Role = 'Power Platform admin'; Effort = 'Quick win' }
    @{ Id = '^18\.7$'; Role = 'Maker or asset owner'; Effort = 'Quick win' }
    @{ Id = '^18\.(6|9|10)$'; Role = 'Governance lead'; Effort = 'Policy or process change' }
    @{ Id = '^18\.'; Role = 'Maker or asset owner'; Effort = 'Policy or process change' }
)
# Used only when no rule above matches (a new check that has no rule yet), so no finding is ever left without an owner.
$OwnerTopicDefault = @{
    1 = 'Governance lead'; 2 = 'Power Platform admin'; 3 = 'Environment admin'; 4 = 'Power Platform admin'; 5 = 'Entra / identity admin'; 6 = 'Environment admin'
    7 = 'Maker or asset owner'; 8 = 'Maker or asset owner'; 9 = 'Maker or asset owner'; 10 = 'Maker or asset owner'; 11 = 'Maker or asset owner'; 12 = 'Maker or asset owner'
    13 = 'Maker or asset owner'; 14 = 'Security and compliance'; 15 = 'Power Platform admin'; 16 = 'Security and compliance'; 17 = 'Governance lead'; 18 = 'Governance lead'
}

function Get-OwnerRoute {
    param($F)
    foreach ($r in $OwnerRules) {
        if ([string]$F.Id -notmatch $r.Id) { continue }
        if ($r.ContainsKey('Title') -and [string]$F.Title -notmatch $r.Title) { continue }
        return [pscustomobject]@{ Role = [string]$r.Role; Effort = [string]$r.Effort }
    }
    $role = if ($OwnerTopicDefault.ContainsKey([int]$F.Topic)) { $OwnerTopicDefault[[int]$F.Topic] } else { 'Power Platform admin' }
    return [pscustomobject]@{ Role = $role; Effort = 'Policy or process change' }
}

# ------------------------------------------------------------------ Hand-off: owner outreach and tracker import files
# Which owner to contact: the owner lookup in Test-Owners fills OwnerNames, OwnerUpns and OwnerState (Deleted or Disabled).
$script:OwnerUpns = @{}
$script:OwnerState = @{}
$script:OwnerCandidates = @()
$script:HandoffEnabled = -not $SkipHandoff

# What to ask an owner for each kind of reason. First matches win; an empty action means the owner status covers it.
$OutreachActions = @(
    @{ Match = 'Owner account|No owner reported'; Action = '' }
    @{ Match = 'No authentication|without sign-in'; Action = 'require sign-in (Authenticate with Microsoft or Entra ID) or unpublish the agent' }
    @{ Match = 'hard-coded secret'; Action = 'remove the secret, store it in Key Vault and rotate it' }
    @{ Match = 'Maker credentials|as the maker'; Action = 'switch tools to end-user credentials or document the exception' }
    @{ Match = 'entire tenant|Everyone'; Action = 'share with a security group instead of the whole tenant' }
    @{ Match = 'other Microsoft Entra tenants'; Action = 'turn off multitenant access unless there is a documented need' }
    @{ Match = 'sign-in only when'; Action = 'ask users to sign in up front' }
    @{ Match = 'open channel|external channel|Open web'; Action = 'confirm the website or external channels are intended and require sign-in' }
    @{ Match = 'Autonomous|HTTP'; Action = 'review the triggers and HTTP requests and the identity the agent runs as' }
    @{ Match = 'MCP|Bot Service|External-service connector'; Action = 'confirm the external connectors, MCP actions and skills are approved' }
    @{ Match = 'co-authors'; Action = 'trim co-authors to the people who need edit access' }
    @{ Match = 'Public website|Web search|General model knowledge'; Action = 'confirm the public and web knowledge sources are approved' }
    @{ Match = 'content moderation'; Action = 'raise content moderation' }
    @{ Match = 'Never published|Not published|Not modified'; Action = 'confirm it is still needed and archive or delete it if not' }
)

# Apps and flows that are dormant or have no owner. Test-Owners only keeps the orphaned ones, so these are saved while the inventory is at hand.
function Get-OwnerCandidate {
    param($Apps, $Flows, $EnvMap)
    $rows = New-Object System.Collections.ArrayList
    foreach ($set in @(@{ Kind = 'App'; Items = $Apps }, @{ Kind = 'Flow'; Items = $Flows })) {
        foreach ($r in @($set.Items)) {
            $owner = [string](Get-Prop $r 'properties.ownerId' '')
            $days = Get-DaysSince (Get-Prop $r 'properties.lastModifiedAt' '')
            $reasons = New-Object System.Collections.ArrayList
            if (-not $owner) { [void]$reasons.Add('No owner reported') }
            if ($days -gt $StaleDays) { [void]$reasons.Add("Not modified for $days days (may be dormant)") }
            if ($reasons.Count -eq 0) { continue }
            $envId = [string](Get-Prop $r 'properties.environmentId' '')
            [void]$rows.Add([pscustomobject]@{ Kind = $set.Kind; Name = [string](Get-Prop $r 'properties.displayName' $r.name); OwnerId = $owner; EnvId = $envId; Environment = (Get-EnvLabel $EnvMap $envId); Reasons = @($reasons) })
        }
    }
    return $rows.ToArray()
}

# Deleted or Disabled come from the owner lookup; Active means the lookup found the account; Not checked means Graph owner lookup did not run.
function Get-OwnerStatus {
    param([string]$OwnerId)
    if (-not $OwnerId) { return 'No owner reported' }
    $k = $OwnerId.ToLower()
    if ($script:OwnerState.ContainsKey($k)) { return [string]$script:OwnerState[$k] }
    if ($script:OwnerNames.Count -eq 0) { return 'Not checked' }
    return 'Active'
}

function Add-OutreachReason {
    param($Assets, [string]$Key, [string]$Kind, [string]$Name, [string]$Environment, [string]$OwnerId, [string]$Priority, [string]$Reason)
    if (-not $Assets.ContainsKey($Key)) {
        $Assets[$Key] = [pscustomobject]@{ Kind = $Kind; Name = $Name; Environment = $Environment; OwnerId = $OwnerId; Priority = 'Low'; Reasons = (New-Object System.Collections.ArrayList) }
    }
    $a = $Assets[$Key]
    if ($Reason -and -not $a.Reasons.Contains($Reason)) { [void]$a.Reasons.Add($Reason) }
    $want = [array]::IndexOf($SeverityOrder, $Priority)
    if ($want -ge 0 -and $want -lt [array]::IndexOf($SeverityOrder, $a.Priority)) { $a.Priority = $Priority }
}

# One row per owner with the assets that need attention. Assets with no usable owner (none reported, or the account was deleted)
# are grouped under one clearly labeled "No owner" row, because there is nobody to notify.
function Get-OwnerOutreach {
    param($AgentRisk)
    $assets = @{}
    $riskById = @{}
    foreach ($r in @($AgentRisk)) { if ($r.AgentId) { $riskById[([string]$r.AgentId).ToLower()] = $r } }
    foreach ($a in @($script:AgentView)) {
        $id = ([string]$a.Id).ToLower()
        $key = "agent|$id"
        $owner = [string]$a.Owner
        $risk = $riskById[$id]
        # Medium rating (15 points) and above; lower-rated agents only appear for ownership or lifecycle reasons.
        if ($risk -and [int]$risk.RiskScore -ge 15) {
            foreach ($s in @(([string]$risk.Signals) -split '; ' | Where-Object { $_ -and $_ -ne 'Owner deleted or disabled' })) {
                Add-OutreachReason -Assets $assets -Key $key -Kind 'Agent' -Name $a.Agent -Environment $a.Environment -OwnerId $owner -Priority $risk.Rating -Reason $s
            }
        }
        if (-not $owner) { Add-OutreachReason -Assets $assets -Key $key -Kind 'Agent' -Name $a.Agent -Environment $a.Environment -OwnerId $owner -Priority 'High' -Reason 'No owner reported' }
        if (-not $a.LastPublished -and (Get-DaysSince $a.Created) -gt 90) { Add-OutreachReason -Assets $assets -Key $key -Kind 'Agent' -Name $a.Agent -Environment $a.Environment -OwnerId $owner -Priority 'Low' -Reason 'Never published and older than 90 days' }
        elseif ($a.LastPublished -and (Get-DaysSince $a.LastPublished) -gt $StaleDays) { Add-OutreachReason -Assets $assets -Key $key -Kind 'Agent' -Name $a.Agent -Environment $a.Environment -OwnerId $owner -Priority 'Low' -Reason "Not published for $(Get-DaysSince $a.LastPublished) days" }
    }
    foreach ($o in @($script:OrphanedAssets)) {
        $oid = [string]$o.Owner
        $key = if ($o.Kind -eq 'Agent' -and $o.Id) { 'agent|' + ([string]$o.Id).ToLower() } else { ("$($o.Kind)|$oid|$($o.Env)|$($o.Name)").ToLower() }
        $reason = if ((Get-OwnerStatus $oid) -eq 'Disabled') { 'Owner account is disabled' } else { 'Owner account was deleted' }
        Add-OutreachReason -Assets $assets -Key $key -Kind $o.Kind -Name $o.Name -Environment (Get-EnvLabel $script:EnvMap $o.Env) -OwnerId $oid -Priority 'High' -Reason $reason
    }
    foreach ($c in @($script:OwnerCandidates)) {
        $key = ("$($c.Kind)|$($c.OwnerId)|$($c.EnvId)|$($c.Name)").ToLower()
        foreach ($reason in @($c.Reasons)) {
            Add-OutreachReason -Assets $assets -Key $key -Kind $c.Kind -Name $c.Name -Environment $c.Environment -OwnerId $c.OwnerId -Priority $(if ($reason -like 'No owner*') { 'High' } else { 'Low' }) -Reason $reason
        }
    }

    $groups = @{}
    foreach ($a in $assets.Values) {
        if ($a.Reasons.Count -eq 0) { continue }
        $gk = if ((Get-OwnerStatus $a.OwnerId) -in @('No owner reported', 'Deleted')) { 'no-owner' } else { ([string]$a.OwnerId).ToLower() }
        if (-not $groups.ContainsKey($gk)) { $groups[$gk] = New-Object System.Collections.ArrayList }
        [void]$groups[$gk].Add($a)
    }
    $assetCap = 25
    $rows = foreach ($gk in @($groups.Keys)) {
        $list = @($groups[$gk] | Sort-Object @{ Expression = { [array]::IndexOf($SeverityOrder, $_.Priority) } }, Kind, Name)
        $noOwner = ($gk -eq 'no-owner')
        $ownerId = [string]$list[0].OwnerId
        $status = if ($noOwner) { 'No owner' } else { Get-OwnerStatus $ownerId }
        $label = if ($noOwner) { 'No owner' } else { Resolve-OwnerLabel $ownerId }
        $upn = ''
        if (-not $noOwner) {
            $upn = [string]$script:OwnerUpns[$ownerId.ToLower()]
            if (-not $upn -and $label -match '^[^@\s]+@[^@\s]+$') { $upn = $label }
        }
        $reasonCount = @{}
        foreach ($a in $list) { foreach ($rs in $a.Reasons) { $reasonCount[$rs] = 1 + [int]$reasonCount[$rs] } }
        $reasonText = (@($reasonCount.Keys | Sort-Object @{ Expression = { $reasonCount[$_] }; Descending = $true }, @{ Expression = { $_ } } | Select-Object -First 12 | ForEach-Object { if ($reasonCount[$_] -gt 1) { "$_ (x$($reasonCount[$_]))" } else { $_ } })) -join '; '
        $lines = New-Object System.Collections.ArrayList
        $len = 0
        foreach ($a in $list) {
            $where = if ($a.Environment) { " [$($a.Environment)]" } else { '' }
            $line = "$($a.Kind): $($a.Name)$where - $($a.Reasons -join '; ')"
            if ($lines.Count -ge $assetCap -or ($len + $line.Length) -gt 30000) { break }
            [void]$lines.Add($line)
            $len += $line.Length + 3
        }
        $assetText = $lines -join ' | '
        if ($list.Count -gt $lines.Count) { $assetText += " | (+$($list.Count - $lines.Count) more assets not listed here; the counts in this row cover all of them)" }
        $asks = New-Object System.Collections.ArrayList
        foreach ($rule in $OutreachActions) {
            if (-not $rule.Action) { continue }
            if (@($reasonCount.Keys | Where-Object { $_ -match $rule.Match }).Count -gt 0 -and -not $asks.Contains($rule.Action)) { [void]$asks.Add($rule.Action) }
        }
        $todo = if ($asks.Count -gt 0) { (@($asks | Select-Object -First 5) -join '; ') + '.' } else { 'review the flagged items.' }
        $action = switch ($status) {
            'No owner' { "Nobody to notify: assign an owner to each asset (or retire it), then ask the new owner to $todo" }
            'Disabled' { "The owner account is disabled: ask their manager to nominate a new owner and reassign these assets, then ask the new owner to $todo" }
            'Not checked' { "Owner status was not checked (the Microsoft Graph owner lookup did not run). Confirm the owner is still active, then ask them to $todo" }
            default { "Contact the owner and ask them to $todo" }
        }
        [pscustomobject][ordered]@{
            Owner = $label; Contact = $upn; OwnerStatus = $status; HighestRisk = $list[0].Priority; AtRiskAssets = $list.Count
            Agents = @($list | Where-Object Kind -eq 'Agent').Count; Apps = @($list | Where-Object Kind -eq 'App').Count; Flows = @($list | Where-Object Kind -eq 'Flow').Count
            Environments = (@($list | ForEach-Object { $_.Environment } | Where-Object { $_ } | Sort-Object -Unique) -join '; ')
            Reasons = $reasonText; Assets = $assetText; RecommendedAction = $action; OwnerId = $(if ($noOwner) { '' } else { $ownerId })
        }
    }
    return @($rows | Sort-Object @{ Expression = { [array]::IndexOf($SeverityOrder, $_.HighestRisk) } }, @{ Expression = 'AtRiskAssets'; Descending = $true }, Owner)
}

# Tracker files are ASCII-safe: typographic punctuation becomes plain punctuation.
function ConvertTo-AsciiText {
    param([string]$Text)
    if (-not $Text) { return '' }
    return $Text.Replace([string][char]0x2018, "'").Replace([string][char]0x2019, "'").Replace([string][char]0x201C, '"').Replace([string][char]0x201D, '"').Replace([string][char]0x2013, '-').Replace([string][char]0x2014, '-').Replace([string][char]0x2026, '...').Replace([string][char]0x00A0, ' ')
}

# Tags and labels cannot hold spaces in Jira, so every value is reduced to letters, digits and hyphens.
function ConvertTo-TagText {
    param([string]$Text)
    return (([string]$Text -replace '[^A-Za-z0-9]+', '-').Trim('-'))
}

# One work item per open (Fail or Warning) action, in priority order, for Azure DevOps and Jira CSV import.
# Work Item Type and Issue Type are Task, which exists in every Azure DevOps process and Jira project type. Severity text is in Tags or Labels and in the description,
# because the Severity field exists only on some Azure DevOps work item types and an unknown column would stop the import.
function Export-WorkItem {
    param([string]$Dir, $Actions)
    $open = @($Actions | Where-Object { $_.Finding.Status -in @('Fail', 'Warning') })
    if ($open.Count -eq 0) { return }
    $adoPriority = @{ Critical = 1; High = 2; Medium = 3; Low = 4 }
    $jiraPriority = @{ Critical = 'Highest'; High = 'High'; Medium = 'Medium'; Low = 'Low' }
    $ado = New-Object System.Collections.ArrayList
    $jira = New-Object System.Collections.ArrayList
    foreach ($e in $open) {
        $f = $e.Finding
        $route = Get-OwnerRoute $f
        $why = ConvertTo-AsciiText (Get-WhyText $f)
        $found = ConvertTo-AsciiText $(if ($f.Value) { $f.Value } else { $f.Detail })
        $rec = ConvertTo-AsciiText $f.Recommendation
        $links = @(Get-LearnLinks $f)
        $related = @($e.Related | Select-Object -Skip 1)
        $title = ConvertTo-AsciiText "PPCS $($f.Id): $($f.Title)"
        if ($title.Length -gt 250) { $title = $title.Substring(0, 247) + '...' }
        $statusText = if ($f.Status -eq 'Fail') { 'Fail' } else { 'Warning' }

        $h = New-Object System.Text.StringBuilder
        [void]$h.Append("<p><b>Severity:</b> $(Format-Html $f.Severity) ($statusText) &middot; <b>Check:</b> $(Format-Html $f.Id) &middot; <b>Area:</b> $(Format-Html (ConvertTo-AsciiText $f.TopicName))</p>")
        if ($found) { [void]$h.Append("<p><b>What we found:</b> $(Format-Html $found)</p>") }
        if ($rec) { [void]$h.Append("<p><b>Recommended action:</b> $(Format-Html $rec)</p>") }
        if ($why) { [void]$h.Append("<p><b>Why:</b> $(Format-Html $why)</p>") }
        [void]$h.Append("<p><b>Suggested owner:</b> $(Format-Html $route.Role) &middot; <b>Effort:</b> $(Format-Html $route.Effort)</p>")
        if ($related.Count -gt 0) { [void]$h.Append("<p><b>Also counted in:</b> $(Format-Html ($related -join ', '))</p>") }
        if ($links.Count -gt 0) { [void]$h.Append('<p><b>Microsoft Learn:</b> ' + ((@($links | ForEach-Object { "<a href='$(Format-Html $_.Url)'>$(Format-Html $_.Title)</a>" })) -join '; ') + '</p>') }
        $tags = @('PPCS', "Severity-$($f.Severity)", "Area-$($f.Topic)", "Owner-$(ConvertTo-TagText $route.Role)", "Effort-$(ConvertTo-TagText $route.Effort)")
        [void]$ado.Add([pscustomobject][ordered]@{ 'Work Item Type' = 'Task'; Title = $title; Description = $h.ToString(); Priority = $adoPriority[[string]$f.Severity]; Tags = ($tags -join '; ') })

        $t = New-Object System.Collections.ArrayList
        [void]$t.Add("Severity: $($f.Severity) ($statusText)  |  Check: $($f.Id)  |  Area: $(ConvertTo-AsciiText $f.TopicName)")
        if ($found) { [void]$t.Add("What we found: $found") }
        if ($rec) { [void]$t.Add("Recommended action: $rec") }
        if ($why) { [void]$t.Add("Why: $why") }
        [void]$t.Add("Suggested owner: $($route.Role)  |  Effort: $($route.Effort)")
        if ($related.Count -gt 0) { [void]$t.Add("Also counted in: $($related -join ', ')") }
        if ($links.Count -gt 0) { [void]$t.Add("Microsoft Learn:`n" + ((@($links | ForEach-Object { "- $($_.Title): $($_.Url)" })) -join "`n")) }
        [void]$jira.Add([pscustomobject][ordered]@{
                Summary = $title; 'Issue Type' = 'Task'; Priority = $jiraPriority[[string]$f.Severity]; Description = ($t -join "`n`n")
                Labels = 'PPCS'; Labels2 = $tags[1]; Labels3 = $tags[3]; Labels4 = $tags[4]
            })
    }
    Export-SafeCsv -Rows $ado.ToArray() -Path (Join-Path $Dir 'workitems-azure-devops.csv')
    $jiraPath = Join-Path $Dir 'workitems-jira.csv'
    Export-SafeCsv -Rows $jira.ToArray() -Path $jiraPath
    # Jira reads several Labels columns of the same name as several labels, so the numbered names are only needed to build the rows.
    $jt = [System.IO.File]::ReadAllText($jiraPath)
    $eol = $jt.IndexOf("`n")
    [System.IO.File]::WriteAllText($jiraPath, (($jt.Substring(0, $eol) -replace '"Labels[0-9]"', '"Labels"') + $jt.Substring($eol)), (New-Object System.Text.UTF8Encoding($true)))
}

function Export-Handoff {
    param([string]$Dir, $Actions, $AgentRisk)
    try {
        $outreach = @(Get-OwnerOutreach -AgentRisk $AgentRisk)
        if ($outreach.Count -gt 0) { Export-SafeCsv -Rows $outreach -Path (Join-Path $Dir 'owner-outreach.csv') }
        Export-WorkItem -Dir $Dir -Actions $Actions
    }
    catch { Add-Limitation 'Hand-off exports' "owner-outreach.csv and the work-item import files could not be written: $($_.Exception.Message)" }
}

function Format-FindingCard {
    param($F)
    $actionable = $F.Status -in @('Fail', 'Warning', 'Unavailable', 'Accepted')
    $route = Get-OwnerRoute $F
    $cl = $script:Checklist[$F.Id]
    $confLabel = switch ($F.Confidence) { 'Configuration' { 'Configuration' } 'Sample' { 'Sample' } 'Heuristic' { 'Heuristic' } 'NotVerified' { 'Not verified' } default { [string]$F.Confidence } }
    $confTitle = switch ($F.Confidence) {
        'Configuration' { 'Confirmed by configuration: read directly from the service.' }
        'Sample' { 'Confirmed by sample: covers only part of the tenant (see Scope and confidence).' }
        'Heuristic' { 'Heuristic: pattern-based detection, verify before reporting.' }
        'NotVerified' { 'Not verified: the data could not be read.' }
        default { '' }
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<article class='finding st-$($F.Status)' id='f-$($F.Key)' data-status='$($F.Status)' data-sev='$($F.Severity)' data-area='$($F.Topic)' data-owner='$(Format-Html $route.Role)'><header class='f-top'>")
    [void]$sb.Append((Format-StatusChip $F.Status))
    if ($actionable) { [void]$sb.Append((Format-SeverityChip $F.Severity)) }
    [void]$sb.Append("<span class='fid'>$(Format-Html $F.Id)</span><h3 class='ft'>$(Format-Html $F.Title)</h3><span class='ctag c-$($F.Confidence)' title='$(Format-Html $confTitle)'>$(Format-Html $confLabel)</span><a class='perma' href='#f-$($F.Key)' title='Copy link to this finding' aria-label='Copy link to this finding'>#</a></header>")
    if ($F.Status -eq 'Accepted' -and $F.Acceptance) {
        $ac = $F.Acceptance
        $parts = New-Object System.Collections.ArrayList
        [void]$parts.Add("<b>Accepted risk</b> (was $(Format-Html $F.AcceptedFrom)). Reason: $(Format-Html $ac.Reason)")
        if ($ac.Owner) { [void]$parts.Add("Owner: $(Format-Html $ac.Owner)") }
        if ($ac.ApprovedBy) { [void]$parts.Add("Approved by $(Format-Html $ac.ApprovedBy)$(if ($ac.Approved) { ' on ' + (Format-Html $ac.Approved) })") }
        if ($ac.Expires) { [void]$parts.Add("Expires $(Format-Html $ac.Expires)") }
        if ($ac.Notes) { [void]$parts.Add("<i>$(Format-Html $ac.Notes)</i>") }
        [void]$sb.Append("<div class='accnote'>$($parts -join '. ')</div>")
    }
    $hasRec = [bool]$F.Recommendation
    $found = ''
    if ($F.Value) { $found += "<p>$(Format-Html $F.Value)</p>" }
    if ($F.Detail) { $found += "<p class='small'>$(Format-Html $F.Detail)</p>" }
    if (-not $found) { $found = "<p class='small'>No further detail.</p>" }
    $one = if ($hasRec) { '' } else { ' one' }
    [void]$sb.Append("<div class='f-body$one'><div><div class='lbl'>What we found</div>$found</div>")
    if ($hasRec) {
        $whyCard = Get-WhyText $F
        $whyHtml = if ($whyCard) { "<p class='why'><b>Why:</b> $(Format-Html $whyCard)</p>" } else { '' }
        [void]$sb.Append("<div><div class='lbl'>Recommended action</div><p>$(Format-Html $F.Recommendation)</p>$whyHtml<p class='route'><b>Suggested owner:</b> $(Format-Html $route.Role) &middot; <b>Effort:</b> $(Format-Html $route.Effort)</p></div>")
    }
    [void]$sb.Append('</div>')
    if ($F.EvidenceCount -gt 0) {
        $cols = @($F.Evidence[0].PSObject.Properties.Name)
        $shown = @($F.Evidence | Select-Object -First $HtmlEvidenceRows)
        $file = ''
        if ($F.EvidenceFile) { $file = " <a href='$(Format-Html $F.EvidenceFile)'>Open full list (CSV)</a>" }
        $trunc = if ($F.EvidenceCount -gt $shown.Count) { " Showing the first $($shown.Count) of $($F.EvidenceCount)." } else { '' }
        [void]$sb.Append("<details class='ev'><summary>Evidence: $($F.EvidenceCount) row(s)</summary>$(Format-HtmlTable -Rows $shown -Columns $cols -Limit 12 -MoreLabel 'rows')<p class='small'>$trunc$file</p></details>")
    }
    if ($actionable -and $cl) {
        $extra = ''
        foreach ($opt in @('Why', 'Reference', 'Framework')) { if ($cl.PSObject.Properties[$opt] -and $cl.$opt) { $extra += "<dt>$opt</dt><dd>$(Format-Html $cl.$opt)</dd>" } }
        [void]$sb.Append("<details class='ctl'><summary>About this control: $(Format-Html $F.Id) $(Format-Html $cl.Feature)</summary><dl><dt>What to check</dt><dd>$(Format-Html $cl.Check)</dd><dt>How to verify</dt><dd>$(Format-Html $cl.Verify)</dd><dt>Target state</dt><dd>$(Format-Html $cl.Target)</dd>$extra</dl></details>")
    }
    $learn = @(Get-LearnLinks $F)
    if ($learn.Count -gt 0) {
        $li = ($learn | ForEach-Object { "<li><a href='$(Format-Html $_.Url)' target='_blank' rel='noopener noreferrer'>$(Format-Html $_.Title)<span aria-hidden='true'> &#8599;</span><span class='sr'> (opens Microsoft Learn in a new tab)</span></a></li>" }) -join ''
        [void]$sb.Append("<div class='learn'><span class='lbl'>Microsoft Learn</span><ul>$li</ul></div>")
    }
    $also = if (@($F.AlsoCovers).Count -gt 0) { ' &middot; Also covers ' + (Format-Html (@($F.AlsoCovers) -join ', ')) } else { '' }
    [void]$sb.Append("<footer class='f-meta'>Source: $(Format-Html $F.Source)$also</footer></article>")
    return $sb.ToString()
}

function Write-Report {
    param([string]$Dir, $Started, [switch]$AfterRedactionCheck)
    $evDir = Join-Path $Dir 'evidence'
    New-Item -ItemType Directory -Force -Path $evDir | Out-Null
    if ($script:Redaction.Active) { Initialize-Redaction }
    Save-Evidence $evDir

    # ---- report model (everything is computed before any file is written so limitations from this stage are included)
    $coverage = @(Get-Coverage)
    $areas = @(Get-AreaStats)
    $overall = Get-OverallStats
    $startHere = @(Get-StartHereRows)
    $roadmap = Get-RoadmapBuckets
    $actions = @(Get-ActionList)
    $agentRisk = @(Get-AgentRiskRegister)
    $envProfile = @(Get-EnvironmentProfile)
    $diff = Get-BaselineDiff -Path $BaselinePath
    $health = Get-ApiHealth
    $manual = @($coverage | Where-Object { $_.Coverage -eq 'Manual' -or $_.Coverage -eq 'Attempted, unavailable' })
    $tenantLabel = if ($script:Auth.TenantGuid) { $script:Auth.TenantGuid } else { $TenantId }

    # ---- machine-readable exports (existing columns first, new columns appended)
    $props = @('Key', 'Id', 'Topic', 'TopicName', 'Title', 'Status', 'Severity', 'Value', 'Detail', 'Recommendation', 'Source', 'EvidenceCount', 'EvidenceFile') +
    @(@{ Name = 'Confidence'; Expression = { $_.Confidence } }, @{ Name = 'AlsoCovers'; Expression = { @($_.AlsoCovers) -join '; ' } }, @{ Name = 'RollupKey'; Expression = { $_.RollupKey } }, @{ Name = 'LearnLinks'; Expression = { (@(Get-LearnLinks $_) | ForEach-Object { $_.Url }) -join '; ' } }, @{ Name = 'Why'; Expression = { Get-WhyText $_ } }, @{ Name = 'AcceptedFrom'; Expression = { $_.AcceptedFrom } }, @{ Name = 'AcceptedReason'; Expression = { if ($_.Acceptance) { $_.Acceptance.Reason } else { '' } } }, @{ Name = 'AcceptedOwner'; Expression = { if ($_.Acceptance) { $_.Acceptance.Owner } else { '' } } }, @{ Name = 'AcceptedApprovedBy'; Expression = { if ($_.Acceptance) { $_.Acceptance.ApprovedBy } else { '' } } }, @{ Name = 'AcceptedExpires'; Expression = { if ($_.Acceptance) { $_.Acceptance.Expires } else { '' } } })
    $props += @(@{ Name = 'OwnerRole'; Expression = { (Get-OwnerRoute $_).Role } }, @{ Name = 'Effort'; Expression = { (Get-OwnerRoute $_).Effort } })
    $flat = @($script:Findings | Select-Object -Property $props)
    Export-SafeCsv -Rows $flat -Path (Join-Path $Dir 'findings.csv')
    $jsonRows = $flat
    if ($script:Redaction.Active) { $jsonRows = Protect-Object $flat }
    ConvertTo-Json -InputObject $jsonRows -Depth 4 | Out-File -FilePath (Join-Path $Dir 'findings.json') -Encoding UTF8
    Export-SafeCsv -Rows @($script:ApiLog) -Path (Join-Path $Dir 'api-log.csv')
    if ($coverage.Count -gt 0) { Export-SafeCsv -Rows $coverage -Path (Join-Path $Dir 'checklist-coverage.csv') }
    if ($script:ExceptionsLoaded -and @($script:ExceptionRows).Count -gt 0) {
        $exRows = @($script:ExceptionRows | ForEach-Object {
                [pscustomobject][ordered]@{
                    Row = $_.Row; Id = $_.Id; TitlePattern = $_.Title; State = $_.State; FindingsAccepted = $_.Applied; Findings = $_.Findings; Was = $_.Was; Severity = $_.Severity
                    Reason = $_.Reason; Owner = $_.Owner; ApprovedBy = $_.ApprovedBy; Approved = (Format-ExceptionDate $_.Approved); Reviewed = (Format-ExceptionDate $_.Reviewed)
                    Expires = (Format-ExceptionDate $_.Expires); DaysToExpiry = $_.DaysToExpiry; Notes = (@($_.Notes) -join '; ')
                }
            })
        Export-SafeCsv -Rows $exRows -Path (Join-Path $Dir 'accepted-risks.csv')
    }
    foreach ($u in $script:Usage.Values) {
        if (@($u.Rows).Count -gt 0) { Export-SafeCsv -Rows @($u.Rows) -Path (Join-Path $Dir ('usage-' + $u.Key + '.csv')) }
    }
    # Findings register in the framework template layout (ID, Area, Finding, Evidence, Risk, Recommendation, Owner / date).
    $register = New-Object System.Collections.ArrayList
    $n = 0
    foreach ($e in @($actions | Where-Object { $_.Finding.Status -in @('Fail', 'Warning') })) {
        $n++
        $f = $e.Finding
        $route = Get-OwnerRoute $f
        $areaTxt = (@($f.Topic) + @(@($f.AlsoCovers) | ForEach-Object { ([string]$_).Split('.')[0] }) | Where-Object { $_ } | Select-Object -Unique) -join ' / '
        $evTxt = $f.Source + $(if ($f.EvidenceFile) { '; ' + $f.EvidenceFile } else { '' })
        [void]$register.Add([pscustomobject][ordered]@{
                'ID' = ('F-{0:D2}' -f $n); 'Area' = $areaTxt; 'Finding' = ((@($f.Title, $f.Value) | Where-Object { $_ }) -join ': '); 'Evidence' = $evTxt
                'Risk' = $f.Severity; 'Recommendation' = $f.Recommendation; 'Owner / date' = ''; 'Status' = $f.Status; 'Check' = $f.Id; 'Finding key' = $f.Key
                'Suggested owner' = $route.Role; 'Effort' = $route.Effort
            })
    }
    if ($register.Count -gt 0) { Export-SafeCsv -Rows $register.ToArray() -Path (Join-Path $Dir 'findings-register.csv') }
    if ($script:HandoffEnabled) { Export-Handoff -Dir $Dir -Actions $actions -AgentRisk $agentRisk }
    if ($agentRisk.Count -gt 0) { Export-SafeCsv -Rows ($agentRisk | Select-Object Agent, Environment, Owner, Authentication, Channels, Published, RiskScore, Rating, Signals, Credits30d, OwnerId, AgentId, EnvironmentId) -Path (Join-Path $Dir 'agent-risk-register.csv') }
    if ($envProfile.Count -gt 0) { Export-SafeCsv -Rows ($envProfile | Select-Object Environment, Type, Managed, Group, SecurityGroup, Geo, Retention, State, Apps, Flows, Agents, Sites, ConversationAudit, DataverseAudit, SystemAdmins, RiskScore, Rating, Flags, EnvironmentId) -Path (Join-Path $Dir 'environment-profile.csv') }
    $exSummary = $null
    if ($script:ExceptionsLoaded) {
        $er = @($script:ExceptionRows)
        $exSummary = [ordered]@{
            File = [System.IO.Path]::GetFileName($ExceptionsPath); Rows = $er.Count
            Active = @($er | Where-Object { $_.State -eq 'Active' }).Count; ExpiringSoon = @($er | Where-Object { $_.State -eq 'Expiring soon' }).Count
            Expired = @($er | Where-Object { $_.State -eq 'Expired' }).Count; Invalid = @($er | Where-Object { $_.State -eq 'Invalid' }).Count
            NoOpenFinding = @($er | Where-Object { $_.State -in @('No match', 'Nothing to accept') }).Count; AcceptedFindings = $overall.Accepted
        }
    }
    $summaryCounts = [ordered]@{ Total = $overall.Total }
    foreach ($k in $overall.Counts.Keys) { $summaryCounts[$k] = $overall.Counts[$k] }
    $summary = [ordered]@{
        SchemaVersion = 1; ScriptVersion = $ScriptVersion; GeneratedAt = ($Started.ToUniversalTime().ToString('s') + 'Z'); Customer = $CustomerName; Tenant = $tenantLabel; RunBy = $script:Auth.User
        Redacted = [bool]$script:Redaction.Active
        PowerShell = $PSVersionTable.PSVersion.ToString()
        Scores = [ordered]@{ Overall = $overall.Score; Band = $overall.Band.Name; Capped = $overall.Band.Capped; Provisional = $overall.Provisional; ScoredChecks = $overall.Scored; CriticalGaps = $overall.CriticalFail }
        Counts = $summaryCounts
        Areas = @($areas | Select-Object Topic, Name, Section, Score, Band, Fail, Warning,         Pass, Info, Unavailable, Accepted)
        Kpis = $script:Kpi
                Exceptions = $exSummary
        Limitations = @($script:Limitations)
        Api = [ordered]@{ Total = $health.Total; Ok = $health.Ok; Failed = $health.Failed }
        Parameters = [ordered]@{
            AuthMethod = $AuthMethod; UsageLookbackDays = $UsageLookbackDays; TopN = $TopN; StaleDays = $StaleDays; EvidenceRowLimit = $EvidenceRowLimit
            MaxDataverseEnvironments = $MaxDataverseEnvironments; MaxEnvironmentSettingsCalls = $MaxEnvironmentSettingsCalls; MaxAgentComponentsPerEnvironment = $MaxAgentComponentsPerEnvironment
            MaxFlowDefinitionsPerEnvironment = $MaxFlowDefinitionsPerEnvironment; MaxEntitlementEnvironments = $MaxEntitlementEnvironments; FlowRunSampleLimit = $FlowRunSampleLimit
            MaxAppSharingEnvironments = $MaxAppSharingEnvironments; DefaultEnvironmentAssetWarnThreshold = $DefaultEnvironmentAssetWarnThreshold
            DeveloperEnvironmentDeadline = $DeveloperEnvironmentDeadline.ToString('yyyy-MM-dd'); SkipLegacyApis = [bool]$SkipLegacyApis; SkipEntra = [bool]$SkipEntra
            SkipDataverse = [bool]$SkipDataverse; SkipUsage = [bool]$SkipUsage; SkipDeepScan = [bool]$SkipDeepScan; SkipHandoff = [bool]$SkipHandoff; ChecklistSource = $script:ChecklistSource
            PowerPlatformApiHost = $PowerPlatformApiHost; BapApiHost = $BapApiHost; GraphHost = $GraphHost; ExceptionsFile = $(if ($ExceptionsPath) { [System.IO.Path]::GetFileName($ExceptionsPath) } else { '' })
        }
    }
    $summaryOut = $summary
    if ($script:Redaction.Active) {
        $summaryOut = Protect-Object $summary
        $summaryOut['RedactionNote'] = 'Names, accounts, IDs and URLs from the tenant were replaced with consistent pseudonyms (for example Environment 001 and User 001). Names that are common words, such as Production or Test, are not replaced. Do not use this run as the -BaselinePath for an unredacted run.'
    }
    ConvertTo-Json -InputObject $summaryOut -Depth 6 | Out-File -FilePath (Join-Path $Dir 'run-summary.json') -Encoding UTF8

    # ---- HTML
    $m = @{
        Started = $Started; TenantLabel = $tenantLabel; Areas = $areas; Overall = $overall; StartHere = $startHere; Roadmap = $roadmap; Actions = $actions
        AgentRisk = $agentRisk; EnvProfile = $envProfile; Diff = $diff; Health = $health; Coverage = $coverage; Manual = $manual; Register = @($register)
    }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Power Platform and Copilot Studio review</title><style>$(Get-ReportCss)</style></head><body>")
    [void]$sb.Append((Get-HtmlHero $m))
    [void]$sb.Append((Get-HtmlNav $m))
    [void]$sb.Append("<main class='wrap'>")
    [void]$sb.Append((Get-HtmlSummary $m))
    if ($diff) { [void]$sb.Append((Get-HtmlChanges $m)) }
    [void]$sb.Append((Get-HtmlStartHere $m))
    [void]$sb.Append((Get-HtmlRoadmap $m))
    if ($script:ExceptionsLoaded) { [void]$sb.Append((Get-HtmlAcceptedRisk)) }
    [void]$sb.Append((Get-HtmlScorecard $m))
    [void]$sb.Append((Get-HtmlUsage))
    [void]$sb.Append((Get-HtmlAgents $m))
    [void]$sb.Append((Get-HtmlEnvironments $m))
    [void]$sb.Append((Get-HtmlFindings $m))
    [void]$sb.Append((Get-HtmlManual $m))
    [void]$sb.Append((Get-HtmlAppendix $m))
    [void]$sb.Append("</main><footer class='page'><div class='aboutcard'>$(Get-HtmlAbout)</div>Generated by Invoke-PPCSReview v$ScriptVersion. Results are point-in-time and read-only.$(if ($script:Redaction.Active) { '<!--ppcs-redaction-footer-->' })</footer><script>$(Get-ReportJs)</script></body></html>")

    $html = Join-Path $Dir 'report.html'
    $htmlText = $sb.ToString()
    if ($script:Redaction.Active) {
        # The banners are added after redaction so their wording can never be changed by it.
        $htmlText = (Protect-Html $htmlText).Replace('<!--ppcs-redaction-banner-->', (Get-RedactionBanner 'Cover')).Replace('<!--ppcs-redaction-footer-->', (Get-RedactionBanner 'Footer'))
    }
    [System.IO.File]::WriteAllText($html, $htmlText, (New-Object System.Text.UTF8Encoding($true)))

    if ($script:Redaction.Active) {
        $check = Test-RedactionOutput -Dir $Dir
        if ($check.Count -gt 0 -and -not $AfterRedactionCheck) {
            $where = (@($check.Survivors | ForEach-Object { $_.File }) -join ', ')
            Add-Limitation 'Redaction' "The post-write redaction check found $($check.Count) value(s) that were not replaced, in: $where. Review those files before you share this folder."
            Write-Warning "Redaction check FAILED: $($check.Count) registered or unregistered value(s) survived in $where. Writing the files again with this noted as a limitation; review them before you share the folder."
            return (Write-Report -Dir $Dir -Started $Started -AfterRedactionCheck)
        }
        if ($check.Count -gt 0) {
            foreach ($s in $check.Survivors) { Write-Warning "Redaction check: $($s.Count) value(s) survived in $($s.File) ($($s.Kinds)). Review this file before you share the folder." }
        }
        else { Write-Information "Redaction check: passed. Scanned $($check.Files) file(s) for $($script:Redaction.Entries.Count) registered value(s) and the email, GUID and tenant host patterns." -InformationAction Continue }
        Export-RedactionMap -Dir $Dir
    }
    return $html
}

# ------------------------------------------------------------------ report sections
function Get-ShortText {
    param([string]$Text, [int]$Max = 170)
    if (-not $Text) { return '' }
    # In -Redact mode names are replaced before the text is cut, so a cut can never leave half a name behind.
    if ($script:Redaction.Active) { $Text = Protect-Text $Text }
    if ($Text.Length -le $Max) { return $Text }
    return $Text.Substring(0, $Max - 1).TrimEnd() + [string][char]0x2026
}

function Get-FirstSentence {
    param([string]$Text, [int]$Max = 200)
    if (-not $Text) { return '' }
    if ($script:Redaction.Active) { $Text = Protect-Text $Text }
    $mt = [regex]::Match($Text, '^.+?[.!?](\s|$)')
    if ($mt.Success -and $mt.Value.Trim().Length -le $Max) { return $mt.Value.Trim() }
    return (Get-ShortText $Text $Max)
}

function Get-FindingLink {
    param([string]$Id)
    $hit = @($script:Findings | Where-Object { $_.Id -eq $Id } | Select-Object -First 1)
    if ($hit.Count -gt 0) { return "<a href='#f-$($hit[0].Key)'>$(Format-Html $Id)</a>" }
    return (Format-Html $Id)
}

function Get-HtmlHero {
    param($M)
    $subtitle = if ($CustomerName) { "$(Format-Html $CustomerName) &middot; Security, best-practice and risk review" } else { 'Security, best-practice and risk review' }
    $by = if ($PreparedBy) { $PreparedBy } else { $script:Auth.User }
    $conf = if ($script:Redaction.Active) { '<!--ppcs-redaction-banner-->' } else { "<div class='conf'>Confidential: this report names users, environments and agents from the tenant. Share it only with people who need it.</div>" }
    return @"
<header class='hero'><div class='wrap'><p class='sub'>$subtitle</p><h1>Power Platform and Copilot Studio review</h1>
<div class='meta'><span><b>Tenant</b>$(Format-Html $M.TenantLabel)</span><span><b>Prepared by</b>$(Format-Html $by)</span><span><b>Run</b>$($M.Started.ToString('yyyy-MM-dd HH:mm'))</span><span><b>Access</b>read-only</span><span><b>Script</b>v$ScriptVersion</span></div>
$conf</div></header>
"@
}

$script:NavigatorUrl = 'https://akadrno.github.io/agent-governance-navigator-site/'

# Link only: the report never fetches from the navigator, so it stays offline-safe.
function Get-NavigatorLink {
    param([string]$Text = 'Agent Governance Navigator')
    return "<a href='$(Format-Html $script:NavigatorUrl)' target='_blank' rel='noopener noreferrer'>$(Format-Html $Text)<span aria-hidden='true'> &#8599;</span><span class='sr'> (opens in a new tab)</span></a>"
}

function Get-HtmlRelatedTool {
    return "<div class='related'><b>Related tool:</b> $(Get-NavigatorLink) is an independent web tool by GitHub user akadrno that helps you choose the Microsoft tools, admin centers and products to govern, secure and manage your agents. Use it to plan the fixes for the agent findings in this report. It is a separate third-party project, not part of this script and not an official Microsoft product; nothing in this report is fetched from it.</div>"
}

function Get-HtmlAbout {
    return @'
<div class='about-body'>
<div class='about-id'><div class='avatar' aria-hidden='true'>RR</div>
<div><div class='about-name'>Russ Rimmerman</div><div class='about-role'>Cloud Solution Architect, Microsoft</div>
<div class='about-links'><a class='alink' href='mailto:russ.rimmerman@microsoft.com'><svg viewBox='0 0 24 24' width='16' height='16' aria-hidden='true'><path fill='none' stroke='currentColor' stroke-width='1.8' stroke-linejoin='round' d='M3 6.5h18v11H3z'/><path fill='none' stroke='currentColor' stroke-width='1.8' stroke-linejoin='round' d='M3.5 7l8.5 6.5L20.5 7'/></svg>russ.rimmerman@microsoft.com</a>
<a class='alink' href='https://www.linkedin.com/in/russrimm' target='_blank' rel='noopener noreferrer'><svg viewBox='0 0 24 24' width='16' height='16' aria-hidden='true'><rect x='2.5' y='2.5' width='19' height='19' rx='3.5' fill='currentColor'/><path fill='var(--card)' d='M7 10h2.2v7H7zM8.1 6.8a1.3 1.3 0 110 2.6 1.3 1.3 0 010-2.6zM10.9 10H13v1c.4-.7 1.2-1.2 2.3-1.2 2.2 0 2.7 1.4 2.7 3.3V17h-2.2v-3.4c0-.9-.1-1.6-1.1-1.6s-1.4.7-1.4 1.6V17h-2.2z'/></svg>linkedin.com/in/russrimm</a></div></div></div>
<div class='disclaimer'><b>Not an official Microsoft product.</b> This report and the script that produced it are not supported by Microsoft. They are a personal creation of Russ Rimmerman, built to help customers evaluate the current state of their overall Power Platform governance. Results are point-in-time guidance, not a guarantee of security or compliance. Validate findings against current Microsoft documentation before acting on them.</div>
'@ + (Get-HtmlRelatedTool) + '</div>'
}

function Get-HtmlNav {
    param($M)
    $items = New-Object System.Collections.ArrayList
    [void]$items.Add(@('summary', 'Summary'))
    if ($M.Diff) { [void]$items.Add(@('changes', 'Since last run')) }
    [void]$items.Add(@('starthere', 'Start here'))
    [void]$items.Add(@('roadmap', 'Roadmap'))
    if ($script:ExceptionsLoaded) { [void]$items.Add(@('accepted', 'Accepted risks')) }
    [void]$items.Add(@('scorecard', 'Scorecard'))
    if ($script:Usage.Count -gt 0) { [void]$items.Add(@('usage', 'Usage')) }
    if (@($M.AgentRisk).Count -gt 0) { [void]$items.Add(@('agents', 'Agents')) }
    if (@($M.EnvProfile).Count -gt 0) { [void]$items.Add(@('environments', 'Environments')) }
    [void]$items.Add(@('findings', 'All findings'))
    [void]$items.Add(@('manual', 'Manual checks'))
    [void]$items.Add(@('appendix', 'Appendix'))
    $links = (@($items | ForEach-Object { "<a href='#$($_[0])'>$($_[1])</a>" })) -join ''
    return "<nav class='top' aria-label='Report sections'><div class='wrap'><div class='links'>$links</div><div class='tools'><button type='button' class='tool' id='aboutBtn' aria-haspopup='dialog'><svg viewBox='0 0 24 24' width='14' height='14' aria-hidden='true' style='vertical-align:-2px;margin-right:5px'><circle cx='12' cy='12' r='9.5' fill='none' stroke='currentColor' stroke-width='2'/><path d='M12 11v6' stroke='currentColor' stroke-width='2' stroke-linecap='round'/><circle cx='12' cy='7.5' r='1.2' fill='currentColor'/></svg>About</button><button type='button' class='tool' id='printBtn'>Print</button></div></div></nav><dialog id='aboutDlg' class='about' aria-labelledby='aboutTitle'><div class='about-head'><h2 id='aboutTitle'>About this report</h2><button type='button' class='tool' id='aboutClose' aria-label='Close about'>Close</button></div>$(Get-HtmlAbout)</dialog>"
}

function Get-HtmlSummary {
    param($M)
    $o = $M.Overall
    $c = $o.Counts
    $scoreTxt = if ($null -ne $o.Score) { "$($o.Score)" } else { '&ndash;' }
    $pctMark = if ($null -ne $o.Score) { "<small style='font-size:14px'>%</small>" } else { '' }
    $ringP = if ($null -ne $o.Score) { [int]$o.Score } else { 0 }
    $cap = if ($o.Band.Capped) { "<div class='cap'>Rated no higher than Developing while a Critical gap is open.</div>" } else { '' }
    if (-not $o.Rated) { $cap += "<div class='cap'><b>Not rated:</b> only $($o.Scored) automated check(s) returned a result (at least $MinScoredChecks are needed), so no maturity band is shown. Fix the access or data problems listed in the appendix and run again.</div>" }
    elseif ($o.Provisional) { $cap += "<div class='cap'><b>Provisional:</b> $($o.UnverifiedAll) of $($o.Scored + $o.UnverifiedAll) checks could not be verified, so this rating may change once the data is available.</div>" }
    $parts = New-Object System.Collections.ArrayList
    if (-not $o.Rated) { [void]$parts.Add('Most checks could not be verified in this run, so no conclusion about the tenant should be drawn yet.') }
    elseif ($o.CriticalFail -gt 0 -or $o.HighFail -gt 0) { [void]$parts.Add("<b>$($o.CriticalFail) Critical</b> and <b>$($o.HighFail) High</b> gap(s) are open.") }
    else { [void]$parts.Add('No Critical or High gaps were found by the automated checks.') }
    if ($o.CriticalWarn -gt 0) { [void]$parts.Add("$($o.CriticalWarn) Critical control(s) are only partly met.") }
    if ($o.Unverified -gt 0) { [void]$parts.Add("$($o.Unverified) Critical or High check(s) could not be verified.") }
    if ($o.Accepted -gt 0) {
        $accSev = if ($o.AcceptedCritical -gt 0 -or $o.AcceptedHigh -gt 0) { " ($($o.AcceptedCritical) Critical, $($o.AcceptedHigh) High)" } else { '' }
        [void]$parts.Add("$($o.Accepted) accepted risk(s)$accSev are left out of the score; see <a href='#accepted'>Accepted risks</a>.")
    }
    $headline = $parts -join ' '

    $matrix = New-Object System.Text.StringBuilder
    [void]$matrix.Append("<table class='matrix'><thead><tr><th scope='col'>Severity</th><th scope='col'>Fail</th><th scope='col'>Warning</th><th scope='col'>Not verified</th></tr></thead><tbody>")
    foreach ($sev in $SeverityOrder) {
        [void]$matrix.Append("<tr><td>$(Format-SeverityChip $sev)</td>")
        $i = 0
        foreach ($st in @('Fail', 'Warning', 'Unavailable')) {
            $i++
            $n = @($script:Findings | Where-Object { $_.Severity -eq $sev -and $_.Status -eq $st }).Count
            $cls = if ($n -eq 0) { 'h0' } else { "h$i" }
            [void]$matrix.Append("<td class='$cls'>$n</td>")
        }
        [void]$matrix.Append('</tr>')
    }
    [void]$matrix.Append('</tbody></table>')

    $legend = ''
    foreach ($p in @(@('Fail', 'i-fail', 'Fail'), @('Warning', 'i-warn', 'Warning'), @('Pass', 'i-pass', 'Pass'), @('Info', 'i-info', 'Info'), @('Unavailable', 'i-na', 'Not verified'), @('Accepted', 'i-acc', 'Accepted risk'))) {
        if ($p[0] -eq 'Accepted' -and [int]$c['Accepted'] -eq 0) { continue }
        $legend += "<li><i class='$($p[1])'></i><b>$($c[$p[0]])</b> $($p[2])</li>"
    }

    $kpiBefore = @{}
    if ($M.Diff) { foreach ($k in @($M.Diff.Kpis)) { $kpiBefore[[string]$k.Metric] = $k.Before } }
    $tiles = ''
    foreach ($k in $script:Kpi.Keys) {
        $v = $script:Kpi[$k]
        $cls = Get-KpiClass $k $v
        $pct = if ($k -match '%$') { '%' } else { '' }
        $label = ($k -replace '\s*%$', '')
        $was = if ($kpiBefore.ContainsKey($k) -and "$($kpiBefore[$k])" -ne "$v") { " <span class='delta'>was $(Format-Html $kpiBefore[$k])$pct</span>" } else { '' }
        $tiles += "<div class='tile $cls'><b>$(Format-Html $v)$pct</b><span>$(Format-Html $label)</span>$was</div>"
    }
    if ($tiles) { $tiles = "<div class='tiles' aria-label='Governance KPIs'>$tiles</div>" }

    $fix = ''
    $rank = 0
    foreach ($e in @($M.Actions | Select-Object -First 8)) {
        $rank++
        $f = $e.Finding
        $related = ''
        if (@($e.Related).Count -gt 1) { $related = " <span class='small'>Also counted in $(Format-Html ((@($e.Related | Select-Object -Skip 1)) -join ', '))</span>" }
        $val = Get-ShortText $(if ($f.Value) { $f.Value } else { $f.Detail }) 190
        $act = Get-FirstSentence $f.Recommendation 220
        $actHtml = if ($act) { "<div class='a'>$(Format-Html $act)</div>" } else { '' }
        $whyTxt = Get-WhyText $f
        if ($act -and $whyTxt) { $actHtml += "<div class='w'>$(Format-Html $whyTxt)</div>" }
        $fixRoute = Get-OwnerRoute $f
        $actHtml += "<div class='rt'><b>Suggested owner:</b> $(Format-Html $fixRoute.Role) &middot; <b>Effort:</b> $(Format-Html $fixRoute.Effort)</div>"
        $fix += "<li><span class='n'>$rank</span><div><div class='t'>$(Format-StatusChip $f.Status) $(Format-SeverityChip $f.Severity) <a href='#f-$($f.Key)'>$(Format-Html $f.Title)</a> <span class='fid'>$(Format-Html $f.Id)</span>$related</div><div class='v'>$(Format-Html $val)</div>$actHtml</div></li>"
    }
    $fixHtml = if ($fix) { "<ol class='fixlist'>$fix</ol><p class='small' style='margin-top:10px'>$(@($M.Actions).Count) item(s) need action or verification. The roadmap below groups all of them.</p>" } else { '<p>No open gaps were found by the automated checks.</p>' }

    $autoCov = @($M.Coverage | Where-Object { $_.Coverage -like 'Automated*' }).Count
    $covTotal = @($M.Coverage).Count
    $covPct = if ($covTotal -gt 0) { [int][math]::Round(100 * $autoCov / $covTotal, 0) } else { 0 }
    $okPct = if ($M.Health.Total -gt 0) { [int][math]::Round(100 * $M.Health.Ok / $M.Health.Total, 0) } else { 100 }
    $confCounts = [ordered]@{ Configuration = 0; Sample = 0; Heuristic = 0; NotVerified = 0 }
    foreach ($f in $script:Findings) { if ($confCounts.Contains([string]$f.Confidence)) { $confCounts[[string]$f.Confidence] = 1 + [int]$confCounts[[string]$f.Confidence] } }
    $tot = [math]::Max(1, $o.Total)
    $confRows = ''
    foreach ($p in @(@('Configuration', 'Confirmed by configuration'), @('Sample', 'Confirmed by sample'), @('Heuristic', 'Heuristic (verify)'), @('NotVerified', 'Not verified'))) {
        $n = [int]$confCounts[$p[0]]
        $confRows += "<div class='row'><span>$($p[1])</span><div class='mbar'><i style='width:$([int][math]::Round(100 * $n / $tot, 0))%'></i></div><b>$n</b></div>"
    }
    $covNote = if ($covTotal -eq 0) { "<p class='small'>Checklist file not found, so coverage is not calculated.</p>" } else { "<p class='small'>$($covTotal - $autoCov) checklist item(s) need a manual review (see Manual checks).</p>" }
    $lims = New-Object System.Collections.ArrayList
    [void]$lims.Add('Point-in-time, read-only snapshot. A Pass means the specific automated test passed, not that the whole checklist item is met.')
    [void]$lims.Add('Advisor-based usage covers managed environments only; flow runs and app sharing counts are sampled.')
    foreach ($l in @($script:Limitations | Group-Object Text | ForEach-Object { $_.Group[0] })) { [void]$lims.Add("$($l.Area): $($l.Text)") }
    if ($c.Unavailable -gt 0) { [void]$lims.Add("$($c.Unavailable) finding(s) could not be verified; treat them as unknown, not as passes (see Data collection health in the appendix).") }
    $limHtml = '<ul>' + ((@($lims | Select-Object -First 8) | ForEach-Object { "<li>$(Format-Html $_)</li>" }) -join '') + '</ul>'
    if ($lims.Count -gt 8) { $limHtml += "<details><summary class='small'>$($lims.Count - 8) more</summary><ul>" + ((@($lims | Select-Object -Skip 8) | ForEach-Object { "<li>$(Format-Html $_)</li>" }) -join '') + '</ul></details>' }

    return @"
<section class='panel' id='summary'><h2>Executive summary</h2><p class='lead'>Where the tenant stands, what to fix first, and how much to trust the result.</p>
<div class='grid g3'>
<div class='box'><h3>Overall maturity</h3><div class='verdict b-$($o.Band.Key)'><div class='ring' style='--p:$ringP'><span>$scoreTxt$pctMark</span></div><div><div class='big bandtxt'>$(Format-Html $o.Band.Name)</div>$cap<div class='small' style='margin-top:6px'>Score = points / (2 x scored checks): Pass 2, Warning 1, Fail 0. Bands: At risk below 40, Developing 40-69, Established 70-89, Leading 90+.</div></div></div><p class='headline'>$headline</p></div>
<div class='box'><h3>Findings by status</h3><div class='donutbox'>$(Format-DonutSvg $c $o.Total)<ul class='legend'>$legend</ul></div></div>
<div class='box'><h3>Open items by severity</h3>$($matrix.ToString())</div>
</div>
$tiles
<h3>Fix these first</h3>$fixHtml
<h3>Scope and confidence</h3>
<div class='grid g2 scope'><div class='box'><h3>How complete is this picture</h3><div class='meter'><div class='row'><span>Checklist items covered by automation</span><div class='mbar'><i style='width:$covPct%'></i></div><b>$autoCov / $covTotal</b></div><div class='row'><span>API calls that succeeded</span><div class='mbar'><i style='width:$okPct%'></i></div><b>$($M.Health.Ok) / $($M.Health.Total)</b></div>$confRows</div>$covNote</div>
<div class='box'><h3>Limitations to keep in mind</h3>$limHtml</div></div>
</section>
"@
}

function Get-HtmlChanges {
    param($M)
    $d = $M.Diff
    $when = if ($d.When) { Format-Html (ConvertTo-CellText $d.When) } else { 'an earlier run' }
    $scoreNote = ''
    if ($null -ne $d.BeforeScore -and $null -ne $M.Overall.Score) {
        $delta = [int]$M.Overall.Score - [int]$d.BeforeScore
        $sign = if ($delta -gt 0) { '+' } else { '' }
        $scoreNote = " Overall score $($d.BeforeScore)% to $($M.Overall.Score)% ($sign$delta points)."
    }
    $cards = "<div class='diffgrid'>"
    foreach ($p in @(@('New', 'New problems', $d.New.Count), @('Regressed', 'Got worse', $d.Regressed.Count), @('Improved', 'Improved', $d.Improved.Count), @('Resolved', 'Resolved', $d.Resolved.Count), @('Unchanged', 'Unchanged', $d.Unchanged))) {
        $cards += "<div class='mini'><b>$($p[2])</b><span>$($p[1])</span></div>"
    }
    if (@($d.Accepted).Count -gt 0) { $cards += "<div class='mini'><b>$(@($d.Accepted).Count)</b><span>Risks accepted</span></div>" }
    $cards += '</div>'
    $lists = ''
    foreach ($p in @(@('Regressed', 'Findings that got worse', $d.Regressed), @('New', 'New problems', $d.New), @('Improved', 'Findings that improved', $d.Improved), @('Resolved', 'Findings resolved', $d.Resolved), @('Accepted', 'Risks accepted since the last run', $d.Accepted), @('Gone', 'No longer reported (check was not run or no longer applies)', $d.Gone))) {
        $rows = @($p[2] | Select-Object Id, Title, Was, Now, Severity)
        if ($rows.Count -gt 0) { $lists += "<details><summary>$($p[1]) ($($rows.Count))</summary>$(Format-HtmlTable -Rows $rows -Columns @('Id', 'Title', 'Was', 'Now', 'Severity') -Limit 15 -MoreLabel 'rows')</details>" }
    }
    $kp = ''
    if (@($d.Kpis).Count -gt 0) { $kp = "<h3>Governance KPIs</h3>$(Format-HtmlTable -Rows @($d.Kpis) -Columns @('Metric', 'Before', 'Now', 'Change'))" }
    return "<section class='panel' id='changes'><h2>Since the last run</h2><p class='lead'>Compared with the run from $when.$scoreNote Findings are matched on check ID and title.</p>$cards$lists$kp</section>"
}

function Get-HtmlStartHere {
    param($M)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<section class='panel' id='starthere'><h2>Start here: the highest-value checks</h2><p class='lead'>If time is short, these cover the controls that most often turn a configuration gap into a data exposure or an uncontrolled action. Each row rolls up the automated findings that map to it. The last two rank by real usage.</p>")
    [void]$sb.Append("<div class='tablewrap'><table class='data st'><thead><tr><th>#</th><th>Check</th><th>Result</th><th>What we found</th><th>Area</th><th>Checklist items</th></tr></thead><tbody>")
    foreach ($r in $M.StartHere) {
        $w = $r.Worst
        if ($w) {
            $txt = if ($w.Value) { $w.Value } else { $w.Detail }
            $found = "$(Format-Html (Get-ShortText $txt 170))<a class='go' href='#f-$($w.Key)'>details</a>"
            if (@($r.ManualIds).Count -gt 0) { $found += "<div class='small'>Also review manually: $(Format-Html ((@($r.ManualIds)) -join ', '))</div>" }
        }
        else { $found = "<span class='small'>Not automated. Review manually.</span>" }
        $res = if ($r.Status -eq 'Manual') { "<span class='chip s-Manual'>Manual</span>" } else { Format-StatusChip $r.Status }
        if ($r.Unverified -gt 0 -and $r.Status -ne 'Unavailable') { $res += "<div class='small'>$($r.Unverified) not verified</div>" }
        $ids = (@($r.Ids | ForEach-Object { Get-FindingLink $_ })) -join ', '
        [void]$sb.Append("<tr><td>$($r.N)</td><td><b>$(Format-Html $r.Check)</b><div class='small'>$(Format-Html $r.Question)</div></td><td>$res</td><td class='found'>$found</td><td><a href='#area-$($r.Area)'>$($r.Area)</a></td><td>$ids</td></tr>")
    }
    [void]$sb.Append('</tbody></table></div></section>')
    return $sb.ToString()
}

function Get-HtmlRoadmap {
    param($M)
    $defs = @(
        @{ K = 'Contain'; T = 'Contain'; W = 'Days 0-30'; D = 'Critical gaps and partly met critical controls' }
        @{ K = 'Standardize'; T = 'Standardize'; W = 'Days 31-60'; D = 'High-severity items and medium gaps' }
        @{ K = 'Automate'; T = 'Automate and measure'; W = 'Days 61-90'; D = 'Medium partials and low gaps' }
        @{ K = 'Optimize'; T = 'Optimize'; W = 'Beyond 90 days'; D = 'Low-severity improvements' }
    )
    $cols = ''
    foreach ($d in $defs) {
        $items = @($M.Roadmap[$d.K])
        $li = foreach ($e in $items) {
            $f = $e.Finding
            $verify = if ($f.Status -eq 'Unavailable') { 'Verify: ' } else { '' }
            $also = if (@($e.Related).Count -gt 1) { " <span class='small'>(+$(@($e.Related).Count - 1) related)</span>" } else { '' }
            $rt = Get-OwnerRoute $f
            "<li><div><span class='id'>$(Format-Html $f.Id)</span><a href='#f-$($f.Key)'>$verify$(Format-Html $f.Title)</a>$also<div class='rt'>$(Format-Html $rt.Role) &middot; $(Format-Html $rt.Effort)</div></div>$(Format-StatusChip $f.Status)</li>"
        }
        $li = @($li)
        $body = if ($li.Count -eq 0) { "<p class='small'>Nothing in this window.</p>" } else { '<ul>' + (($li | Select-Object -First 6) -join '') + '</ul>' }
        if ($li.Count -gt 6) { $body += "<details><summary>$($li.Count - 6) more</summary><ul>" + (($li | Select-Object -Skip 6) -join '') + '</ul></details>' }
        $cols += "<div class='rcol'><h3>$($d.T) <span class='small'>($($items.Count))</span></h3><div class='when'>$($d.W): $($d.D)</div>$body</div>"
    }
    $critManual = @($M.Manual | Where-Object { $_.Priority -eq 'Critical' }).Count
    $manualNote = if (@($M.Manual).Count -gt 0) { " Plan time for the <a href='#manual'>$(@($M.Manual).Count) manual checklist item(s)</a> too, $critManual of them Critical." } else { '' }
    $handoffNote = if ($script:HandoffEnabled) { ' To hand the work over, use owner-outreach.csv (who to notify) and workitems-azure-devops.csv or workitems-jira.csv (tracker import) in the report folder.' } else { '' }
    return "<section class='panel' id='roadmap'><h2>Suggested 30/60/90-day roadmap</h2><p class='lead'>Open findings placed by severity and status: Critical goes to Contain, High and medium gaps to Standardize, the rest to later windows. Each item names the role best placed to fix it and how much work it is. Adjust each item for the customer's likelihood and impact.$manualNote$handoffNote</p><div class='road'>$cols</div><p class='small'>Planning agent governance fixes? The independent $(Get-NavigatorLink) can help you pick the Microsoft tools and admin centers for each area.</p></section>"
}

function Get-HtmlAcceptedRisk {
    $rows = @($script:ExceptionRows)
    $acc = @($script:Findings | Where-Object { $_.Status -eq 'Accepted' } | Sort-Object @{ Expression = { $SeverityOrder.IndexOf([string]$_.Severity) } }, @{ Expression = { [version]($_.Id + '.0') } }, Key)
    $needs = @($rows | Where-Object { $_.State -in @('Invalid', 'No match', 'Nothing to accept') }).Count
    $tileData = @(
        , @($acc.Count, 'Findings accepted (not scored)')
        , @(@($rows | Where-Object { $_.State -eq 'Active' }).Count, 'Active exceptions')
        , @(@($rows | Where-Object { $_.State -eq 'Expiring soon' }).Count, "Expire within $ExceptionExpiringDays days")
        , @(@($rows | Where-Object { $_.State -eq 'Expired' }).Count, 'Expired (finding open again)')
        , @($needs, 'Rows to fix or remove')
    )
    $tiles = "<div class='diffgrid'>" + ((@($tileData | ForEach-Object { "<div class='mini'><b>$($_[0])</b><span>$($_[1])</span></div>" })) -join '') + '</div>'
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<section class='panel' id='accepted'><h2>Accepted risks</h2><p class='lead'>Gaps the customer has accepted on purpose, read from $(Format-Html ([System.IO.Path]::GetFileName($ExceptionsPath))). They are left out of the score, Fix these first and the roadmap, but stay listed here until they expire. An expired row no longer applies, so its finding is open again. The script sees only this file, not exemptions granted elsewhere.</p>$tiles")
    if ($acc.Count -gt 0) {
        [void]$sb.Append("<div class='tablewrap'><table class='data'><thead><tr><th scope='col'>Finding</th><th scope='col'>Severity</th><th scope='col'>Was</th><th scope='col'>Reason</th><th scope='col'>Owner</th><th scope='col'>Expires</th></tr></thead><tbody>")
        foreach ($f in $acc) {
            $ac = $f.Acceptance
            $exp = if ($ac -and $ac.Expires) { Format-Html $ac.Expires } else { 'No expiry' }
            [void]$sb.Append("<tr><td><a href='#f-$($f.Key)'>$(Format-Html $f.Title)</a> <span class='fid'>$(Format-Html $f.Id)</span></td><td>$(Format-SeverityChip $f.Severity)</td><td>$(Format-Html $f.AcceptedFrom)</td><td class='wide'>$(Format-Html $(if ($ac) { $ac.Reason }))</td><td>$(Format-Html $(if ($ac) { $ac.Owner }))</td><td>$exp</td></tr>")
        }
        [void]$sb.Append('</tbody></table></div>')
    }
    else { [void]$sb.Append("<p class='small'>No finding is accepted in this run.</p>") }
    $display = @($rows | ForEach-Object {
            [pscustomobject]@{
                Row = $_.Row; Finding = $(if ($_.Findings) { $_.Findings } else { (($_.Id, $_.Title) -join ' ').Trim() }); State = $_.State; Reason = $_.Reason; Owner = $_.Owner
                'Approved by' = $_.ApprovedBy; Expires = (Format-ExceptionDate $_.Expires); Notes = (@($_.Notes) -join '; ')
            }
        })
    if ($display.Count -gt 0) { [void]$sb.Append("<details style='margin-top:14px'><summary>Exception register: every row in the file ($($display.Count))</summary>$(Format-HtmlTable -Rows $display -Columns @('Row', 'Finding', 'State', 'Reason', 'Owner', 'Approved by', 'Expires', 'Notes') -WideColumns @('Finding', 'Reason', 'Notes') -Limit 15 -MoreLabel 'rows')</details>") }
    [void]$sb.Append('</section>')
    return $sb.ToString()
}

function Get-HtmlScorecard {
    param($M)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<section class='panel' id='scorecard'><h2>Scorecard by assessment area</h2><p class='lead'>Each area is scored from its automated checks and placed in a maturity band. Areas with a Critical gap are held at Developing. Select an area to see its findings.</p>")
    foreach ($sec in $SectionOrder) {
        $as = @($M.Areas | Where-Object { $_.Section -eq $sec })
        if ($as.Count -eq 0) { continue }
        $topics = @($as | ForEach-Object { $_.Topic })
        $secF = @($script:Findings | Where-Object { $topics -contains $_.Topic })
        $secScore = Get-MaturityScore $secF
        $secBand = Get-MaturityBand $secScore @($secF | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'Critical' }).Count
        $secTxt = if ($null -ne $secScore) { "$($secBand.Name), $secScore%" } else { 'no scored checks' }
        [void]$sb.Append("<div class='sechead'><h3>$(Format-Html $sec)</h3><span>$(Format-Html $secTxt)</span></div><div class='cards'>")
        foreach ($a in $as) {
            $chip = if ($null -ne $a.Score) { "<span class='chip bd'>$(Format-Html $a.Band) $($a.Score)%</span>" } else { "<span class='chip s-Manual'>Not scored</span>" }
            $counts = "$($a.Fail) fail &middot; $($a.Warning) warning &middot; $($a.Pass) pass &middot; $($a.Info) info &middot; $($a.Unavailable) not verified$(if ([int]$a.Accepted -gt 0) { " &middot; $($a.Accepted) accepted" })"
            $link = if ($a.Total -gt 0) { "<a class='go' href='#area-$($a.Topic)'>View $($a.Total) finding(s)</a>" } else { "<span class='small'>No automated checks. $($a.ChecklistItems) checklist item(s) need a manual review.</span>" }
            [void]$sb.Append("<div class='acard b-$($a.BandKey)'><div class='h'><b><span class='num'>$($a.Topic)</span>$(Format-Html $a.Name)</b>$chip</div>$(Format-StackedBar $a.Fail $a.Warning $a.Pass $a.Info $a.Unavailable $a.Accepted)<div class='counts'>$counts</div><p>$(Format-Html $a.Why)</p>$link</div>")
        }
        [void]$sb.Append('</div>')
    }
    [void]$sb.Append('</section>')
    return $sb.ToString()
}

function Get-HtmlUsage {
    if ($script:Usage.Count -eq 0) { return '' }
    $usageCols = @{
        UnusedApps = @('Name', 'Environment', 'Owner', 'LastAccessed', 'Users30d')
        UnusedSites = @('Name', 'Environment', 'Owner', 'LastAccessed')
        TopUsedAssets = @('Name', 'Environment', 'Owner', 'Users30d', 'OpenRecommendations')
        TopAgents = @('Agent', 'Environment', 'Owner', 'CreditsConsumed')
        TopFlows = @('Flow', 'Environment', 'Owner', 'Runs', 'Failed', 'LastRun')
        UnusedFlows = @('Flow', 'Environment', 'Owner', 'LastRun', 'LastModified')
        UnusedAgents = @('Agent', 'Environment', 'Owner', 'Channels', 'LastPublished')
        TopSharedApps = @('App', 'Environment', 'Owner', 'SharedUsers', 'SharedGroups', 'LastModified')
    }
    $render = {
        param($Lists)
        $out = ''
        foreach ($u in $Lists) {
            $rows = @($u.Rows)
            if ($rows.Count -eq 0) { $tbl = "<p class='small'>None found.</p>" }
            else {
                $first = $rows[0]
                $cols = if ($usageCols.ContainsKey($u.Key)) { @($usageCols[$u.Key] | Where-Object { $first.PSObject.Properties[$_] }) } else { @($first.PSObject.Properties.Name | Select-Object -First 6) }
                $tbl = Format-HtmlTable -Rows $rows -Columns $cols -Limit 8 -BarColumn $u.Metric -WideColumns @('OpenRecommendations') -MoreLabel 'rows'
            }
            $out += "<div class='box'><h3 style='text-transform:none;letter-spacing:0;font-size:14px;color:var(--ink)'>$(Format-Html $u.Title) ($($rows.Count))</h3><p class='small'>$(Format-Html $u.Note)</p>$tbl</div>"
        }
        return $out
    }
    $top = @($script:Usage.Values | Where-Object { $_.Group -eq 'top' })
    $unused = @($script:Usage.Values | Where-Object { $_.Group -ne 'top' })
    $html = "<section class='panel' id='usage'><h2>Usage and adoption: highest used and not used</h2><p class='lead'>Usage multiplies impact. The busiest apps, flows and agents get the strongest controls first; assets nobody uses add exposure and cost, so they are quarantined and retired. Look-back: $UsageLookbackDays days. Full lists are in the usage-*.csv files.</p>"
    if ($top.Count -gt 0) { $html += "<div class='sechead'><h3>Highest used: protect first</h3></div><div class='grid g2'>$(& $render $top)</div>" }
    if ($unused.Count -gt 0) { $html += "<div class='sechead'><h3>Not used: retire candidates</h3></div><div class='grid g2'>$(& $render $unused)</div>" }
    return $html + '</section>'
}

function Get-HtmlAgents {
    param($M)
    $rows = @($M.AgentRisk)
    if ($rows.Count -eq 0) { return '' }
    $tiles = "<div class='tiles'>"
    foreach ($r in @('Critical', 'High', 'Medium', 'Low', 'None')) {
        $n = @($rows | Where-Object { $_.Rating -eq $r }).Count
        $cls = switch ($r) { 'Critical' { if ($n -gt 0) { 'bad' } else { 'good' } } 'High' { if ($n -gt 0) { 'warn' } else { 'good' } } default { 'neutral' } }
        $label = if ($r -eq 'None') { 'No risk signals' } else { "$r risk" }
        $tiles += "<div class='tile $cls'><b>$n</b><span>$label</span></div>"
    }
    $tiles += '</div>'
    $view = @($rows | Select-Object -First 100 | Select-Object Agent, Environment, Owner, Authentication, Channels, Published, Rating, RiskScore, Signals, Credits30d)
    $tbl = Format-HtmlTable -Rows $view -Columns @('Agent', 'Environment', 'Owner', 'Authentication', 'Channels', 'Published', 'Rating', 'RiskScore', 'Signals', 'Credits30d') -Limit 15 -BarColumn 'RiskScore' -ChipColumns @('Rating') -WideColumns @('Signals') -MoreLabel 'agents'
    $more = if ($rows.Count -gt 100) { " Showing the 100 highest of $($rows.Count); the full register is in agent-risk-register.csv." } else { " The full register is in agent-risk-register.csv." }
    return "<section class='panel' id='agents'><h2>Agent risk register</h2><p class='lead'>Every agent scored from the signals the script collected: authentication, channels, sharing, tool credentials, autonomy, knowledge and ownership. Compounding signals add up, so the top of the list is where exposure, reach and action risk meet. Credits show 30-day Copilot credit use, a proxy for how much the agent is used.</p>$tiles$tbl<p class='small'>Points per signal are listed in the Signals column (for example, no authentication on a published agent adds 35, maker credentials on write-like actions adds 14). Rating: 60+ Critical, 35+ High, 15+ Medium.$more</p><p class='small'>To decide which Microsoft tools and admin centers govern these agents, see the independent $(Get-NavigatorLink).</p></section>"
}

function Get-HtmlEnvironments {
    param($M)
    $rows = @($M.EnvProfile)
    if ($rows.Count -eq 0) { return '' }
    $view = @($rows | ForEach-Object {
            [pscustomobject]@{
                Environment = $_.Environment; Type = $_.Type; Managed = $_.Managed; 'Security group' = $_.SecurityGroup
                Assets = "$($_.Apps) / $($_.Flows) / $($_.Agents) / $($_.Sites)"; Audit = "$($_.ConversationAudit) / $($_.DataverseAudit)"
                Admins = $_.SystemAdmins; Rating = $_.Rating; Risk = $_.RiskScore; Flags = $_.Flags
            }
        })
    $tbl = Format-HtmlTable -Rows $view -Columns @('Environment', 'Type', 'Managed', 'Security group', 'Assets', 'Audit', 'Admins', 'Rating', 'Risk', 'Flags') -Limit 20 -ChipColumns @('Rating') -BarColumn 'Risk' -WideColumns @('Flags') -MoreLabel 'environments'
    return "<section class='panel' id='environments'><h2>Environment profile</h2><p class='lead'>Every environment on one line with the signals that decide its risk: management, security group, audit, admin count, assets and agent exposure. Sorted by risk; select a column heading to re-sort. Assets shows apps / flows / agents / sites. Audit shows Copilot Studio conversation audit logging / Dataverse auditing (n/a when the environment could not be read). Admins counts interactive System Administrators.</p>$tbl<p class='small'>Rating: 50+ Critical, 30+ High, 15+ Medium. The full profile is in environment-profile.csv.</p></section>"
}

function Get-HtmlFindings {
    param($M)
    $all = @($script:Findings)
    $c = $M.Overall.Counts
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<section class='panel' id='findings'><h2>All findings</h2><p class='lead'>Every automated result with its evidence, grouped by assessment area and ordered by priority. Select an area to open it, or use Expand all. Filters combine; search also looks inside evidence tables. Select the # next to a title to copy a link to it.</p><div class='filters'>")
    [void]$sb.Append("<div><label>Status</label><button type='button' class='chipbtn on' data-k='status' data-v='all'>All <span>$($all.Count)</span></button>")
    foreach ($p in @(@('Fail', 'Fail'), @('Warning', 'Warning'), @('Unavailable', 'Not verified'), @('Accepted', 'Accepted risk'), @('Pass', 'Pass'), @('Info', 'Info'))) { if ($p[0] -eq 'Accepted' -and [int]$c['Accepted'] -eq 0) { continue }; [void]$sb.Append("<button type='button' class='chipbtn' data-k='status' data-v='$($p[0])'>$($p[1]) <span>$($c[$p[0]])</span></button>") }
    [void]$sb.Append("</div><div><label>Severity</label><button type='button' class='chipbtn on' data-k='sev' data-v='all'>All</button>")
    foreach ($s in $SeverityOrder) { [void]$sb.Append("<button type='button' class='chipbtn' data-k='sev' data-v='$s'>$s <span>$(@($all | Where-Object { $_.Severity -eq $s }).Count)</span></button>") }
    $roleCount = @{}
    foreach ($f in $all) { $rr = (Get-OwnerRoute $f).Role; $roleCount[$rr] = 1 + [int]$roleCount[$rr] }
    [void]$sb.Append("</div><div><label>Owner</label><button type='button' class='chipbtn on' data-k='owner' data-v='all'>All</button>")
    foreach ($role in $OwnerRoles) { if ([int]$roleCount[$role] -gt 0) { [void]$sb.Append("<button type='button' class='chipbtn' data-k='owner' data-v='$(Format-Html $role)' title='Who is best placed to fix it'>$(Format-Html $role) <span>$($roleCount[$role])</span></button>") } }
    [void]$sb.Append("</div><div><label for='areaFilter'>Area</label><select id='areaFilter'><option value='all'>All areas</option>")
    $topics = @($all | ForEach-Object { if ($_.Topic -ge 1 -and $_.Topic -le 18) { $_.Topic } else { 0 } } | Sort-Object -Unique)
    foreach ($t in $topics) { $nm = if ($t -eq 0) { 'Other' } else { $TopicNames[$t] }; [void]$sb.Append("<option value='$t'>$t. $(Format-Html $nm)</option>") }
    [void]$sb.Append("</select></div><div><input id='q' type='search' placeholder='Search findings and evidence' aria-label='Search findings'></div><div><button type='button' class='tool' id='expandAll'>Expand all</button><button type='button' class='tool' id='collapseAll'>Collapse all</button><button type='button' class='tool' id='resetFilters'>Reset</button></div><span class='small' id='visCount'></span></div>")
    $statusRank = { param($s) switch ($s) { 'Fail' { 0 } 'Warning' { 1 } 'Unavailable' { 2 } 'Accepted' { 3 } 'Pass' { 4 } default { 5 } } }
    foreach ($t in $topics) {
        $fs = @($all | Where-Object { if ($t -eq 0) { $_.Topic -lt 1 -or $_.Topic -gt 18 } else { $_.Topic -eq $t } })
        if ($fs.Count -eq 0) { continue }
        $cnt = Get-StatusCounts $fs
        $score = Get-MaturityScore $fs
        $band = Get-MaturityBand $score @($fs | Where-Object { $_.Status -eq 'Fail' -and $_.Severity -eq 'Critical' }).Count
        $name = if ($t -eq 0) { 'Other' } else { $TopicNames[$t] }
        $why = if ($t -ge 1 -and $t -le 18) { "<p class='why'>$(Format-Html $TopicWhy[$t])</p>" } else { '' }
        $chips = ''
        if ($cnt.Fail -gt 0) { $chips += "<span class='chip s-Fail'>$($cnt.Fail) fail</span>" }
        if ($cnt.Warning -gt 0) { $chips += "<span class='chip s-Warning'>$($cnt.Warning) warning</span>" }
        if ($cnt.Unavailable -gt 0) { $chips += "<span class='chip s-Unavailable'>$($cnt.Unavailable) not verified</span>" }
        if ($cnt.Accepted -gt 0) { $chips += "<span class='chip s-Accepted'>$($cnt.Accepted) accepted</span>" }
        if ($cnt.Pass -gt 0) { $chips += "<span class='chip s-Pass'>$($cnt.Pass) pass</span>" }
        if ($cnt.Info -gt 0) { $chips += "<span class='chip s-Info'>$($cnt.Info) info</span>" }
        $bandChip = if ($null -ne $score) { "<span class='b-$($band.Key)'><span class='chip bd'>$(Format-Html $band.Name) $score%</span></span>" } else { '' }
        [void]$sb.Append("<details class='area' id='area-$t'><summary><span class='anum'>$t</span><span class='aname'>$(Format-Html $name)</span><span class='asum'>$chips$bandChip<span class='small'><span class='vis'>$($fs.Count)</span> shown</span></span></summary>$why<div class='areabody'>")
        $ordered = @($fs | Sort-Object @{ Expression = { & $statusRank $_.Status } }, @{ Expression = { Get-PriorityRank $_ } }, @{ Expression = { [version]($_.Id + '.0') } }, Key)
        foreach ($f in $ordered) { [void]$sb.Append((Format-FindingCard $f)) }
        [void]$sb.Append('</div></details>')
    }
    [void]$sb.Append('</section>')
    return $sb.ToString()
}

function Get-HtmlManual {
    param($M)
    $sb = New-Object System.Text.StringBuilder
    $items = @($M.Manual)
    [void]$sb.Append("<section class='panel' id='manual'><h2>Checklist items needing manual review ($($items.Count))</h2>")
    if (@($M.Coverage).Count -eq 0) {
        [void]$sb.Append("<p class='lead'>The checklist file was not found ($(Format-Html $ChecklistPath)), so the framework items that automation cannot cover are not listed here and findings without their own severity default to Medium. Get PPCS-Checklist.csv from the repository (or rebuild it with tools\Export-Checklist.ps1), keep it next to the script, and run again.</p></section>")
        return $sb.ToString()
    }
    [void]$sb.Append("<p class='lead'>These checklist items have no automated test, or the test could not run. Nothing is silently skipped: review each one with the customer, using the how-to-verify guidance.</p>")
    $prio = { param($p) switch ($p) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } default { 3 } } }
    foreach ($t in (@($items | ForEach-Object { [int]$_.Topic } | Sort-Object -Unique))) {
        $grp = @($items | Where-Object { [int]$_.Topic -eq $t } | Sort-Object @{ Expression = { & $prio $_.Priority } }, @{ Expression = { [version]($_.Id + '.0') } })
        $rows = @($grp | ForEach-Object { [pscustomobject]@{ ID = $_.Id; Priority = $_.Priority; Feature = $_.Feature; 'What to check' = $_.Check; 'How to verify' = $_.Verify; 'Target state' = $_.Target; Status = $_.Coverage } })
        $nm = $TopicNames[$t]
        $crit = @($grp | Where-Object { $_.Priority -eq 'Critical' }).Count
        $critChip = if ($crit -gt 0) { "<span class='chip r-Critical'>$crit Critical</span>" } else { '' }
        [void]$sb.Append("<details class='marea'><summary><span class='anum'>$t</span><span class='aname'>$(Format-Html $nm)</span><span class='asum'>$critChip<span class='chip s-Manual'>$($grp.Count) item(s)</span></span></summary><div class='areabody'>$(Format-HtmlTable -Rows $rows -Columns @('ID', 'Priority', 'Feature', 'What to check', 'How to verify', 'Target state', 'Status') -ChipColumns @('Priority'))</div></details>")
    }
    [void]$sb.Append('</section>')
    return $sb.ToString()
}

function Get-HtmlAppendix {
    param($M)
    $h = $M.Health
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<section class='panel' id='appendix'><h2>Appendix</h2><p class='lead'>How to read the results, what could not be read and why, and what was run.</p>")
    [void]$sb.Append(@'
<h3>How to read this report</h3>
<table class="legendtbl"><thead><tr><th>Result</th><th>Framework term</th><th>Meaning</th></tr></thead><tbody>
<tr><td><span class="chip s-Fail">Fail</span></td><td>Gap (0)</td><td>The control is absent or ineffective. Raise a finding.</td></tr>
<tr><td><span class="chip s-Warning">Warning</span></td><td>Partial (1)</td><td>The control exists but is inconsistent, incomplete or only partly evidenced.</td></tr>
<tr><td><span class="chip s-Pass">Pass</span></td><td>Meets (2)</td><td>The automated test passed. This is not proof that the whole checklist item is satisfied.</td></tr>
<tr><td><span class="chip s-Info">Info</span></td><td>Not scored</td><td>Context or inventory. It does not change the score.</td></tr>
<tr><td><span class="chip s-Unavailable">Not verified</span></td><td>Not verified</td><td>The data could not be read (permissions, preview endpoint or the tenant lacks the feature). Treat it as unknown, never as a pass.</td></tr>
<tr><td><span class="chip s-Accepted">Accepted risk</span></td><td>Not scored</td><td>A Fail or Warning the customer accepted in the exceptions file (-ExceptionsPath). It is left out of the score, Fix these first and the roadmap, and stays listed under Accepted risks until it expires.</td></tr>
</tbody></table>
<h3>Severity, confidence and scoring</h3>
<table class="legendtbl"><tbody>
<tr><th>Severity</th><td>The checklist's default priority: the severity if the check is a gap. Adjust it with likelihood and impact for the customer (an unauthenticated agent that only reads public content ranks below one that reaches HR data). Severity is shown only on items that need action or verification.</td></tr>
<tr><th>Confidence</th><td><b>Configuration</b>: read directly from the service. <b>Sample</b>: covers only part of the tenant because of a scan cap or sampling (see Scope and confidence). <b>Heuristic</b>: pattern-based detection such as secret scanning or write-like tool names, so verify before reporting. <b>Not verified</b>: could not be read.</td></tr>
<tr><th>Score</th><td>Points divided by twice the number of scored checks (Pass 2, Warning 1, Fail 0). Bands: below 40 At risk, 40-69 Developing, 70-89 Established, 90 and above Leading. An area or the overall result is held at Developing while it has a Critical gap. Accepted risks are not scored and do not count as open gaps.</td></tr>
<tr><th>Risk ratings</th><td>Agent and environment ratings add points for each signal that is present; the points are listed beside every row so the rating can be challenged.</td></tr>
</tbody></table>
'@)
    $hostRows = @($h.Hosts | Select-Object @{ n = 'Service'; e = { $_.Host } }, Calls, Succeeded, Failed, @{ n = 'Success rate'; e = { "$($_.SuccessRate)%" } })
    [void]$sb.Append("<h3>Data collection health</h3><p class='small'>$($h.Ok) of $($h.Total) API calls succeeded. Failed calls produce Not verified findings rather than guesses. The full call log is below and in api-log.csv (request IDs help when opening a support case).</p>")
    if ($hostRows.Count -gt 0) { [void]$sb.Append((Format-HtmlTable -Rows $hostRows -Columns @('Service', 'Calls', 'Succeeded', 'Failed', 'Success rate') -Class 'narrow')) }
    if (@($h.Causes).Count -gt 0) {
        $causeRows = @($h.Causes | Select-Object Host, Cause, Calls, @{ n = 'Example call'; e = { $_.Example } }, @{ n = 'Server message'; e = { Get-ShortText $_.Error 140 } }, @{ n = 'What to do'; e = { $_.WhatToDo } })
        [void]$sb.Append("<h3>Why some data is missing</h3>" + (Format-HtmlTable -Rows $causeRows -Columns @('Host', 'Cause', 'Calls', 'Example call', 'Server message', 'What to do') -Limit 15 -MoreLabel 'causes'))
    }
    $pr = @(@{ N = 'Authentication method'; V = $AuthMethod }, @{ N = 'Look-back (days)'; V = $UsageLookbackDays }, @{ N = 'Stale after (days)'; V = $StaleDays }, @{ N = 'Dataverse environments scanned (max)'; V = $MaxDataverseEnvironments }, @{ N = 'Environment settings calls (max)'; V = $MaxEnvironmentSettingsCalls }, @{ N = 'Flow run sample (max flows)'; V = $FlowRunSampleLimit }, @{ N = 'Agent components per environment (max)'; V = $MaxAgentComponentsPerEnvironment }, @{ N = 'Flow definitions per environment (max)'; V = $MaxFlowDefinitionsPerEnvironment }, @{ N = 'Evidence rows per CSV (max)'; V = $EvidenceRowLimit }, @{ N = 'Checklist source'; V = $script:ChecklistSource }, @{ N = 'Exceptions file'; V = $(if ($ExceptionsPath) { [System.IO.Path]::GetFileName($ExceptionsPath) } else { 'none' }) }, @{ N = 'Developer environment deadline'; V = $DeveloperEnvironmentDeadline.ToString('yyyy-MM-dd') })
    $skips = @(@('SkipLegacyApis', $SkipLegacyApis), @('SkipEntra', $SkipEntra), @('SkipDataverse', $SkipDataverse), @('SkipDeepScan', $SkipDeepScan), @('SkipUsage', $SkipUsage), @('SkipHandoff', $SkipHandoff) | Where-Object { [bool]$_[1] } | ForEach-Object { $_[0] })
    $pr += @{ N = 'Skipped steps'; V = $(if ($skips.Count -gt 0) { $skips -join ', ' } else { 'none' }) }
    [void]$sb.Append("<h3>Run parameters</h3>" + (Format-HtmlTable -Rows @($pr | ForEach-Object { [pscustomobject]@{ Setting = $_.N; Value = $_.V } }) -Columns @('Setting', 'Value') -Class 'narrow'))
    [void]$sb.Append(@'
<h3>Files in this folder</h3>
<table class="legendtbl"><tbody>
<tr><th>report.html</th><td>This report. It is self-contained and works offline.</td></tr>
<tr><th>findings.csv, findings.json</th><td>Every finding with status, severity, confidence and recommendation. Use findings.json as the baseline for the next run (-BaselinePath).</td></tr>
<tr><th>findings-register.csv</th><td>Open gaps in the framework findings-register layout, with Owner / date left blank for the remediation backlog.</td></tr>
<tr><th>agent-risk-register.csv, environment-profile.csv</th><td>Full risk views behind the Agents and Environments sections.</td></tr>
<tr><th>owner-outreach.csv</th><td>One row per asset owner with the assets that need attention and the recommended action, so an admin can notify makers. Assets with no usable owner are in one No owner row.</td></tr>
<tr><th>workitems-azure-devops.csv, workitems-jira.csv</th><td>The open Fail and Warning findings as work items for CSV import into Azure DevOps or Jira, with priority, suggested owner and effort. Not written with -SkipHandoff.</td></tr>
<tr><th>usage-*.csv, evidence\*.csv</th><td>Full lists behind the usage tables and the evidence shown under each finding.</td></tr>
<tr><th>checklist-coverage.csv</th><td>Every checklist item with its coverage: automated, attempted but unavailable, or manual.</td></tr>
<tr><th>accepted-risks.csv</th><td>Every row of the exceptions file with its state, the findings it accepted, owner, approver and expiry (only with -ExceptionsPath).</td></tr>
<tr><th>run-summary.json, api-log.csv</th><td>Scores, KPIs, limitations and parameters for this run, and the log of every API call.</td></tr>
</tbody></table>
'@)
    $log = @($script:ApiLog | Sort-Object @{ Expression = { if ($_.Ok) { 1 } else { 0 } } }, Name | Select-Object Name, Method, Endpoint, Status, Ok, Rows, Ms, Error, RequestId)
    [void]$sb.Append("<h3>Related tools</h3>" + (Get-HtmlRelatedTool))
    if ($log.Count -gt 0) { [void]$sb.Append("<details style='margin-top:14px'><summary>API call log ($($log.Count) calls, failures first)</summary>$(Format-HtmlTable -Rows $log -Columns @('Name', 'Method', 'Endpoint', 'Status', 'Ok', 'Rows', 'Ms', 'Error', 'RequestId') -Limit 25 -MoreLabel 'calls')</details>") }
    [void]$sb.Append('</section>')
    return $sb.ToString()
}

# ---- redaction (-Redact share-safe mode)
# Names, accounts, GUIDs and URLs from the tenant are replaced with consistent pseudonyms at the OUTPUT boundary only. The checks,
# scores and rankings run on the real values; every string written to a file then passes through Protect-Text (CSV cells, JSON
# values, evidence file names) or Protect-Html (report.html). What gets replaced comes from a registry of the sensitive values
# found in the run (inventory, owners, evidence tables, run parameters) plus catch-all patterns for emails, GUIDs and tenant,
# Dataverse, SharePoint and Power Pages hosts. Pseudonyms are numbered in registration order (sorted by name within each kind) and
# are never derived from the real value. Values that are common words (Production, Test, ...) are not replaced: they carry no
# identity, and replacing them everywhere would corrupt the report text and the Type column.

# Label used in the pseudonym, and the hex digit that starts a pseudonym GUID. Single kinds use the bare label.
$script:RedactionKinds = @{
    Environment = @{ Label = 'Environment'; Code = 'e' }
    Agent = @{ Label = 'Agent'; Code = 'a' }
    App = @{ Label = 'App'; Code = 'b' }
    Flow = @{ Label = 'Flow'; Code = 'f' }
    Site = @{ Label = 'Site'; Code = 'c' }
    Policy = @{ Label = 'Policy'; Code = 'd' }
    Group = @{ Label = 'Environment group'; Code = '2' }
    SecurityGroup = @{ Label = 'Security group'; Code = '3' }
    User = @{ Label = 'User'; Code = '1' }
    Component = @{ Label = 'Component'; Code = '6' }
    Network = @{ Label = 'IP range'; Code = '8' }
    Path = @{ Label = 'Local path'; Code = '0' }
    Host = @{ Label = 'Host'; Code = '7' }
    Item = @{ Label = 'Item'; Code = '5' }
    Guid = @{ Label = 'Id'; Code = '9' }
    Tenant = @{ Label = 'Tenant'; Code = '4'; Single = $true }
    Customer = @{ Label = 'Customer'; Code = '4'; Single = $true }
}

$script:RedactionGenericWords = @(
    'production', 'prod', 'sandbox', 'test', 'tests', 'testing', 'dev', 'development', 'developer', 'trial', 'default', 'demo', 'sample', 'training', 'staging'
    'teams', 'user', 'users', 'admin', 'admins', 'administrator', 'owner', 'system', 'tenant', 'name', 'group', 'groups', 'policy', 'policies', 'agent', 'agents'
    'app', 'apps', 'flow', 'flows', 'site', 'sites', 'environment', 'environments', 'copilot', 'dataverse', 'microsoft', 'sharepoint', 'power', 'platform'
    'yes', 'no', 'none', 'n/a', 'unknown', 'other', 'all', 'any', 'general', 'standard', 'personal', 'public', 'private', 'internal', 'external', 'main', 'primary'
    'global administrator', 'power platform administrator', 'dynamics 365 administrator'
)

# Evidence, usage and agent columns that hold a name of a given kind (an ordered list, so numbering is the same on every run).
$script:RedactionColumns = @(
    @{ Name = 'Environment'; Kind = 'Environment' }
    @{ Name = 'Agent'; Kind = 'Agent' }
    @{ Name = 'App'; Kind = 'App' }
    @{ Name = 'Flow'; Kind = 'Flow' }
    @{ Name = 'Site'; Kind = 'Site' }
    @{ Name = 'Policy'; Kind = 'Policy' }
    @{ Name = 'Group'; Kind = 'Group' }
    @{ Name = 'SecurityGroup'; Kind = 'SecurityGroup' }
    @{ Name = 'Security group'; Kind = 'SecurityGroup' }
    @{ Name = 'Resource'; Kind = 'Item' }
    @{ Name = 'Components'; Kind = 'Component'; Split = $true }
    @{ Name = 'AllowedIpRanges'; Kind = 'Network'; Split = $true }
    @{ Name = 'Url'; Kind = 'Host' }
    @{ Name = 'SharePointSites'; Kind = 'Host'; Split = $true }
    @{ Name = 'PublicSites'; Kind = 'Host'; Split = $true }
    @{ Name = 'HttpHosts'; Kind = 'Host'; Split = $true }
)
$script:RedactionUserColumns = @('Owner', 'OwnerUpn', 'Upn', 'User', 'DisplayName', 'Guest', 'ApplicationUser', 'CreatedBy', 'Account')

# Catch-all patterns, tried on every string: SharePoint sites (host and path), Dataverse and Dynamics hosts, tenant domains,
# Power Pages portals, environment- and tenant-specific Power Platform API hosts, email addresses and GUIDs.
$script:RedactionPattern = @(
    '(?<![\p{L}\p{N}@.-])(?:https?://)?[a-z0-9][a-z0-9-]*\.sharepoint\.com(?:/[^\s''"<>,;)\]]*)?'
    '(?<![\p{L}\p{N}@.-])(?:https?://)?(?:[a-z0-9][a-z0-9-]*\.)+dynamics\.com'
    '(?<![\p{L}\p{N}@.-])(?:https?://)?[a-z0-9][a-z0-9-]*\.onmicrosoft\.com'
    '(?<![\p{L}\p{N}@.-])(?:https?://)?[a-z0-9][a-z0-9-]*\.(?:powerappsportals|microsoftcrmportals|powerpagesites)\.(?:com|us|cn)'
    '(?<![\p{L}\p{N}@.-])(?:https?://)?[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:environment|tenant)\.api\.powerplatform\.(?:com|us)'
    '(?<![\p{L}\p{N}._%+''-])[\p{L}\p{N}._%+''-]+@[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+'
    '(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])'
) -join '|'

function Get-RedactionShape {
    param([string]$Value)
    if ($Value -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return 'guid' }
    if ($Value -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return 'email' }
    if ($Value -match '^https?://') { return 'url' }
    return 'text'
}

function Get-RedactionNumber {
    param([string]$Counter)
    $c = $script:Redaction.Counters
    $c[$Counter] = 1 + [int]$c[$Counter]
    return [int]$c[$Counter]
}

# Words that appear in the report's own static text (checklist, why rules, topic names), so a single-word name that is also
# ordinary report vocabulary is left alone instead of corrupting the prose.
function Get-RedactionVocabulary {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($w in $script:RedactionGenericWords) { [void]$set.Add($w) }
    $texts = New-Object System.Collections.ArrayList
    foreach ($row in @($script:Checklist.Values)) { foreach ($p in $row.PSObject.Properties) { [void]$texts.Add([string]$p.Value) } }
    foreach ($t in (@($TopicNames.Values) + @($TopicWhy.Values))) { [void]$texts.Add([string]$t) }
    foreach ($s in @($StartHere)) { [void]$texts.Add([string]$s.Check); [void]$texts.Add([string]$s.Question) }
    foreach ($w in @($WhyRules)) { [void]$texts.Add([string]$w.Why); [void]$texts.Add([string]$w.Title) }
    foreach ($l in @($Learn.Values)) { [void]$texts.Add([string]@($l)[0]) }
    foreach ($t in $texts) { foreach ($m in [regex]::Matches($t, '[A-Za-z]{3,}')) { [void]$set.Add($m.Value) } }
    return , $set
}

function Optimize-RedactionIndex {
    param([string]$Key)
    $list = $script:Redaction.First[$Key]
    if ($list.Count -gt 1) { $list.Sort(); $list.Reverse() }
}

# Registers one sensitive value and returns its entry (Value, Alias, Kind, Number), or $null when it is too short, generic or kept.
function Add-RedactionValue {
    param([string]$Value, [string]$Kind = 'Item', [int]$Number = 0, [switch]$AsHost)
    $r = $script:Redaction
    $v = ([string]$Value).Trim()
    if ($v.Length -lt 3) { return $null }
    $known = $r.Exact[$v]
    if ($known) { return $known }
    if ($r.Keep.Contains($v)) { return $null }
    if (-not $script:RedactionKinds.ContainsKey($Kind)) { $Kind = 'Item' }
    $meta = $script:RedactionKinds[$Kind]
    $shape = if ($AsHost) { 'host' } else { Get-RedactionShape $v }
    if ($shape -eq 'text' -and $Kind -ne 'Customer' -and $Kind -ne 'Tenant' -and $r.Vocabulary.Contains($v)) { $r.Skipped = 1 + [int]$r.Skipped; return $null }
    $n = $Number
    $alias = ''
    if ($shape -eq 'guid') {
        $n = Get-RedactionNumber ('G' + $meta.Code)
        $alias = '{0}0000000-0000-0000-0000-{1:D12}' -f $meta.Code, $n
    }
    elseif ($shape -eq 'email') {
        if ($n -le 0) { $n = Get-RedactionNumber 'User' }
        $alias = 'user{0:D3}@redacted.example' -f $n
    }
    elseif ($shape -eq 'url' -or $shape -eq 'host') {
        if ($Kind -eq 'Tenant') { $hostAlias = 'tenant.redacted.example' }
        elseif ($Kind -eq 'Environment' -and $n -gt 0) { $hostAlias = 'org{0:D3}.crm.redacted.example' -f $n }
        else { $n = Get-RedactionNumber 'Host'; $hostAlias = 'host{0:D3}.redacted.example' -f $n }
        $alias = if ($shape -eq 'url') { $v.Substring(0, $v.IndexOf('://') + 3) + $hostAlias } else { $hostAlias }
    }
    elseif ($meta.ContainsKey('Single')) { $alias = $meta.Label }
    else {
        if ($n -le 0) { $n = Get-RedactionNumber $Kind }
        $alias = '{0} {1:D3}' -f $meta.Label, $n
    }
    $entry = [pscustomobject]@{ Value = $v; Alias = $alias; Kind = $Kind; Number = $n; Shape = $shape }
    $r.Exact[$v] = $entry
    [void]$r.Entries.Add($entry)
    [void]$r.AliasSet.Add($alias)
    if ($shape -eq 'text' -or $shape -eq 'host') {
        # Free-text matching looks up runs of whole tokens: the first token picks the possible token counts, then the run itself is looked up.
        $r.Free[$v] = $entry
        $first = $r.Token.Match($v).Value
        if (-not $r.First.ContainsKey($first)) { $r.First[$first] = New-Object System.Collections.ArrayList }
        $count = $r.Token.Matches($v).Count
        if (-not $r.First[$first].Contains($count)) { [void]$r.First[$first].Add($count); if ($r.Ready) { Optimize-RedactionIndex $first } }
    }
    return $entry
}

# A person: a display name or an email address. Suffixes the owner lookup adds ("(disabled)", "(deleted account 1a2b3c4d)") are handled.
function Add-RedactionUser {
    param([string]$Value, [int]$Number = 0)
    $v = ([string]$Value).Trim()
    if ($v -match '^\(deleted account ([0-9a-fA-F]{8})\)$') { return (Add-RedactionValue $Matches[1] 'User') }
    if ($v -eq '(disabled account)') { return $null }
    $v = $v -replace '\s*\(disabled\)$', ''
    return (Add-RedactionValue $v 'User' $Number)
}

# Decides what a catch-all match becomes. In -Scan mode (the post-write check) nothing is allocated and any match that is not a
# pseudonym or a kept value is reported as a survivor.
function Resolve-RedactionMatch {
    param([string]$Value, [switch]$Scan)
    $r = $script:Redaction
    if ($r.Keep.Contains($Value)) { return $null }
    if ($Value -match '[@.]redacted\.example' -or $Value -match '^[0-9a-f]0000000-0000-0000-0000-[0-9]{12}$') { return $null }
    $shape = Get-RedactionShape $Value
    if ($shape -ne 'guid' -and $shape -ne 'email') {
        # Shared Microsoft hosts (for example api.crm.dynamics.com) carry no tenant identity.
        $hostPart = ($Value -replace '^https?://', '') -replace '[/?#].*$', ''
        if ($hostPart -match '^(api|admin|login|www|home|make)\.(crm\d*\.)?dynamics\.com$') { return $null }
    }
    $known = $r.Exact[$Value]
    if ($Scan) { return [pscustomobject]@{ Alias = ''; Kind = $(if ($known) { $known.Kind } else { 'Unregistered' }) } }
    if ($known) { return $known }
    $kind = switch ($shape) { 'guid' { 'Guid' } 'email' { 'User' } default { 'Host' } }
    return (Add-RedactionValue -Value $Value -Kind $kind -AsHost:($shape -eq 'text'))
}

# Registers whatever the catch-all patterns find in a string, so numbering is allocated in a fixed order before any file is written.
function Register-RedactionPattern {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text) -or $Text.Length -lt 8) { return }
    foreach ($m in $script:Redaction.CatchAll.Matches($Text)) { [void](Resolve-RedactionMatch -Value $m.Value) }
}

function Register-RedactionRow {
    param($Row)
    if ($null -eq $Row -or $Row -is [string] -or $Row -is [ValueType]) { return }
    $vals = @{}
    foreach ($p in $Row.PSObject.Properties) { if ($null -ne $p.Value) { $vals[$p.Name] = $p.Value } }
    if ($vals.Count -eq 0) { return }
    foreach ($col in $script:RedactionColumns) {
        if (-not $vals.ContainsKey($col.Name)) { continue }
        $raw = $vals[$col.Name]
        $text = if ($raw -is [System.Collections.IEnumerable] -and $raw -isnot [string]) { (@($raw) -join '; ') } else { [string]$raw }
        $parts = if ($col.ContainsKey('Split')) { @($text -split '\s*[;,]\s*') } else { @($text) }
        foreach ($part in $parts) {
            $s = $part.Trim()
            if ($s.Length -lt 3 -or ($col.Kind -ne 'Network' -and $s -match '^[\d\s.,:%+-]+$')) { continue }
            if ($col.Kind -eq 'Host') {
                $h = ($s -replace '^https?://', '') -replace '[/?#:].*$', ''
                if ($h -match '(^|\.)(microsoft\.com|microsoftonline\.com|office\.com|office365\.com|azure\.com|github\.com|aka\.ms)$') { continue }
                [void](Add-RedactionValue $h 'Host' -AsHost)
                if ($s -match '^https?://') { [void](Add-RedactionValue $s 'Host') }
            }
            else { [void](Add-RedactionValue $s $col.Kind) }
        }
    }
    if ($vals.ContainsKey('Name')) {
        $kind = $null
        if ($vals.ContainsKey('Kind')) { $kind = switch ([string]$vals['Kind']) { 'App' { 'App' } 'Flow' { 'Flow' } 'Agent' { 'Agent' } 'Site' { 'Site' } default { $null } } }
        elseif (-not $vals.ContainsKey('Holder') -and -not $vals.ContainsKey('Setting')) { $kind = 'Item' }
        if ($kind) { [void](Add-RedactionValue ([string]$vals['Name']) $kind) }
    }
    # People: a name and an email in the same row share one number.
    $userCols = @($script:RedactionUserColumns)
    if ($vals.ContainsKey('Holder')) { $userCols += 'Name' }
    $email = ''; $name = ''
    foreach ($c in $userCols) {
        if (-not $vals.ContainsKey($c)) { continue }
        $s = ([string]$vals[$c]).Trim()
        if ($s.Length -lt 3) { continue }
        $shape = Get-RedactionShape $s
        if ($shape -eq 'email') { if (-not $email) { $email = $s } }
        elseif ($shape -eq 'guid') { [void](Add-RedactionValue $s 'User') }
        elseif (-not $name) { $name = $s }
    }
    $ne = $null
    if ($name) { $ne = Add-RedactionUser $name }
    if ($email) {
        $ee = Add-RedactionValue $email 'User' $(if ($ne) { $ne.Number } else { 0 })
        # The email was registered earlier under another number: give it the name's number (nothing has been written yet).
        if ($ne -and $ee -and $ne.Shape -eq 'text' -and $ee.Shape -eq 'email' -and $ee.Number -ne $ne.Number -and -not $script:Redaction.Ready) {
            $ee.Number = $ne.Number
            $ee.Alias = 'user{0:D3}@redacted.example' -f $ne.Number
            [void]$script:Redaction.AliasSet.Add($ee.Alias)
        }
    }
}

function Register-RedactionSource {
    $r = $script:Redaction
    # ---- the run itself
    if ($CustomerName) { [void](Add-RedactionValue $CustomerName 'Customer') }
    $tenantLabels = New-Object System.Collections.ArrayList
    $upnDomain = ''
    if (([string]$script:Auth.User) -match '@([^@\s]+)$') { $upnDomain = $Matches[1] }
    foreach ($t in @($script:Auth.TenantGuid, $TenantId, $upnDomain)) {
        $tv = ([string]$t).Trim()
        if (-not $tv -or $tv -eq 'organizations') { continue }
        if ((Get-RedactionShape $tv) -eq 'guid') { [void](Add-RedactionValue $tv 'Tenant'); continue }
        [void](Add-RedactionValue $tv 'Tenant' -AsHost)
        $label = ($tv -split '\.')[0]
        if ($label.Length -ge 4 -and -not $r.Vocabulary.Contains($label)) { [void]$tenantLabels.Add($label) }
    }
    foreach ($u in @($script:Auth.User, $PreparedBy)) { if ($u) { [void](Add-RedactionUser $u) } }
    # ---- owners found through Microsoft Graph
    $ownerKeys = @($script:OwnerNames.Keys | Sort-Object -Property @{ Expression = { [string]$script:OwnerNames[$_] } }, @{ Expression = { [string]$_ } })
    foreach ($k in $ownerKeys) {
        [void](Add-RedactionUser ([string]$script:OwnerNames[$k]))
        [void](Add-RedactionValue ([string]$k) 'User')
    }
    # ---- owner contact addresses (hand-off files) and the owners and approvers named in the exceptions file
    foreach ($u in @($script:OwnerUpns.Values | Sort-Object)) { [void](Add-RedactionUser ([string]$u)) }
    foreach ($ex in @($script:ExceptionRows | Sort-Object -Property Row)) {
        foreach ($p in @($ex.Owner, $ex.ApprovedBy)) { if ($p) { [void](Add-RedactionUser ([string]$p)) } }
    }
    # ---- environments and their groups
    $envs = @($script:EnvMap.Values | Sort-Object -Property @{ Expression = { [string]$_.Name } }, @{ Expression = { [string]$_.Id } })
    foreach ($e in $envs) {
        $ne = Add-RedactionValue ([string]$e.Name) 'Environment'
        $n = if ($ne) { [int]$ne.Number } else { 0 }
        [void](Add-RedactionValue ([string]$e.Id) 'Environment')
        $url = ([string]$e.Url).Trim().TrimEnd('/')
        if ($url) {
            [void](Add-RedactionValue $url 'Environment' $n)
            $hostName = ''
            try { $hostName = ([uri]$url).Host } catch { Write-Verbose "Environment URL '$url' is not a valid URI." }
            if ($hostName) { [void](Add-RedactionValue $hostName 'Environment' $n -AsHost) }
        }
        [void](Add-RedactionValue ([string]$e.DataverseId) 'Environment')
        [void](Add-RedactionValue ([string]$e.SecurityGroupId) 'SecurityGroup')
        [void](Add-RedactionValue ([string]$e.GroupId) 'Group')
        [void](Add-RedactionValue ([string]$e.CreatedById) 'User')
    }
    foreach ($g in @($envs | ForEach-Object { [string]$_.Group } | Where-Object { $_ } | Sort-Object -Unique)) { [void](Add-RedactionValue $g 'Group') }
    # ---- inventory: groups, agents, apps, flows and Power Pages sites
    $inv = $script:Inventory
    if ($inv) {
        foreach ($spec in @(@('Groups', 'Group'), @('Agents', 'Agent'), @('Apps', 'App'), @('Flows', 'Flow'), @('Sites', 'Site'))) {
            $rows = @(Get-OkRows $inv[$spec[0]])
            $sorted = @($rows | Sort-Object -Property @{ Expression = { [string](Get-Prop $_ 'properties.displayName' '') } }, @{ Expression = { [string]$_.name } })
            foreach ($row in $sorted) {
                [void](Add-RedactionValue ([string](Get-Prop $row 'properties.displayName' '')) $spec[1])
                [void](Add-RedactionValue ([string]$row.name) $spec[1])
                [void](Add-RedactionValue ([string](Get-Prop $row 'properties.ownerId' '')) 'User')
                if ($spec[1] -eq 'Site') {
                    $su = ([string](Get-Prop $row 'properties.siteUrl' '')).Trim()
                    if ($su) { Register-RedactionRow ([pscustomobject]@{ Url = $su }) }
                }
            }
        }
    }
    foreach ($a in @($script:AgentView | Sort-Object -Property @{ Expression = { [string]$_.Agent } }, @{ Expression = { [string]$_.Id } })) {
        [void](Add-RedactionValue ([string]$a.Agent) 'Agent')
        [void](Add-RedactionValue ([string]$a.Id) 'Agent')
        [void](Add-RedactionValue ([string]$a.Owner) 'User')
    }
    # ---- evidence, usage and scan rows
    foreach ($f in @($script:Findings)) { foreach ($row in @($f.Evidence)) { Register-RedactionRow $row } }
    foreach ($u in @($script:Usage.Values)) { foreach ($row in @($u.Rows)) { Register-RedactionRow $row } }
    foreach ($row in @($script:DeepAgentRows)) { Register-RedactionRow $row }
    foreach ($row in @($script:OrphanedAssets)) { Register-RedactionRow $row }
    # The tenant name (for example the contoso in contoso.onmicrosoft.com) goes last so a more specific kind, such as an environment with that name, wins.
    foreach ($label in $tenantLabels) { [void](Add-RedactionValue $label 'Tenant') }
    # ---- local paths that show in limitations and run parameters
    foreach ($p in @($ChecklistPath, $BaselinePath, $OutputPath, $scriptDir, (Get-Location).Path)) {
        if (-not $p -or ([string]$p).Length -lt 4) { continue }
        [void](Add-RedactionValue ([string]$p) 'Path')
        $full = ''
        try { $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath([string]$p) } catch { Write-Verbose "Path '$p' could not be resolved." }
        if ($full -and $full.Length -ge 4) { [void](Add-RedactionValue $full 'Path') }
    }
    # ---- catch-all pass over every string that will be written, in a fixed order
    foreach ($f in @($script:Findings)) {
        foreach ($s in @($f.Title, $f.Value, $f.Detail, $f.Recommendation, $f.Source)) { Register-RedactionPattern ([string]$s) }
        foreach ($row in @($f.Evidence)) {
            if ($null -eq $row -or $row -is [ValueType]) { continue }
            if ($row -is [string]) { Register-RedactionPattern $row; continue }
            foreach ($p in $row.PSObject.Properties) { if ($p.Value -is [string]) { Register-RedactionPattern $p.Value } }
        }
    }
    foreach ($l in @($script:Limitations)) { Register-RedactionPattern ([string]$l.Text) }
    foreach ($ex in @($script:ExceptionRows | Sort-Object -Property Row)) { foreach ($s in @($ex.Reason, $ex.Title, (@($ex.Notes) -join ' '))) { Register-RedactionPattern ([string]$s) } }
    foreach ($a in @($script:ApiLog)) { foreach ($s in @($a.Name, $a.Endpoint, $a.Error)) { Register-RedactionPattern ([string]$s) } }
    foreach ($u in @($script:Usage.Values)) { foreach ($row in @($u.Rows)) { foreach ($p in $row.PSObject.Properties) { if ($p.Value -is [string]) { Register-RedactionPattern $p.Value } } } }
}

function Complete-Redaction {
    $r = $script:Redaction
    foreach ($k in @($r.First.Keys)) { Optimize-RedactionIndex $k }
    $r.Ready = $true
}

# Builds the registry from everything the run collected. Call it once the findings are final and before any file is written.
function Initialize-Redaction {
    $r = $script:Redaction
    $r.Ready = $false
    $r.Exact = @{}
    $r.Free = @{}
    $r.First = @{}
    $r.Entries = New-Object System.Collections.ArrayList
    $r.Counters = @{}
    $r.Skipped = 0
    $r.AliasSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $r.Keep = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    # The author's contact details are in the report's About card, and the Microsoft and sign-in client IDs are not tenant data.
    foreach ($k in @('russ.rimmerman@microsoft.com', 'Russ Rimmerman', '00000000-0000-0000-0000-000000000000', '00000007-0000-0000-c000-000000000000', '11648597-926c-4cf3-9c36-bcebb0ba8dcc', '1950a258-227b-4e31-a9cf-717495945fc2', '44367163-eba1-44c3-98af-f5787879f96a', '475226c6-020e-4fb2-8a90-7a972cbfc1d4', '62e90394-69f5-4237-9190-012177145e10', '7df0a125-d3be-4c96-aa54-591f83ff541c')) { [void]$r.Keep.Add($k) }
    $r.Vocabulary = Get-RedactionVocabulary
    $opts = [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant, Compiled'
    $r.CatchAll = New-Object System.Text.RegularExpressions.Regex($script:RedactionPattern, $opts)
    $r.Token = New-Object System.Text.RegularExpressions.Regex('[\p{L}\p{N}]+|[^\p{L}\p{N}\s]', $opts)
    Register-RedactionSource
    Complete-Redaction
}

# Finds what must be replaced in a string: catch-all matches plus registered values (whole tokens, case-insensitive, longest first).
# Each span is an array: Index, Length, Alias, Kind (arrays are much cheaper than objects when this runs on every string).
function Get-RedactionSpan {
    param([string]$Text, [switch]$Scan)
    $r = $script:Redaction
    $spans = New-Object System.Collections.ArrayList
    foreach ($m in $r.CatchAll.Matches($Text)) {
        $hit = Resolve-RedactionMatch -Value $m.Value -Scan:$Scan
        if ($hit) { [void]$spans.Add(@($m.Index, $m.Length, $hit.Alias, $hit.Kind)) }
    }
    $tokens = $r.Token.Matches($Text)
    $n = $tokens.Count
    for ($i = 0; $i -lt $n; $i++) {
        $t = $tokens[$i]
        $counts = $r.First[$t.Value]
        if ($null -eq $counts) { continue }
        foreach ($k in $counts) {
            $j = $i + $k - 1
            if ($j -ge $n) { continue }
            $last = $tokens[$j]
            $len = $last.Index + $last.Length - $t.Index
            $hit = $r.Free[$Text.Substring($t.Index, $len)]
            if ($null -eq $hit) { continue }
            if ($Scan -and $r.AliasSet.Contains($hit.Value)) { break }
            [void]$spans.Add(@($t.Index, $len, $hit.Alias, $hit.Kind))
            break
        }
    }
    return , $spans
}

function Protect-Text {
    param([string]$Text)
    $r = $script:Redaction
    if (-not $r.Active -or [string]::IsNullOrEmpty($Text) -or $Text.Length -lt 3) { return $Text }
    if (-not $r.Ready) { Initialize-Redaction }
    $whole = $r.Exact[$Text.Trim()]
    if ($whole) { return $Text.Replace($Text.Trim(), $whole.Alias) }
    $spans = Get-RedactionSpan -Text $Text
    if ($spans.Count -eq 0) { return $Text }
    $ordered = $spans
    if ($spans.Count -gt 1) { $ordered = @($spans | Sort-Object -Property @{ Expression = { $_[0] } }, @{ Expression = { $_[1] }; Descending = $true }) }
    $sb = New-Object System.Text.StringBuilder
    $pos = 0
    foreach ($s in $ordered) {
        $end = $s[0] + $s[1]
        if ($end -le $pos) { continue }
        if ($s[0] -gt $pos) { [void]$sb.Append($Text, $pos, $s[0] - $pos) }
        [void]$sb.Append($s[2])
        $pos = $end
    }
    if ($pos -lt $Text.Length) { [void]$sb.Append($Text, $pos, $Text.Length - $pos) }
    return $sb.ToString()
}

# Walks an object and returns a copy whose string values are redacted (used for the JSON files). Arrays come back as arrays.
function Protect-Object {
    param($Obj)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [string]) { return (Protect-Text $Obj) }
    if ($Obj -is [guid] -or $Obj -is [uri]) { return (Protect-Text ([string]$Obj)) }
    if ($Obj -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $Obj.Keys) { $o[$k] = Protect-Object $Obj[$k] }
        return $o
    }
    if ($Obj -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.ArrayList
        foreach ($i in $Obj) { [void]$list.Add((Protect-Object $i)) }
        return , $list.ToArray()
    }
    if ($Obj -is [ValueType]) { return $Obj }
    if ($Obj.PSObject -and $Obj.PSObject.Properties.Count -gt 0) {
        $o = [ordered]@{}
        foreach ($p in $Obj.PSObject.Properties) { $o[$p.Name] = Protect-Object $p.Value }
        return [pscustomobject]$o
    }
    return $Obj
}

# Redacts the human-visible parts of the report (text nodes and title, alt, href, value attributes) and leaves tags, class names,
# styles and scripts alone. With -Scan it returns the decoded visible text instead, for the post-write check.
function Convert-HtmlText {
    param([string]$Html, [switch]$Scan)
    $attr = New-Object System.Text.RegularExpressions.Regex('(\s(?:title|aria-label|alt|placeholder|href|value|content)\s*=\s*)(?:''([^'']*)''|"([^"]*)")', 'IgnoreCase')
    $evaluator = [System.Text.RegularExpressions.MatchEvaluator] {
        param($m)
        $quote = if ($m.Groups[2].Success) { "'" } else { '"' }
        $val = if ($m.Groups[2].Success) { $m.Groups[2].Value } else { $m.Groups[3].Value }
        $dec = [System.Net.WebUtility]::HtmlDecode($val)
        $red = Protect-Text $dec
        if ([string]::Equals($red, $dec, [System.StringComparison]::Ordinal)) { return $m.Value }
        return $m.Groups[1].Value + $quote + [System.Net.WebUtility]::HtmlEncode($red) + $quote
    }
    $sb = New-Object System.Text.StringBuilder
    foreach ($p in [regex]::Split($Html, '(?is)(<script\b.*?</script>|<style\b.*?</style>|<!--.*?-->|<[^>]*>)')) {
        if ($p.Length -eq 0) { continue }
        if ($p[0] -eq '<') {
            $skip = ($p -match '^<(script|style|!--)')
            if ($Scan) {
                if (-not $skip -and $p.IndexOf('=') -ge 0) {
                    foreach ($am in $attr.Matches($p)) {
                        $val = if ($am.Groups[2].Success) { $am.Groups[2].Value } else { $am.Groups[3].Value }
                        [void]$sb.Append([System.Net.WebUtility]::HtmlDecode($val)).Append("`n")
                    }
                }
            }
            elseif (-not $skip -and $p.IndexOf('=') -ge 0) { [void]$sb.Append($attr.Replace($p, $evaluator)) }
            else { [void]$sb.Append($p) }
            continue
        }
        $dec = if ($p.IndexOf('&') -ge 0) { [System.Net.WebUtility]::HtmlDecode($p) } else { $p }
        if ($Scan) { [void]$sb.Append($dec).Append("`n"); continue }
        $red = if ($p.Trim().Length -eq 0) { $dec } else { Protect-Text $dec }
        if ([string]::Equals($red, $dec, [System.StringComparison]::Ordinal)) { [void]$sb.Append($p) } else { [void]$sb.Append([System.Net.WebUtility]::HtmlEncode($red)) }
    }
    return $sb.ToString()
}

function Protect-Html {
    param([string]$Html)
    if (-not $script:Redaction.Active) { return $Html }
    if (-not $script:Redaction.Ready) { Initialize-Redaction }
    return (Convert-HtmlText -Html $Html)
}

# Post-write check: scans every text file in the output folder for a registered original or an unregistered email, GUID or tenant
# host. It reports counts and kinds only, never the values, because the report it feeds is the file that is being shared.
function Test-RedactionOutput {
    param([string]$Dir)
    $root = (Resolve-Path -LiteralPath $Dir).Path
    $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.html', '.htm', '.csv', '.json', '.txt', '.md', '.xml', '.tsv', '.yml', '.yaml', '.log') })
    $found = New-Object System.Collections.ArrayList
    foreach ($f in $files) {
        $text = [System.IO.File]::ReadAllText($f.FullName, [System.Text.Encoding]::UTF8)
        $ext = $f.Extension.ToLowerInvariant()
        if ($ext -eq '.html' -or $ext -eq '.htm') { $text = Convert-HtmlText -Html $text -Scan }
        elseif ($ext -eq '.json') { try { $text = [regex]::Unescape($text) } catch { Write-Verbose "Could not unescape $($f.Name): $($_.Exception.Message)" } }
        elseif ($ext -eq '.csv' -or $ext -eq '.tsv') { $text = $text.Replace('""', '"') }
        $hits = Get-RedactionSpan -Text $text -Scan
        if ($hits.Count -gt 0) {
            $kinds = (@($hits | ForEach-Object { $_[3] } | Sort-Object -Unique)) -join ', '
            [void]$found.Add([pscustomobject]@{ File = $f.FullName.Substring($root.Length).TrimStart('\', '/'); Count = $hits.Count; Kinds = $kinds })
        }
    }
    return [pscustomobject]@{ Files = $files.Count; Survivors = $found.ToArray(); Count = [int](($found | Measure-Object -Property Count -Sum).Sum) }
}

# The map holds the real values, so it must never be written into the folder that gets shared.
function Test-RedactionSetting {
    param([string]$OutputDir)
    $mapPath = $script:Redaction.MapPath
    if ($mapPath -and -not $script:Redaction.Active) { throw '-RedactionMapPath needs -Redact. Run again with -Redact, or leave -RedactionMapPath out.' }
    if (-not $mapPath) { return }
    if (-not $OutputDir) { $OutputDir = $OutputPath }
    $sess = $ExecutionContext.SessionState.Path
    $map = $sess.GetUnresolvedProviderPathFromPSPath($mapPath).TrimEnd('\', '/')
    $out = $sess.GetUnresolvedProviderPathFromPSPath($OutputDir).TrimEnd('\', '/')
    if ($map -ieq $out -or $map.StartsWith($out + '\', [System.StringComparison]::OrdinalIgnoreCase) -or $map.StartsWith($out + '/', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "-RedactionMapPath ($mapPath) is inside the output folder ($OutputDir), which is meant to be shared. The map holds the real names, so choose a path outside the output folder."
    }
    if (Test-Path -LiteralPath $map -PathType Container) { throw "-RedactionMapPath ($mapPath) is a folder. Give a file name, for example redaction-map.csv." }
}

function Export-RedactionMap {
    param([string]$Dir)
    $r = $script:Redaction
    if (-not $r.Active -or -not $r.MapPath) { return }
    Test-RedactionSetting -OutputDir $Dir
    $map = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($r.MapPath)
    $parent = Split-Path -Parent $map
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    $rows = @($r.Entries | Sort-Object -Property Kind, Alias | ForEach-Object { [pscustomobject]@{ Pseudonym = $_.Alias; Original = $_.Value; Kind = $_.Kind } })
    Export-SafeCsv -Rows $rows -Path $map -Raw
    Write-Warning "Redaction map written to $map. It contains the REAL names and IDs behind every pseudonym, so keep it private and never share it with the report."
}

function Get-RedactionBanner {
    param([ValidateSet('Cover', 'Footer')][string]$Place)
    if ($Place -eq 'Cover') {
        return "<div class='conf red'><b>Redacted for sharing.</b> Names, accounts, IDs and URLs from the tenant were replaced with consistent pseudonyms (for example Environment 001 and User 001). Counts, ratings and scores are unchanged. Redaction is best effort, so review the files before you share them.</div>"
    }
    return "<p class='small'><b>Redacted output.</b> Tenant names, accounts, IDs and URLs were replaced with pseudonyms. Do not use a redacted run as the baseline (-BaselinePath) for an unredacted run.</p>"
}

# ------------------------------------------------------------------ built-in checklist
# A compressed copy of PPCS-Checklist.csv so the script still has the framework checklist when it is copied on its own.
# A PPCS-Checklist.csv next to the script (or passed with -ChecklistPath) is used instead when present.
# The block below is generated by tools\Export-Checklist.ps1 from the framework document. Do not edit it by hand.
# BEGIN EMBEDDED CHECKLIST
$EmbeddedChecklist = @'
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
PbP3uLqR1P8HCzLsWmPUAAA=
'@
# END EMBEDDED CHECKLIST

function Get-BuiltInChecklist {
    try {
        $bytes = [Convert]::FromBase64String(($EmbeddedChecklist -replace '\s', ''))
        $in = New-Object System.IO.MemoryStream(, $bytes)
        $gz = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
        $reader = New-Object System.IO.StreamReader($gz, [System.Text.Encoding]::UTF8)
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
        return @($text | ConvertFrom-Csv)
    }
    catch { Write-Verbose "The built-in checklist could not be read: $($_.Exception.Message)"; return @() }
}

# ------------------------------------------------------------------ main
function Invoke-Review {
    if ($ExceptionsPath) {
        $script:ExceptionRows = @(Read-ExceptionFile -Path $ExceptionsPath)
        $script:ExceptionsLoaded = $true
        Write-Information "Loaded $($script:ExceptionRows.Count) exception row(s) from $ExceptionsPath" -InformationAction Continue
    }
    $started = Get-Date
    Test-RedactionSetting -OutputDir $OutputPath
    if ($script:Redaction.Active) { Write-Information 'Redact mode: names, accounts, IDs and URLs will be replaced with pseudonyms in every file this run writes.' -InformationAction Continue }
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
    $checklistRows = @()
    if (Test-Path -LiteralPath $ChecklistPath) {
        $checklistRows = @(Import-Csv -LiteralPath $ChecklistPath)
        $script:ChecklistSource = $ChecklistPath
        Write-Host "Loaded $($checklistRows.Count) checklist items from $ChecklistPath"
    }
    else {
        $checklistRows = @(Get-BuiltInChecklist)
        if ($checklistRows.Count -gt 0) {
            $script:ChecklistSource = 'Built into the script'
            Write-Information "Checklist file not found at $ChecklistPath; using the $($checklistRows.Count) items built into this script. Keep PPCS-Checklist.csv next to the script to customize it." -InformationAction Continue
        }
        else {
            Write-Warning "Checklist file not found at $ChecklistPath and the checklist built into this script could not be read. The report will not list manual checks or coverage, and findings without their own severity default to Medium. Get PPCS-Checklist.csv from the repository (or rebuild it with tools\Export-Checklist.ps1) and keep it next to the script."
            Add-Limitation 'Checklist' "No checklist was available, so manual checks and coverage are not listed and findings without their own severity default to Medium. Severity counts, the roadmap and Fix these first can differ from a run that has the checklist."
        }
    }
    foreach ($row in $checklistRows) { $script:Checklist[$row.Id] = $row }

    Write-Host 'Signing in...' -ForegroundColor Cyan
    Initialize-Auth
    Write-Host "Signed in as $($script:Auth.User) (tenant $($script:Auth.TenantGuid))" -ForegroundColor Green

    Write-Host 'Loading Power Platform inventory and environments...' -ForegroundColor Cyan
    $inv = Get-Inventory
    $script:Inventory = $inv
    $envMap = Merge-Environments $inv
    $script:EnvMap = $envMap
    $catalog = @{}
    foreach ($c in (Get-OkRows $inv.Connectors)) {
        $cid = [string](Get-Prop $c 'connectorId' '')
        if ($cid) { $catalog[$cid] = [pscustomobject]@{ ConnectorId = $cid; Publisher = [string](Get-Prop $c 'publisher' ''); Tier = [string](Get-Prop $c 'tier' ''); Deprecated = [bool](Get-Prop $c 'isDeprecated' $false); Name = [string](Get-Prop $c 'displayName' '') } }
    }

    if ($AuthMethod -eq 'Token') { Add-Limitation 'Authentication' 'AuthMethod Token covers api.powerplatform.com only, so Microsoft Graph, BAP and Dataverse checks could not run.' }
    if ($SkipLegacyApis) { Add-Limitation 'Scope' 'Tenant settings, tenant isolation, data policies and Managed Environment settings were skipped (-SkipLegacyApis).' }
    if ($SkipEntra) { Add-Limitation 'Scope' 'Admin roles, PIM, Conditional Access and owner lookups were skipped (-SkipEntra).' }
    if ($SkipDataverse) { Add-Limitation 'Scope' 'All Dataverse checks were skipped (-SkipDataverse): auditing, admin counts, transcripts, solutions, environment security settings, production roles, agent access settings, agent topics and flow definitions.' }
    elseif ($SkipDeepScan) { Add-Limitation 'Scope' 'Agent topic, knowledge and trigger scans and flow definition scans were skipped (-SkipDeepScan).' }
    if ($SkipUsage) { Add-Limitation 'Scope' 'The usage and adoption analysis was skipped (-SkipUsage).' }

    # Each step runs on its own: one failure becomes a Not verified finding and the run continues.
    function Invoke-Step {
        param([string]$Label, [string]$FailId, [scriptblock]$Action)
        Write-Host "Checking: $Label" -ForegroundColor Cyan
        $script:StepConfidence = 'Configuration'
        try { & $Action }
        catch { Add-Finding -Id $FailId -Title "Check failed: $Label" -Status Unavailable -Detail $_.Exception.Message -Source 'script' }
        $script:StepConfidence = 'Configuration'
    }

    Invoke-Step 'Environments' '3.2' { Test-Environments -EnvMap $envMap -Inv $inv }
    Invoke-Step 'Environment settings' '14.1' { Test-EnvironmentSettings -EnvMap $envMap }
    Invoke-Step 'Managed Environment settings' '7.1' { Test-ManagedEnvironmentConfiguration -EnvMap $envMap }
    Invoke-Step 'Environment group rules' '3.7' { Test-RuleSets }
    Invoke-Step 'Advisor recommendations' '2.6' { Test-AdvisorRecommendations }
    Invoke-Step 'Capacity and billing' '15.3' { Test-Capacity }
    Invoke-Step 'Tenant settings' '2.3' { Test-TenantSettings }
    Invoke-Step 'Tenant isolation' '2.5' { Test-TenantIsolation }
    Invoke-Step 'Data policies' '4.1' { Test-DataPolicies -EnvMap $envMap }
    $agentView = @(Invoke-Step 'Copilot Studio agents' '9.1' { Test-Agents -Inv $inv -EnvMap $envMap })
    $script:AgentView = $agentView
    [void](Invoke-Step 'apps, flows, Power Pages' '7.4' { Test-AppsFlowsSites -Inv $inv -EnvMap $envMap -Catalog $catalog })
    if (-not $SkipUsage) { Invoke-Step 'usage and adoption (highest used, not used)' '18.1' { Test-Usage -Inv $inv -EnvMap $envMap -AgentView $agentView } }
    Invoke-Step 'Copilot credit controls' '15.2' { Test-CreditControls -EnvMap $envMap }
    if (-not $SkipEntra) {
        Invoke-Step 'owners (Microsoft Graph)' '5.8' { Test-Owners -Inv $inv -EnvMap $envMap -AgentView $agentView }
        Invoke-Step 'Entra roles and Conditional Access (Microsoft Graph)' '2.1' { Test-Entra }
    }
    Invoke-Step 'shadow environments' '2.4' { Test-ShadowEnvironments -EnvMap $envMap }
    if (-not $SkipDataverse) {
        Invoke-Step 'Dataverse (per environment)' '6.4' { Test-Dataverse -EnvMap $envMap }
        Invoke-Step 'Dataverse environment security settings' '6.6' { Test-DataverseEnvironmentSecurity -EnvMap $envMap }
        Invoke-Step 'Dataverse access review' '3.3' { Test-DataverseAccess -EnvMap $envMap }
        if (-not $SkipDeepScan) {
            Invoke-Step 'agent topics, knowledge and triggers (Dataverse)' '9.7' { Test-DeepAgents -EnvMap $envMap -AgentView $agentView }
            Invoke-Step 'flow definitions (Dataverse)' '8.2' { Test-DeepFlows -EnvMap $envMap }
        }
        Invoke-Step 'agent access control and sign-in (Dataverse)' '9.1' { Test-AgentAccessControl -EnvMap $envMap -AgentView $agentView }
    }

    if ($script:ExceptionsLoaded) {
        Invoke-Step 'accepted risks (exceptions file)' '1.5' {
            Resolve-AcceptedRisk -Rows $script:ExceptionRows
            $script:Kpi['Accepted risks'] = @($script:Findings | Where-Object { $_.Status -eq 'Accepted' }).Count
            Add-ExceptionFinding -Rows $script:ExceptionRows
            if ($script:Redaction.Active) { Add-Limitation 'Redaction' 'Reasons in the exceptions file are free text written by people. Names the script knows were replaced, but other names were not, so read the Accepted risks section before sharing the report.' }
        }
    }

    if ($script:Kpi.Count -gt 0) {
        $kv = ($script:Kpi.Keys | ForEach-Object { "$_=$($script:Kpi[$_])" }) -join '; '
        Add-Finding -Id '14.8' -Title 'Governance KPIs (this run)' -Status Info -Value $kv -Source 'derived from the checks above' `
            -Recommendation 'Track these monthly: managed environment %, unauthenticated agents, orphaned assets, maker-credential agents, tenant-wide shared agents.'
    }

    $html = Write-Report -Dir $OutputPath -Started $started
    $c = @{}; foreach ($s in 'Pass', 'Fail', 'Warning', 'Info', 'Unavailable', 'Accepted') { $c[$s] = @($script:Findings | Where-Object Status -eq $s).Count }
    $ov = Get-OverallStats
    Write-Host ''
    Write-Host "Done. Fail=$($c.Fail) Warning=$($c.Warning) Pass=$($c.Pass) Info=$($c.Info) Unavailable=$($c.Unavailable)$(if ($script:ExceptionsLoaded) { " Accepted=$($c.Accepted)" })" -ForegroundColor Green
    $matText = if ($ov.Rated) { "$($ov.Band.Name) ($($ov.Score)%)$(if ($ov.Provisional) { ', provisional' })" } else { "not rated (only $($ov.Scored) check(s) returned a result)" }
    Write-Host "Maturity: $matText; Critical gaps: $($ov.CriticalFail); High gaps: $($ov.HighFail)" -ForegroundColor Green
    Write-Host "Report: $html"
    if ($OpenReport) { Start-Process $html }
}

if (-not $env:PPCS_DOTSOURCE) { Invoke-Review }
