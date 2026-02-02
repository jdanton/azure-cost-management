# Azure Cost Management

A collection of Azure Automation runbooks and scripts for aggressive cost optimization across Azure subscriptions.

> **Created by [Joey D'Antoni](https://bsky.app/profile/joeydantoni.com) and [John Morehouse](https://bsky.app/profile/sqlrus.bsky.social), Microsoft Data Platform MVPs and hosts of [Azure Cloud Chronicles](https://www.youtube.com/@AzureCloudChronicles).**

## Overview

This repository contains automation tools designed to identify and reduce Azure spend and improve governance. It includes:

- **Cost Optimization Runbook** — Sweeps subscriptions to pause, stop, scale down, or remove underutilized and orphaned resources
- **Tagging Policy** — Deploys Azure Policy to enforce mandatory tags for cost allocation and accountability
- **Reservations & Savings Plans Analyzer** — Audits existing commitments, identifies coverage gaps, and surfaces purchase recommendations

## Scripts

### `automation-runbook.ps1`

An Azure Automation runbook that aggressively reduces costs across all accessible subscriptions. It connects via a system-assigned managed identity and performs the following actions:

#### Pause / Stop (Reversible)
- Microsoft Fabric capacities
- Synapse Analytics dedicated SQL pools
- Azure SQL Managed Instances (General Purpose tier)
- Azure Analysis Services servers
- Azure Data Explorer (Kusto) clusters
- Application Gateways
- Virtual Machines (opt-in)

#### Deallocate (Reversible)
- Azure Firewalls (configuration preserved, public IP may change)

#### Scale Down (Reversible)
- Azure SQL Databases → Basic (≤ 2 GB) or S0 (> 2 GB)

#### Delete (Irreversible)
- Detached managed disks
- Orphaned snapshots (source disk no longer exists)
- Unattached public IP addresses
- Azure Virtual WANs (opt-in, includes hubs and gateways)

#### Audit / Warn
- Long-term backup retention policies (LTR)
- Geo-redundant backup storage
- Cosmos DB containers with high provisioned RU/s
- Premium / Enterprise Redis Cache instances
- ExpressRoute circuits and VPN Gateways
- Bastion Hosts and NAT Gateways
- Standard Load Balancers (empty)
- AKS clusters and node pools
- HDInsight / Databricks clusters
- Log Analytics workspace retention > 90 days
- Running Container Instances
- API Management (Premium tier)
- Machine Learning workspaces

---

### `azure-tagging-policy.ps1`

Deploys an Azure Policy initiative that enforces mandatory resource tagging for cost allocation and governance.

#### Required Tags

| Tag | Description | Validation |
|-----|-------------|------------|
| `CostCenter` | Finance/billing charge code | Must not be empty |
| `Environment` | Deployment stage (dev, prod, etc.) | Must be from allowed values list |
| `Department` | Owning business unit | Must not be empty |
| `CreatedDate` | Date the resource was created | Must match `YYYY-MM-DD` format |
| `Owner` | Responsible person/team email | Must not be empty |
| `Application` | Application or workload name | Must not be empty |

#### Policy Effects

The initiative contains three policy types per tag:

1. **DENY** — Blocks resource creation/update if the tag is missing or invalid
2. **AUDIT** — Reports non-compliance without blocking (for existing resources)
3. **INHERIT** — Automatically copies tag values from the resource group to child resources

#### Recommended Rollout

1. Deploy with `-EnforcementMode Audit` to assess current compliance
2. Review compliance in Azure Portal → Policy → Compliance
3. Run remediation tasks to backfill tags on existing resources
4. Switch to `-EnforcementMode Deny` once compliance is high

---

### `azure-reservations-savingsplans.ps1`

Analyzes Azure workloads for reservation and savings plan coverage and opportunities. Run interactively from PowerShell to generate a comprehensive report.

#### What It Analyzes

**Existing Commitments**
- All active Reservations — utilization %, unused hours, scope, expiry
- All active Savings Plans — utilization %, commitment amount, expiry
- Under-utilized commitments (below configurable threshold)
- Commitments expiring within configurable window

**Coverage Gap Analysis** (per subscription)
- Virtual Machines not covered by RI or Savings Plan
- SQL Databases, Elastic Pools, and Managed Instances
- Cosmos DB provisioned throughput
- App Service Plans (Premium/Isolated tiers)
- Redis Cache (Premium/Enterprise SKUs)
- Premium/Ultra Managed Disks
- Data Explorer (Kusto) clusters
- Synapse Dedicated SQL Pools
- Databricks workspaces
- Azure VMware Solution nodes

**Recommendations**
- Azure Advisor reservation & savings plan recommendations
- Consumption API recommendations (7/30/60-day lookback)
- High-uptime VM candidates (>95% availability)

#### Output

- Console report with color-coded findings
- Optional HTML report with summary cards and detailed tables
- CSV exports for reservations, savings plans, and all findings

## Usage

### Cost Optimization Runbook

```powershell
# Dry run (default) - no changes made, only reports what would happen
.\automation-runbook.ps1

# Live execution - actually performs the changes
.\automation-runbook.ps1 -DryRun $false

# Include VM deallocation
.\automation-runbook.ps1 -DryRun $false -IncludeVmDeallocation $true

# Include Virtual WAN deletion (destructive!)
.\automation-runbook.ps1 -DryRun $false -IncludeVirtualWanDeletion $true

# Exclude specific subscriptions or resource groups
.\automation-runbook.ps1 -ExcludeSubscriptionIds @("sub-id-1", "sub-id-2") `
                         -ExcludeResourceGroups @("rg-keep-this", "rg-important")
```

### Tagging Policy

```powershell
# Audit mode — assess compliance without blocking anything
.\azure-tagging-policy.ps1 -EnforcementMode Audit

# Enforce at subscription level (blocks non-compliant resources)
.\azure-tagging-policy.ps1 -EnforcementMode Deny

# Enforce at management group level with remediation tasks
.\azure-tagging-policy.ps1 -ManagementGroupName "mg-corp" `
                           -EnforcementMode Deny `
                           -CreateRemediationTasks $true

# Custom environment values
.\azure-tagging-policy.ps1 -AllowedEnvironments @("dev", "staging", "prod", "sandbox")
```

### Reservations & Savings Plans Analyzer

```powershell
# Quick analysis of current subscription
.\azure-reservations-savingsplans.ps1

# Full analysis with HTML and CSV export
.\azure-reservations-savingsplans.ps1 -ExportPath "C:\Reports" -LookbackDays 30

# Flag only severely under-utilized commitments
.\azure-reservations-savingsplans.ps1 -UtilizationThresholdPct 50 -ExpiryWarningDays 30

# Analyze a specific subscription
.\azure-reservations-savingsplans.ps1 -BillingScope "your-subscription-id"

# Skip Advisor recommendations (faster)
.\azure-reservations-savingsplans.ps1 -IncludeAdvisor $false
```

## Parameters

### Cost Optimization Runbook

| Parameter | Default | Description |
|-----------|---------|-------------|
| `DryRun` | `$true` | When true, no changes are made—only reports what would happen |
| `IncludeVmDeallocation` | `$false` | When true, running VMs are deallocated |
| `IncludeVirtualWanDeletion` | `$false` | When true, Virtual WANs and child resources are deleted |
| `ExcludeSubscriptionIds` | `@()` | Array of subscription IDs to skip |
| `ExcludeResourceGroups` | `@()` | Array of resource group names to skip (case-insensitive) |
| `ProductionKeywords` | `@("prod", "production", "prd", "live")` | Keywords that trigger production protection |

### Tagging Policy

| Parameter | Default | Description |
|-----------|---------|-------------|
| `SubscriptionId` | Current context | Target subscription (omit to use current Az context) |
| `ManagementGroupName` | — | Assign at management group scope instead of subscription |
| `EnforcementMode` | `Deny` | `Deny` blocks non-compliant resources; `Audit` only reports |
| `AllowedEnvironments` | `@("dev", "development", "test", "qa", "staging", "uat", "preprod", "prod", "production", "sandbox", "dr")` | Permitted values for the Environment tag |
| `CreateRemediationTasks` | `$false` | When true, creates remediation tasks for tag inheritance |
| `InitiativeDisplayName` | `Require Mandatory Resource Tags` | Display name for the policy initiative |

### Reservations & Savings Plans Analyzer

| Parameter | Default | Description |
|-----------|---------|-------------|
| `BillingScope` | All subscriptions | Subscription ID, billing account ID, or EA enrollment account |
| `UtilizationThresholdPct` | `80` | Reservations/SPs below this % are flagged as under-utilized |
| `ExpiryWarningDays` | `90` | Commitments expiring within this window are flagged |
| `LookbackDays` | `30` | Days of usage data for recommendations (7, 30, or 60) |
| `ExportPath` | — | Folder path for HTML report and CSV exports |
| `IncludeAdvisor` | `$true` | Pull Azure Advisor cost recommendations |

## Safety Features

- **Dry Run by Default**: The runbook runs in read-only mode unless explicitly set to live
- **Production Detection**: Automatically skips resources matching production keywords in names or tags
- **Exclusion Lists**: Easily exclude specific subscriptions or resource groups
- **Opt-in Destructive Actions**: VM deallocation and vWAN deletion require explicit opt-in

## Prerequisites

### Required Azure PowerShell Modules

Import these modules in your Automation Account (or install locally for interactive scripts):

- Az.Accounts
- Az.Resources
- Az.Sql
- Az.Synapse
- Az.Network
- Az.Compute
- Az.Kusto
- Az.AnalysisServices
- Az.Monitor
- Az.CosmosDB
- Az.Aks
- Az.Advisor (for reservations analyzer)
- Az.Billing (for reservations analyzer)

### Permissions

| Script | Required Role |
|--------|---------------|
| Cost Optimization Runbook | **Contributor** on target subscriptions |
| Tagging Policy | **Owner** or **Resource Policy Contributor** on target scope |
| Reservations Analyzer | **Reader** + **Reservation Reader** or **Billing Reader** |

## Warning

**This runbook performs destructive operations. Do not run against production environments.**

Always execute with `-DryRun $true` first and carefully review the output before running in live mode.

## Roadmap

Additional scripts and functionality coming soon:
- Cost anomaly detection and alerting
- Scheduled scaling policies
- Budget threshold automation
- Spot VM opportunity analysis

## License

MIT

## Authors

- **Joey D'Antoni** - Microsoft Data Platform MVP - [@joeydantoni.com](https://bsky.app/profile/joeydantoni.com)
- **John Morehouse** - Microsoft Data Platform MVP - [@sqlrus.bsky.social](https://bsky.app/profile/sqlrus.bsky.social)

*From the [Azure Cloud Chronicles](https://azurecloudchronicles.com) team*
