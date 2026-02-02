# Azure Cost Management

A collection of Azure Automation runbooks and scripts for aggressive cost optimization across Azure subscriptions.

> **Created by [Joey D'Antoni](https://bsky.app/profile/joeydantoni.com) and [John Morehouse](https://bsky.app/profile/sqlrus.bsky.social), Microsoft Data Platform MVPs and hosts of [Azure Cloud Chronicles](https://azurecloudchronicles.com).**

## Overview

This repository contains automation tools designed to identify and reduce Azure spend in non-production environments. The primary runbook performs a comprehensive sweep of your subscriptions to pause, stop, scale down, or remove underutilized and orphaned resources.

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

## Usage

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

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `DryRun` | `$true` | When true, no changes are made—only reports what would happen |
| `IncludeVmDeallocation` | `$false` | When true, running VMs are deallocated |
| `IncludeVirtualWanDeletion` | `$false` | When true, Virtual WANs and child resources are deleted |
| `ExcludeSubscriptionIds` | `@()` | Array of subscription IDs to skip |
| `ExcludeResourceGroups` | `@()` | Array of resource group names to skip (case-insensitive) |
| `ProductionKeywords` | `@("prod", "production", "prd", "live")` | Keywords that trigger production protection |

## Safety Features

- **Dry Run by Default**: The runbook runs in read-only mode unless explicitly set to live
- **Production Detection**: Automatically skips resources matching production keywords in names or tags
- **Exclusion Lists**: Easily exclude specific subscriptions or resource groups
- **Opt-in Destructive Actions**: VM deallocation and vWAN deletion require explicit opt-in

## Prerequisites

### Required Azure PowerShell Modules

Import these modules in your Automation Account:
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

### Permissions

The Automation Account's managed identity requires **Contributor** role on each target subscription.

## Warning

**This runbook performs destructive operations. Do not run against production environments.**

Always execute with `-DryRun $true` first and carefully review the output before running in live mode.

## Roadmap

Additional scripts and functionality coming soon:
- Cost anomaly detection and alerting
- Scheduled scaling policies
- Resource tagging compliance reports
- Budget threshold automation

## License

MIT

## Authors

- **Joey D'Antoni** - Microsoft Data Platform MVP - [@jaborooza](https://bsky.app/profile/joeydantoni.com)
- **John Morehouse** - Microsoft Data Platform MVP - [@sqlrus](https://bsky.app/profile/sqlrus.bsky.social)

*From the [Azure Cloud Chronicles](https://azurecloudchronicles.com) team*
