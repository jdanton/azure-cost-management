<#
.SYNOPSIS
    Azure Cost Optimization Runbook — aggressively reduces spend across all accessible subscriptions.

.DESCRIPTION
    Connects via the Automation Account's system-assigned managed identity and performs the
    following actions across every subscription the identity can reach:

    PAUSE / STOP  (reversible)
      • Microsoft Fabric capacities            (REST API suspend)
      • Synapse Analytics dedicated SQL pools   (Suspend-AzSynapseSqlPool)
      • Azure SQL Managed Instances             (Stop-AzSqlInstance — GP tier only)
      • Azure Analysis Services servers         (Suspend-AzAnalysisServicesServer)
      • Azure Data Explorer (Kusto) clusters    (Stop-AzKustoCluster)
      • Application Gateways                    (Stop-AzApplicationGateway)
      • Virtual Machines  (opt-in)              (Stop-AzVM -Force)

    DEALLOCATE  (reversible — public IP may change)
      • Azure Firewalls                         (Deallocate + Set-AzFirewall)

    SCALE DOWN  (reversible)
      • Azure SQL Databases → Basic (≤ 2 GB) or S0 (> 2 GB)

    DELETE  (irreversible ⚠️)
      • Detached managed disks                  (ManagedBy -eq $null)
      • Orphaned snapshots whose source disk no longer exists
      • Unattached public IP addresses          (IpConfiguration -eq $null)
      • Azure Virtual WANs  (opt-in)            (hubs, gateways, connections removed first)

    AUDIT / WARN
      • Long-term backup retention policies (LTR) on SQL databases
      • Geo-redundant backup storage on SQL databases / MIs
      • Cosmos DB containers with high provisioned RU/s
      • Premium / Enterprise Redis Cache instances
      • ExpressRoute circuits
      • VPN Gateways
      • Bastion Hosts
      • NAT Gateways
      • Standard Load Balancers
      • AKS clusters (node pools with many nodes)
      • HDInsight / Databricks clusters
      • Large Log Analytics workspace retention settings
      • Running Container Instances

    ╔══════════════════════════════════════════════════════════════════════╗
    ║  ⚠️  WARNING — THIS RUNBOOK IS DESTRUCTIVE                        ║
    ║  DO NOT RUN AGAINST PRODUCTION ENVIRONMENTS.                      ║
    ║  Always execute with -DryRun $true first and review the output.   ║
    ╚══════════════════════════════════════════════════════════════════════╝

.PARAMETER DryRun
    When $true (the DEFAULT), no changes are made — the runbook only reports what it
    would do. Set to $false to execute changes.

.PARAMETER IncludeVmDeallocation
    When $true, running VMs are deallocated. Default $false — VMs are only reported.

.PARAMETER IncludeVirtualWanDeletion
    When $true, Virtual WANs (and child hubs / gateways) are deleted. Default $false.

.PARAMETER ExcludeSubscriptionIds
    Array of subscription IDs to skip entirely.

.PARAMETER ExcludeResourceGroups
    Array of resource group names to skip (case-insensitive).

.PARAMETER ProductionKeywords
    If any of these keywords appear in a subscription name, resource group name, or
    resource tags, the runbook will SKIP that scope and log a production warning.

.NOTES
    Required Automation Account modules (import via Modules blade):
        Az.Accounts  Az.Resources  Az.Sql  Az.Synapse  Az.Network
        Az.Compute   Az.Kusto      Az.AnalysisServices  Az.Monitor
        Az.CosmosDB  Az.Aks

    The managed identity needs at minimum Contributor on each target subscription.

    Version : 2.0
#>

# ─────────────────────────────────────────────────────────────────────────────
# PARAMETERS
# ─────────────────────────────────────────────────────────────────────────────
param(
    [Parameter(Mandatory = $false)]
    [bool]$DryRun = $true,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeVmDeallocation = $false,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeVirtualWanDeletion = $false,

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeSubscriptionIds = @(),

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeResourceGroups = @(),

    [Parameter(Mandatory = $false)]
    [string[]]$ProductionKeywords = @("prod", "production", "prd", "live")
)

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL STATE
# ─────────────────────────────────────────────────────────────────────────────
$ErrorActionPreference = "Continue"
$script:ActionsTaken   = [System.Collections.Generic.List[string]]::new()
$script:Warnings       = [System.Collections.Generic.List[string]]::new()
$script:Errors         = [System.Collections.Generic.List[string]]::new()
$script:SkippedProd    = [System.Collections.Generic.List[string]]::new()

# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","ACTION","SKIP","AUDIT")]
        [string]$Level = "INFO"
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        "INFO"   { "[INFO]   " }
        "WARN"   { "[⚠ WARN] " }
        "ERROR"  { "[❌ ERROR]" }
        "ACTION" { "[✅ ACTION]" }
        "SKIP"   { "[⏭ SKIP] " }
        "AUDIT"  { "[🔍 AUDIT]" }
    }
    $line = "$ts $prefix $Message"
    Write-Output $line

    switch ($Level) {
        "WARN"   { $script:Warnings.Add($Message) }
        "ERROR"  { $script:Errors.Add($Message) }
        "ACTION" { $script:ActionsTaken.Add($Message) }
    }
}

function Test-IsExcludedResourceGroup {
    param([string]$ResourceGroupName)
    foreach ($excluded in $ExcludeResourceGroups) {
        if ($ResourceGroupName -ieq $excluded) { return $true }
    }
    return $false
}

function Test-ProductionIndicators {
    <#
        Returns $true if any production keyword is found in the supplied strings
        or in tag values. Callers should SKIP the resource/scope when this returns $true.
    #>
    param(
        [string[]]$NamesToCheck,
        [hashtable]$Tags = @{}
    )
    $searchSpace = @($NamesToCheck)
    if ($Tags) {
        $searchSpace += $Tags.Values | ForEach-Object { "$_" }
        $searchSpace += $Tags.Keys   | ForEach-Object { "$_" }
    }
    foreach ($name in $searchSpace) {
        foreach ($kw in $ProductionKeywords) {
            if ($name -imatch [regex]::Escape($kw)) { return $true }
        }
    }
    return $false
}

function Invoke-ActionOrDryRun {
    <#
        Wraps every mutating operation. In DryRun mode the ScriptBlock is NOT executed.
    #>
    param(
        [string]$Description,
        [scriptblock]$Action
    )
    if ($DryRun) {
        Write-Log "[DRY RUN] Would: $Description" -Level ACTION
    } else {
        try {
            Write-Log "Executing: $Description" -Level ACTION
            & $Action
        } catch {
            Write-Log "Failed — $Description — $_" -Level ERROR
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 1.  FABRIC CAPACITIES  (REST API — no native cmdlet yet)
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-PauseFabricCapacities {
    Write-Log "── Checking Microsoft Fabric capacities ──"
    $caps = Get-AzResource -ResourceType "Microsoft.Fabric/capacities" -ErrorAction SilentlyContinue
    if (-not $caps) { Write-Log "No Fabric capacities found." ; return }

    foreach ($cap in $caps) {
        if (Test-IsExcludedResourceGroup $cap.ResourceGroupName) {
            Write-Log "Skipping Fabric capacity $($cap.Name) — excluded RG." -Level SKIP ; continue
        }
        if (Test-ProductionIndicators -NamesToCheck @($cap.Name, $cap.ResourceGroupName) -Tags ($cap.Tags ?? @{})) {
            Write-Log "Skipping Fabric capacity $($cap.Name) — production indicator." -Level WARN
            $script:SkippedProd.Add("Fabric:$($cap.Name)") ; continue
        }

        # Read current state via REST
        $getUri = "$($cap.ResourceId)?api-version=2023-11-01"
        try {
            $detail = Invoke-AzRestMethod -Path $getUri -Method GET -ErrorAction Stop
            $body   = $detail.Content | ConvertFrom-Json
            $state  = $body.properties.state
        } catch {
            Write-Log "Unable to read state for Fabric capacity $($cap.Name): $_" -Level ERROR ; continue
        }

        if ($state -ieq "Active") {
            Invoke-ActionOrDryRun -Description "Suspend Fabric capacity $($cap.Name) (RG: $($cap.ResourceGroupName))" -Action {
                $suspendUri = "$($cap.ResourceId)/suspend?api-version=2023-11-01"
                $result = Invoke-AzRestMethod -Path $suspendUri -Method POST -ErrorAction Stop
                if ($result.StatusCode -notin 200,202) {
                    throw "HTTP $($result.StatusCode): $($result.Content)"
                }
            }
        } else {
            Write-Log "Fabric capacity $($cap.Name) already in state '$state'." -Level SKIP
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 2.  AZURE SQL DATABASES — scale to Basic (≤2 GB) or S0
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-ScaleDownSqlDatabases {
    Write-Log "── Checking Azure SQL Databases ──"
    $servers = Get-AzSqlServer -ErrorAction SilentlyContinue
    if (-not $servers) { Write-Log "No SQL servers found." ; return }

    foreach ($srv in $servers) {
        if (Test-IsExcludedResourceGroup $srv.ResourceGroupName) {
            Write-Log "Skipping SQL server $($srv.ServerName) — excluded RG." -Level SKIP ; continue
        }
        if (Test-ProductionIndicators -NamesToCheck @($srv.ServerName, $srv.ResourceGroupName) -Tags ($srv.Tags ?? @{})) {
            Write-Log "Skipping SQL server $($srv.ServerName) — production indicator." -Level WARN
            $script:SkippedProd.Add("SqlServer:$($srv.ServerName)") ; continue
        }

        $dbs = Get-AzSqlDatabase -ServerName $srv.ServerName -ResourceGroupName $srv.ResourceGroupName -ErrorAction SilentlyContinue
        foreach ($db in $dbs) {
            # Skip system databases and already-optimized tiers
            if ($db.DatabaseName -eq "master") { continue }
            $edition = $db.Edition
            $slo     = $db.CurrentServiceObjectiveName

            # Already at Basic or S0 — nothing to do
            if ($edition -ieq "Basic" -or $slo -ieq "Basic") {
                Write-Log "SQL DB $($srv.ServerName)/$($db.DatabaseName) already on Basic." -Level SKIP ; continue
            }
            if ($slo -ieq "S0") {
                Write-Log "SQL DB $($srv.ServerName)/$($db.DatabaseName) already on S0." -Level SKIP ; continue
            }

            # Skip Hyperscale / DataWarehouse — cannot trivially scale to DTU
            if ($edition -iin @("Hyperscale", "DataWarehouse")) {
                Write-Log "SQL DB $($srv.ServerName)/$($db.DatabaseName) is $edition — skipping (manual review needed)." -Level WARN
                continue
            }

            # Determine current size to pick Basic vs S0
            # Basic max = 2 GB (2,147,483,648 bytes).  S0 max = 250 GB.
            $maxSizeBytes = $db.MaxSizeBytes
            $currentUsedBytes = 0
            try {
                $metrics = Get-AzSqlDatabaseUsage -ServerName $srv.ServerName `
                               -DatabaseName $db.DatabaseName `
                               -ResourceGroupName $srv.ResourceGroupName -ErrorAction SilentlyContinue
                $sizeUsage = $metrics | Where-Object { $_.ResourceName -eq "database_size" -or $_.DisplayName -like "*size*" } | Select-Object -First 1
                if ($sizeUsage) { $currentUsedBytes = $sizeUsage.CurrentValue }
            } catch {
                # If we can't determine size, be safe and choose S0
                Write-Log "Could not determine size for $($db.DatabaseName), defaulting to S0." -Level WARN
            }

            # Fallback: if we couldn't get usage, infer from MaxSizeBytes
            # If MaxSizeBytes > 2 GB the DB was configured for more than Basic allows
            $basicMaxBytes = 2147483648  # 2 GB
            if ($currentUsedBytes -gt 0) {
                $targetEdition = if ($currentUsedBytes -le $basicMaxBytes) { "Basic" } else { "Standard" }
            } else {
                $targetEdition = if ($maxSizeBytes -le $basicMaxBytes) { "Basic" } else { "Standard" }
            }
            $targetSlo = if ($targetEdition -eq "Basic") { "Basic" } else { "S0" }
            $sizeInfo  = if ($currentUsedBytes -gt 0) { "$([math]::Round($currentUsedBytes / 1MB, 1)) MB used" } else { "MaxSize=$([math]::Round($maxSizeBytes / 1GB, 1)) GB" }

            Invoke-ActionOrDryRun -Description "Scale SQL DB $($srv.ServerName)/$($db.DatabaseName) from $edition/$slo → $targetEdition/$targetSlo ($sizeInfo)" -Action {
                Set-AzSqlDatabase -ServerName $srv.ServerName `
                    -DatabaseName $db.DatabaseName `
                    -ResourceGroupName $srv.ResourceGroupName `
                    -Edition $targetEdition `
                    -RequestedServiceObjectiveName $targetSlo `
                    -ErrorAction Stop | Out-Null
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 3.  SYNAPSE DEDICATED SQL POOLS
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-PauseSynapsePools {
    Write-Log "── Checking Synapse Dedicated SQL Pools ──"
    $workspaces = Get-AzSynapseWorkspace -ErrorAction SilentlyContinue
    if (-not $workspaces) { Write-Log "No Synapse workspaces found." ; return }

    foreach ($ws in $workspaces) {
        if (Test-IsExcludedResourceGroup $ws.ResourceGroupName) {
            Write-Log "Skipping Synapse workspace $($ws.Name) — excluded RG." -Level SKIP ; continue
        }
        if (Test-ProductionIndicators -NamesToCheck @($ws.Name, $ws.ResourceGroupName) -Tags ($ws.Tags ?? @{})) {
            Write-Log "Skipping Synapse workspace $($ws.Name) — production indicator." -Level WARN
            $script:SkippedProd.Add("Synapse:$($ws.Name)") ; continue
        }

        $pools = Get-AzSynapseSqlPool -WorkspaceName $ws.Name -ResourceGroupName $ws.ResourceGroupName -ErrorAction SilentlyContinue
        foreach ($pool in $pools) {
            if ($pool.Status -ieq "Online") {
                Invoke-ActionOrDryRun -Description "Pause Synapse SQL pool $($ws.Name)/$($pool.SqlPoolName)" -Action {
                    Suspend-AzSynapseSqlPool -WorkspaceName $ws.Name `
                        -Name $pool.SqlPoolName `
                        -ResourceGroupName $ws.ResourceGroupName `
                        -ErrorAction Stop | Out-Null
                }
            } else {
                Write-Log "Synapse pool $($ws.Name)/$($pool.SqlPoolName) status=$($pool.Status)." -Level SKIP
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 4.  AZURE FIREWALLS — deallocate (removes compute cost; config preserved)
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-DeallocateFirewalls {
    Write-Log "── Checking Azure Firewalls ──"
    $firewalls = Get-AzFirewall -ErrorAction SilentlyContinue
    if (-not $firewalls) { Write-Log "No Azure Firewalls found." ; return }

    foreach ($fw in $firewalls) {
        if (Test-IsExcludedResourceGroup $fw.ResourceGroupName) {
            Write-Log "Skipping Firewall $($fw.Name) — excluded RG." -Level SKIP ; continue
        }
        if (Test-ProductionIndicators -NamesToCheck @($fw.Name, $fw.ResourceGroupName) -Tags ($fw.Tag ?? @{})) {
            Write-Log "Skipping Firewall $($fw.Name) — production indicator." -Level WARN
            $script:SkippedProd.Add("Firewall:$($fw.Name)") ; continue
        }

        # A deallocated firewall has no IP configurations
        if ($fw.IpConfigurations.Count -eq 0 -and -not $fw.ManagementIpConfiguration) {
            Write-Log "Firewall $($fw.Name) is already deallocated." -Level SKIP ; continue
        }

        Invoke-ActionOrDryRun -Description "Deallocate Azure Firewall $($fw.Name) (~`$1.25/hr savings)" -Action {
            $fw.Deallocate()
            Set-AzFirewall -AzureFirewall $fw -ErrorAction Stop | Out-Null
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 5.  AZURE SQL MANAGED INSTANCES — stop (General Purpose only)
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-StopSqlManagedInstances {
    Write-Log "── Checking Azure SQL Managed Instances ──"
    $instances = Get-AzSqlInstance -ErrorAction SilentlyContinue
    if (-not $instances) { Write-Log "No SQL Managed Instances found." ; return }

    foreach ($mi in $instances) {
        if (Test-IsExcludedResourceGroup $mi.ResourceGroupName) {
            Write-Log "Skipping MI $($mi.ManagedInstanceName) — excluded RG." -Level SKIP ; continue
        }
        if (Test-ProductionIndicators -NamesToCheck @($mi.ManagedInstanceName, $mi.ResourceGroupName) -Tags ($mi.Tags ?? @{})) {
            Write-Log "Skipping MI $($mi.ManagedInstanceName) — production indicator." -Level WARN
            $script:SkippedProd.Add("SqlMI:$($mi.ManagedInstanceName)") ; continue
        }

        if ($mi.Sku.Tier -ine "GeneralPurpose") {
            Write-Log "MI $($mi.ManagedInstanceName) is $($mi.Sku.Tier) — stop/start only supports General Purpose." -Level WARN
            continue
        }

        # Check if already stopped by querying state
        $state = $mi.State
        if ($state -iin @("Stopped", "Stopping")) {
            Write-Log "MI $($mi.ManagedInstanceName) is already $state." -Level SKIP ; continue
        }

        Invoke-ActionOrDryRun -Description "Stop SQL Managed Instance $($mi.ManagedInstanceName) (tier: $($mi.Sku.Name))" -Action {
            Stop-AzSqlInstance -Name $mi.ManagedInstanceName `
                -ResourceGroupName $mi.ResourceGroupName `
                -Force -ErrorAction Stop | Out-Null
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 6.  VIRTUAL WANs — delete (opt-in, extremely destructive)
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RemoveVirtualWans {
    Write-Log "── Checking Azure Virtual WANs ──"
    $vwans = Get-AzVirtualWan -ErrorAction SilentlyContinue
    if (-not $vwans) { Write-Log "No Virtual WANs found." ; return }

    foreach ($vwan in $vwans) {
        $rg = $vwan.Id -replace '(?i)^/subscriptions/[^/]+/resourceGroups/([^/]+)/.*', '$1'
        if (Test-IsExcludedResourceGroup $rg) {
            Write-Log "Skipping vWAN $($vwan.Name) — excluded RG." -Level SKIP ; continue
        }
        if (Test-ProductionIndicators -NamesToCheck @($vwan.Name, $rg)) {
            Write-Log "Skipping vWAN $($vwan.Name) — production indicator." -Level WARN
            $script:SkippedProd.Add("vWAN:$($vwan.Name)") ; continue
        }

        if (-not $IncludeVirtualWanDeletion) {
            Write-Log "vWAN found: $($vwan.Name) (RG: $rg). Deletion SKIPPED — set -IncludeVirtualWanDeletion `$true to enable." -Level AUDIT
            $script:Warnings.Add("Virtual WAN $($vwan.Name) exists and is potentially expensive — deletion not enabled.")
            continue
        }

        Write-Log "⚠️  DESTRUCTIVE: Will attempt to remove vWAN $($vwan.Name) and all child resources." -Level WARN

        Invoke-ActionOrDryRun -Description "Delete Virtual WAN $($vwan.Name) and child hubs/gateways" -Action {
            # 1. Remove VPN/ER gateways in each hub
            $hubs = Get-AzVirtualHub -ResourceGroupName $rg -ErrorAction SilentlyContinue |
                    Where-Object { $_.VirtualWan.Id -ieq $vwan.Id }
            foreach ($hub in $hubs) {
                # VPN Gateway
                $vpnGw = Get-AzVpnGateway -ResourceGroupName $rg -ErrorAction SilentlyContinue |
                         Where-Object { $_.VirtualHub.Id -ieq $hub.Id }
                foreach ($gw in $vpnGw) {
                    Write-Log "  Removing VPN gateway $($gw.Name)..." -Level ACTION
                    Remove-AzVpnGateway -Name $gw.Name -ResourceGroupName $rg -Force -ErrorAction Stop | Out-Null
                }
                # ExpressRoute Gateway
                $erGw = Get-AzExpressRouteGateway -ResourceGroupName $rg -ErrorAction SilentlyContinue |
                        Where-Object { $_.VirtualHub.Id -ieq $hub.Id }
                foreach ($gw in $erGw) {
                    Write-Log "  Removing ER gateway $($gw.Name)..." -Level ACTION
                    Remove-AzExpressRouteGateway -ResourceGroupName $rg -Name $gw.Name -Force -ErrorAction Stop | Out-Null
                }
                # Remove hub
                Write-Log "  Removing virtual hub $($hub.Name)..." -Level ACTION
                Remove-AzVirtualHub -Name $hub.Name -ResourceGroupName $rg -Force -ErrorAction Stop | Out-Null
            }
            # 2. Remove the vWAN itself
            Remove-AzVirtualWan -Name $vwan.Name -ResourceGroupName $rg -Force -ErrorAction Stop | Out-Null
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 7.  DETACHED MANAGED DISKS
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RemoveDetachedDisks {
    Write-Log "── Checking for detached managed disks ──"
    $disks = Get-AzDisk -ErrorAction SilentlyContinue | Where-Object { [string]::IsNullOrEmpty($_.ManagedBy) }
    if (-not $disks) { Write-Log "No detached managed disks found." ; return }

    foreach ($disk in $disks) {
        if (Test-IsExcludedResourceGroup $disk.ResourceGroupName) {
            Write-Log "Skipping disk $($disk.Name) — excluded RG." -Level SKIP ; continue
        }
        if (Test-ProductionIndicators -NamesToCheck @($disk.Name, $disk.ResourceGroupName) -Tags ($disk.Tags ?? @{})) {
            Write-Log "Skipping disk $($disk.Name) — production indicator." -Level WARN
            $script:SkippedProd.Add("Disk:$($disk.Name)") ; continue
        }

        $sizeGB = $disk.DiskSizeGB
        $sku    = $disk.Sku.Name
        Invoke-ActionOrDryRun -Description "Delete detached disk $($disk.Name) ($sizeGB GB, $sku, RG: $($disk.ResourceGroupName))" -Action {
            Remove-AzDisk -ResourceGroupName $disk.ResourceGroupName -DiskName $disk.Name -Force -ErrorAction Stop | Out-Null
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 8.  ORPHANED SNAPSHOTS
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RemoveOrphanedSnapshots {
    Write-Log "── Checking for orphaned snapshots ──"
    $snapshots = Get-AzSnapshot -ErrorAction SilentlyContinue
    if (-not $snapshots) { Write-Log "No snapshots found." ; return }

    # Build a set of existing disk IDs for fast lookup
    $existingDiskIds = @{}
    Get-AzDisk -ErrorAction SilentlyContinue | ForEach-Object { $existingDiskIds[$_.Id] = $true }

    foreach ($snap in $snapshots) {
        if (Test-IsExcludedResourceGroup $snap.ResourceGroupName) {
            Write-Log "Skipping snapshot $($snap.Name) — excluded RG." -Level SKIP ; continue
        }
        if (Test-ProductionIndicators -NamesToCheck @($snap.Name, $snap.ResourceGroupName) -Tags ($snap.Tags ?? @{})) {
            Write-Log "Skipping snapshot $($snap.Name) — production indicator." -Level WARN
            $script:SkippedProd.Add("Snapshot:$($snap.Name)") ; continue
        }

        $sourceDiskId = $snap.CreationData.SourceResourceId
        $isOrphaned   = (-not $sourceDiskId) -or (-not $existingDiskIds.ContainsKey($sourceDiskId))

        if ($isOrphaned) {
            $sizeGB = $snap.DiskSizeGB
            Invoke-ActionOrDryRun -Description "Delete orphaned snapshot $($snap.Name) ($sizeGB GB, RG: $($snap.ResourceGroupName))" -Action {
                Remove-AzSnapshot -ResourceGroupName $snap.ResourceGroupName -SnapshotName $snap.Name -Force -ErrorAction Stop | Out-Null
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 9.  UNATTACHED PUBLIC IP ADDRESSES
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-RemoveUnattachedPublicIPs {
    Write-Log "── Checking for unattached public IP addresses ──"
    $pips = Get-AzPublicIpAddress -ErrorAction SilentlyContinue | Where-Object { $null -eq $_.IpConfiguration }
    if (-not $pips) { Write-Log "No unattached public IPs found." ; return }

    foreach ($pip in $pips) {
        if (Test-IsExcludedResourceGroup $pip.ResourceGroupName) {
            Write-Log "Skipping PIP $($pip.Name) — excluded RG." -Level SKIP ; continue
        }
        if (Test-ProductionIndicators -NamesToCheck @($pip.Name, $pip.ResourceGroupName) -Tags ($pip.Tag ?? @{})) {
            Write-Log "Skipping PIP $($pip.Name) — production indicator." -Level WARN
            $script:SkippedProd.Add("PIP:$($pip.Name)") ; continue
        }

        $sku = $pip.Sku.Name
        $method = $pip.PublicIpAllocationMethod
        Invoke-ActionOrDryRun -Description "Delete unattached public IP $($pip.Name) ($sku, $method, RG: $($pip.ResourceGroupName))" -Action {
            Remove-AzPublicIpAddress -ResourceGroupName $pip.ResourceGroupName -Name $pip.Name -Force -ErrorAction Stop | Out-Null
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 10. LONG-TERM BACKUP RETENTION POLICIES (SQL DB)
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-AuditBackupPolicies {
    Write-Log "── Auditing long-term backup retention policies ──"
    $servers = Get-AzSqlServer -ErrorAction SilentlyContinue
    if (-not $servers) { return }

    foreach ($srv in $servers) {
        $dbs = Get-AzSqlDatabase -ServerName $srv.ServerName -ResourceGroupName $srv.ResourceGroupName -ErrorAction SilentlyContinue |
               Where-Object { $_.DatabaseName -ne "master" }

        foreach ($db in $dbs) {
            # Long-Term Retention (LTR)
            try {
                $ltr = Get-AzSqlDatabaseBackupLongTermRetentionPolicy `
                    -ServerName $srv.ServerName `
                    -DatabaseName $db.DatabaseName `
                    -ResourceGroupName $srv.ResourceGroupName -ErrorAction Stop

                $hasLtr = ($ltr.WeeklyRetention -and $ltr.WeeklyRetention -ine "PT0S") -or
                          ($ltr.MonthlyRetention -and $ltr.MonthlyRetention -ine "PT0S") -or
                          ($ltr.YearlyRetention -and $ltr.YearlyRetention -ine "PT0S")

                if ($hasLtr) {
                    $detail = "W=$($ltr.WeeklyRetention) M=$($ltr.MonthlyRetention) Y=$($ltr.YearlyRetention)"
                    Write-Log "LTR policy active on $($srv.ServerName)/$($db.DatabaseName): $detail — review for cost." -Level AUDIT
                }
            } catch {
                # Silently skip if LTR query fails (e.g. unsupported edition)
            }

            # Short-term retention — flag if > 14 days (default 7)
            try {
                $str = Get-AzSqlDatabaseBackupShortTermRetentionPolicy `
                    -ServerName $srv.ServerName `
                    -DatabaseName $db.DatabaseName `
                    -ResourceGroupName $srv.ResourceGroupName -ErrorAction Stop
                if ($str.RetentionDays -gt 14) {
                    Write-Log "Short-term retention for $($srv.ServerName)/$($db.DatabaseName) is $($str.RetentionDays) days (>14)." -Level AUDIT
                }
            } catch { }

            # Geo-redundant backup storage
            try {
                $redundancy = $db.CurrentBackupStorageRedundancy
                if ($redundancy -iin @("Geo", "GeoZone")) {
                    Write-Log "Geo-redundant backup storage on $($srv.ServerName)/$($db.DatabaseName) ($redundancy) — consider switching to Local or Zone." -Level AUDIT
                }
            } catch { }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 11. APPLICATION GATEWAYS — stop
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-StopApplicationGateways {
    Write-Log "── Checking Application Gateways ──"
    $appGws = Get-AzApplicationGateway -ErrorAction SilentlyContinue
    if (-not $appGws) { Write-Log "No Application Gateways found." ; return }

    foreach ($gw in $appGws) {
        if (Test-IsExcludedResourceGroup $gw.ResourceGroupName) {
            Write-Log "Skipping App GW $($gw.Name) — excluded RG." -Level SKIP ; continue
        }
        if (Test-ProductionIndicators -NamesToCheck @($gw.Name, $gw.ResourceGroupName) -Tags ($gw.Tag ?? @{})) {
            Write-Log "Skipping App GW $($gw.Name) — production indicator." -Level WARN
            $script:SkippedProd.Add("AppGW:$($gw.Name)") ; continue
        }

        if ($gw.OperationalState -ieq "Stopped") {
            Write-Log "App GW $($gw.Name) is already stopped." -Level SKIP ; continue
        }

        $sku = "$($gw.Sku.Name)/$($gw.Sku.Tier)"
        Invoke-ActionOrDryRun -Description "Stop Application Gateway $($gw.Name) ($sku)" -Action {
            Stop-AzApplicationGateway -ApplicationGateway $gw -ErrorAction Stop | Out-Null
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 12. DATA EXPLORER (KUSTO) CLUSTERS — stop
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-StopDataExplorerClusters {
    Write-Log "── Checking Azure Data Explorer (Kusto) clusters ──"
    try {
        $clusters = Get-AzKustoCluster -ErrorAction Stop
    } catch {
        Write-Log "Az.Kusto module may not be available: $_" -Level WARN ; return
    }
    if (-not $clusters) { Write-Log "No Data Explorer clusters found." ; return }

    foreach ($cluster in $clusters) {
        if (Test-IsExcludedResourceGroup $cluster.ResourceGroupName) {
            Write-Log "Skipping ADX $($cluster.Name) — excluded RG." -Level SKIP ; continue
        }
        if (Test-ProductionIndicators -NamesToCheck @($cluster.Name, $cluster.ResourceGroupName)) {
            Write-Log "Skipping ADX $($cluster.Name) — production indicator." -Level WARN
            $script:SkippedProd.Add("ADX:$($cluster.Name)") ; continue
        }

        if ($cluster.State -ieq "Running") {
            Invoke-ActionOrDryRun -Description "Stop Data Explorer cluster $($cluster.Name)" -Action {
                Stop-AzKustoCluster -Name $cluster.Name -ResourceGroupName $cluster.ResourceGroupName -ErrorAction Stop | Out-Null
            }
        } else {
            Write-Log "ADX cluster $($cluster.Name) state=$($cluster.State)." -Level SKIP
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 13. ANALYSIS SERVICES — pause
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-PauseAnalysisServices {
    Write-Log "── Checking Azure Analysis Services ──"
    try {
        $servers = Get-AzAnalysisServicesServer -ErrorAction Stop
    } catch {
        Write-Log "Az.AnalysisServices may not be available: $_" -Level WARN ; return
    }
    if (-not $servers) { Write-Log "No Analysis Services servers found." ; return }

    foreach ($as in $servers) {
        if (Test-IsExcludedResourceGroup $as.ResourceGroupName) {
            Write-Log "Skipping AAS $($as.Name) — excluded RG." -Level SKIP ; continue
        }
        if (Test-ProductionIndicators -NamesToCheck @($as.Name, $as.ResourceGroupName) -Tags ($as.Tag ?? @{})) {
            Write-Log "Skipping AAS $($as.Name) — production indicator." -Level WARN
            $script:SkippedProd.Add("AAS:$($as.Name)") ; continue
        }

        if ($as.State -ine "Paused") {
            Invoke-ActionOrDryRun -Description "Pause Analysis Services server $($as.Name) (SKU: $($as.Sku.Name))" -Action {
                Suspend-AzAnalysisServicesServer -Name $as.Name -ResourceGroupName $as.ResourceGroupName -ErrorAction Stop | Out-Null
            }
        } else {
            Write-Log "AAS $($as.Name) is already paused." -Level SKIP
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 14. VIRTUAL MACHINES — deallocate (opt-in)
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-DeallocateVirtualMachines {
    Write-Log "── Checking Virtual Machines ──"
    $vms = Get-AzVM -Status -ErrorAction SilentlyContinue
    if (-not $vms) { Write-Log "No VMs found." ; return }

    $runningVms = $vms | Where-Object { $_.PowerState -ieq "VM running" }
    if (-not $runningVms) { Write-Log "No running VMs." ; return }

    foreach ($vm in $runningVms) {
        if (Test-IsExcludedResourceGroup $vm.ResourceGroupName) {
            Write-Log "Skipping VM $($vm.Name) — excluded RG." -Level SKIP ; continue
        }
        if (Test-ProductionIndicators -NamesToCheck @($vm.Name, $vm.ResourceGroupName) -Tags ($vm.Tags ?? @{})) {
            Write-Log "Skipping VM $($vm.Name) — production indicator." -Level WARN
            $script:SkippedProd.Add("VM:$($vm.Name)") ; continue
        }

        if (-not $IncludeVmDeallocation) {
            Write-Log "Running VM found: $($vm.Name) (Size: $($vm.HardwareProfile.VmSize), RG: $($vm.ResourceGroupName)) — deallocate not enabled." -Level AUDIT
            continue
        }

        Invoke-ActionOrDryRun -Description "Deallocate VM $($vm.Name) ($($vm.HardwareProfile.VmSize))" -Action {
            Stop-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name -Force -ErrorAction Stop | Out-Null
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# 15. REPORT OTHER EXPENSIVE RESOURCES
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-AuditExpensiveResources {
    Write-Log "── Auditing other expensive resource types ──"

    # --- VPN / ExpressRoute Gateways (requires -ResourceGroupName, so discover via Get-AzResource) ---
    $vnetGwResources = Get-AzResource -ResourceType "Microsoft.Network/virtualNetworkGateways" -ErrorAction SilentlyContinue
    foreach ($gwRes in $vnetGwResources) {
        try {
            $gw = Get-AzVirtualNetworkGateway -Name $gwRes.Name -ResourceGroupName $gwRes.ResourceGroupName -ErrorAction Stop
            if ($gw.GatewayType -ieq "Vpn") {
                Write-Log "VPN Gateway: $($gw.Name) (SKU: $($gw.Sku.Name), RG: $($gw.ResourceGroupName)) — ~`$0.04–`$1.25/hr depending on SKU." -Level AUDIT
            } elseif ($gw.GatewayType -ieq "ExpressRoute") {
                Write-Log "ExpressRoute Gateway: $($gw.Name) (SKU: $($gw.Sku.Name), RG: $($gw.ResourceGroupName)) — expensive, review needed." -Level AUDIT
            }
        } catch {
            Write-Log "Could not query VNet gateway $($gwRes.Name): $_" -Level WARN
        }
    }

    # --- ExpressRoute Circuits ---
    $circuits = Get-AzExpressRouteCircuit -ErrorAction SilentlyContinue
    foreach ($c in $circuits) {
        Write-Log "ExpressRoute Circuit: $($c.Name) (Tier: $($c.Sku.Tier), Bandwidth: $($c.ServiceProviderProperties.BandwidthInMbps) Mbps)." -Level AUDIT
    }

    # --- Bastion Hosts ---
    $bastions = Get-AzResource -ResourceType "Microsoft.Network/bastionHosts" -ErrorAction SilentlyContinue
    foreach ($b in $bastions) {
        Write-Log "Bastion Host: $($b.Name) (RG: $($b.ResourceGroupName)) — ~`$0.19/hr. Cannot be paused; consider deleting if not in use." -Level AUDIT
    }

    # --- NAT Gateways ---
    $natGws = Get-AzNatGateway -ErrorAction SilentlyContinue
    foreach ($nat in $natGws) {
        Write-Log "NAT Gateway: $($nat.Name) (RG: $($nat.ResourceGroupName)) — ~`$0.045/hr + data charges." -Level AUDIT
    }

    # --- Standard Load Balancers ---
    $lbs = Get-AzLoadBalancer -ErrorAction SilentlyContinue | Where-Object { $_.Sku.Name -ieq "Standard" }
    foreach ($lb in $lbs) {
        $ruleCount = ($lb.LoadBalancingRules.Count + $lb.OutboundRules.Count + $lb.InboundNatRules.Count)
        if ($ruleCount -eq 0) {
            Write-Log "Empty Standard LB: $($lb.Name) (RG: $($lb.ResourceGroupName)) — has no rules, consider deleting." -Level AUDIT
        }
    }

    # --- Cosmos DB — high provisioned RU/s ---
    $cosmosResources = Get-AzResource -ResourceType "Microsoft.DocumentDb/databaseAccounts" -ErrorAction SilentlyContinue
    foreach ($cosmosRes in $cosmosResources) {
        try {
            $acct = Get-AzCosmosDBAccount -Name $cosmosRes.Name -ResourceGroupName $cosmosRes.ResourceGroupName -ErrorAction Stop
            $sqlDbs = Get-AzCosmosDBSqlDatabase -AccountName $acct.Name -ResourceGroupName $acct.ResourceGroupName -ErrorAction SilentlyContinue
            foreach ($cdb in $sqlDbs) {
                $containers = Get-AzCosmosDBSqlContainer -AccountName $acct.Name `
                    -ResourceGroupName $acct.ResourceGroupName `
                    -DatabaseName $cdb.Name -ErrorAction SilentlyContinue
                foreach ($cont in $containers) {
                    try {
                        $throughput = Get-AzCosmosDBSqlContainerThroughput -AccountName $acct.Name `
                            -ResourceGroupName $acct.ResourceGroupName `
                            -DatabaseName $cdb.Name `
                            -Name $cont.Name -ErrorAction Stop
                        $ru = $throughput.Resource.Throughput
                        $maxRu = $throughput.Resource.AutoscaleSettings.MaxThroughput
                        if ($ru -and $ru -gt 1000) {
                            Write-Log "Cosmos DB $($acct.Name)/$($cdb.Name)/$($cont.Name): provisioned $ru RU/s — consider serverless or lowering." -Level AUDIT
                        }
                        if ($maxRu -and $maxRu -gt 4000) {
                            Write-Log "Cosmos DB $($acct.Name)/$($cdb.Name)/$($cont.Name): autoscale max $maxRu RU/s — review." -Level AUDIT
                        }
                    } catch { }
                }
            }
        } catch {
            Write-Log "Could not query Cosmos DB account $($cosmosRes.Name): $_" -Level WARN
        }
    }

    # --- Redis Cache — Premium/Enterprise tiers ---
    $redisInstances = Get-AzResource -ResourceType "Microsoft.Cache/redis" -ErrorAction SilentlyContinue
    foreach ($r in $redisInstances) {
        try {
            $detail = Get-AzRedisCache -ResourceGroupName $r.ResourceGroupName -Name $r.Name -ErrorAction Stop
            if ($detail.Sku -iin @("Premium", "Enterprise", "EnterpriseFlash")) {
                Write-Log "Redis Cache: $($r.Name) (SKU: $($detail.Sku), Size: $($detail.Size)) — expensive tier, review needed." -Level AUDIT
            }
        } catch { }
    }

    # --- AKS Clusters ---
    try {
        $aksClusters = Get-AzAksCluster -ErrorAction Stop
        foreach ($aks in $aksClusters) {
            $totalNodes = ($aks.AgentPoolProfiles | Measure-Object -Property Count -Sum).Sum
            Write-Log "AKS Cluster: $($aks.Name) (RG: $($aks.ResourceGroupName), Node Pools: $($aks.AgentPoolProfiles.Count), Total Nodes: $totalNodes) — review node sizes and counts." -Level AUDIT
        }
    } catch { }

    # --- HDInsight Clusters ---
    $hdiClusters = Get-AzResource -ResourceType "Microsoft.HDInsight/clusters" -ErrorAction SilentlyContinue
    foreach ($hdi in $hdiClusters) {
        Write-Log "HDInsight Cluster: $($hdi.Name) (RG: $($hdi.ResourceGroupName)) — these are expensive; delete if not needed." -Level AUDIT
    }

    # --- Databricks Workspaces ---
    $dbwSpaces = Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ErrorAction SilentlyContinue
    foreach ($dbw in $dbwSpaces) {
        Write-Log "Databricks Workspace: $($dbw.Name) (RG: $($dbw.ResourceGroupName)) — check for running clusters inside." -Level AUDIT
    }

    # --- Log Analytics — high retention ---
    try {
        $laWorkspaces = Get-AzResource -ResourceType "Microsoft.OperationalInsights/workspaces" -ErrorAction SilentlyContinue
        foreach ($la in $laWorkspaces) {
            try {
                $detail = Get-AzOperationalInsightsWorkspace -ResourceGroupName $la.ResourceGroupName -Name $la.Name -ErrorAction Stop
                $retention = $detail.RetentionInDays
                if ($retention -gt 90) {
                    Write-Log "Log Analytics $($la.Name): retention = $retention days (>90). Additional storage costs apply." -Level AUDIT
                }
            } catch { }
        }
    } catch { }

    # --- Running Container Instances ---
    $acis = Get-AzResource -ResourceType "Microsoft.ContainerInstance/containerGroups" -ErrorAction SilentlyContinue
    foreach ($aci in $acis) {
        Write-Log "Container Instance: $($aci.Name) (RG: $($aci.ResourceGroupName)) — billed while running." -Level AUDIT
    }

    # --- Azure API Management (Premium is very expensive) ---
    $apims = Get-AzResource -ResourceType "Microsoft.ApiManagement/service" -ErrorAction SilentlyContinue
    foreach ($apim in $apims) {
        try {
            $getUri = "$($apim.ResourceId)?api-version=2022-08-01"
            $detail = Invoke-AzRestMethod -Path $getUri -Method GET -ErrorAction Stop
            $body = $detail.Content | ConvertFrom-Json
            $sku  = $body.sku.name
            $cap  = $body.sku.capacity
            if ($sku -iin @("Premium", "Developer", "Standard")) {
                Write-Log "API Management: $($apim.Name) (SKU: $sku, Units: $cap) — Premium is ~`$2,800/unit/month." -Level AUDIT
            }
        } catch { }
    }

    # --- Azure Machine Learning Compute Instances ---
    $amlWorkspaces = Get-AzResource -ResourceType "Microsoft.MachineLearningServices/workspaces" -ErrorAction SilentlyContinue
    foreach ($aml in $amlWorkspaces) {
        Write-Log "ML Workspace: $($aml.Name) (RG: $($aml.ResourceGroupName)) — check for running compute instances and clusters." -Level AUDIT
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

Write-Output ""
Write-Output "╔══════════════════════════════════════════════════════════════════════════╗"
Write-Output "║          AZURE COST OPTIMIZATION RUNBOOK                                ║"
Write-Output "║                                                                         ║"
Write-Output "║  ⚠️  WARNING: This runbook performs DESTRUCTIVE operations.              ║"
Write-Output "║  DO NOT RUN AGAINST PRODUCTION ENVIRONMENTS.                            ║"
Write-Output "║                                                                         ║"
if ($DryRun) {
Write-Output "║  Mode: 🔍 DRY RUN — no changes will be made.                           ║"
} else {
Write-Output "║  Mode: 🔴 LIVE EXECUTION — resources WILL be modified and deleted!      ║"
}
Write-Output "║                                                                         ║"
Write-Output "║  VM Deallocation:   $(if ($IncludeVmDeallocation) { 'ENABLED ' } else { 'DISABLED' })                                        ║"
Write-Output "║  vWAN Deletion:     $(if ($IncludeVirtualWanDeletion) { 'ENABLED ' } else { 'DISABLED' })                                        ║"
Write-Output "╚══════════════════════════════════════════════════════════════════════════╝"
Write-Output ""

# ── Authenticate with Managed Identity ──────────────────────────────────────
Write-Log "Connecting to Azure via system-assigned managed identity..."
try {
    Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    Write-Log "Successfully authenticated."
} catch {
    Write-Log "Failed to authenticate with managed identity: $_" -Level ERROR
    throw "Cannot continue without authentication."
}

# ── Enumerate subscriptions ─────────────────────────────────────────────────
$allSubs = Get-AzSubscription -ErrorAction Stop |
           Where-Object { $_.State -eq "Enabled" } |
           Where-Object { $_.Id -notin $ExcludeSubscriptionIds }

Write-Log "Found $($allSubs.Count) accessible subscription(s) (after exclusions)."

if ($allSubs.Count -eq 0) {
    Write-Log "No subscriptions to process. Exiting." -Level WARN
    return
}

# ── Process each subscription ───────────────────────────────────────────────
foreach ($sub in $allSubs) {
    Write-Output ""
    Write-Output "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    Write-Log "Processing subscription: $($sub.Name) ($($sub.Id))"
    Write-Output "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Check subscription name for production indicators
    if (Test-ProductionIndicators -NamesToCheck @($sub.Name)) {
        Write-Log "⛔ SKIPPING entire subscription '$($sub.Name)' — matches production keyword." -Level WARN
        $script:SkippedProd.Add("Subscription:$($sub.Name)")
        continue
    }

    # Set context
    try {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
    } catch {
        Write-Log "Failed to set context for subscription $($sub.Name): $_" -Level ERROR
        continue
    }

    # Execute all cost-optimization functions
    Invoke-PauseFabricCapacities
    Invoke-ScaleDownSqlDatabases
    Invoke-PauseSynapsePools
    Invoke-DeallocateFirewalls
    Invoke-StopSqlManagedInstances
    Invoke-RemoveVirtualWans
    Invoke-RemoveDetachedDisks
    Invoke-RemoveOrphanedSnapshots
    Invoke-RemoveUnattachedPublicIPs
    Invoke-AuditBackupPolicies
    Invoke-StopApplicationGateways
    Invoke-StopDataExplorerClusters
    Invoke-PauseAnalysisServices
    Invoke-DeallocateVirtualMachines
    Invoke-AuditExpensiveResources
}

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY REPORT
# ─────────────────────────────────────────────────────────────────────────────
Write-Output ""
Write-Output "╔══════════════════════════════════════════════════════════════════════════╗"
Write-Output "║                         EXECUTION SUMMARY                               ║"
Write-Output "╚══════════════════════════════════════════════════════════════════════════╝"
Write-Output ""
Write-Output "Mode:                $(if ($DryRun) { 'DRY RUN (no changes made)' } else { 'LIVE EXECUTION' })"
Write-Output "Subscriptions:       $($allSubs.Count) processed"
Write-Output "Actions taken:       $($script:ActionsTaken.Count)"
Write-Output "Warnings:            $($script:Warnings.Count)"
Write-Output "Errors:              $($script:Errors.Count)"
Write-Output "Skipped (prod):      $($script:SkippedProd.Count)"
Write-Output ""

if ($script:ActionsTaken.Count -gt 0) {
    Write-Output "── ACTIONS ────────────────────────────────────────────────────────────────"
    foreach ($a in $script:ActionsTaken) { Write-Output "  ✅ $a" }
    Write-Output ""
}

if ($script:Warnings.Count -gt 0) {
    Write-Output "── WARNINGS ───────────────────────────────────────────────────────────────"
    foreach ($w in $script:Warnings) { Write-Output "  ⚠️  $w" }
    Write-Output ""
}

if ($script:Errors.Count -gt 0) {
    Write-Output "── ERRORS ─────────────────────────────────────────────────────────────────"
    foreach ($e in $script:Errors) { Write-Output "  ❌ $e" }
    Write-Output ""
}

if ($script:SkippedProd.Count -gt 0) {
    Write-Output "── SKIPPED (PRODUCTION) ───────────────────────────────────────────────────"
    foreach ($s in $script:SkippedProd) { Write-Output "  ⛔ $s" }
    Write-Output ""
}

if ($DryRun) {
    Write-Output "╔══════════════════════════════════════════════════════════════════════════╗"
    Write-Output "║  This was a DRY RUN. To execute changes, re-run with -DryRun `$false.   ║"
    Write-Output "║  ⚠️  REVIEW ALL ACTIONS ABOVE CAREFULLY BEFORE LIVE EXECUTION.          ║"
    Write-Output "╚══════════════════════════════════════════════════════════════════════════╝"
}

Write-Output ""
Write-Log "Runbook execution complete."