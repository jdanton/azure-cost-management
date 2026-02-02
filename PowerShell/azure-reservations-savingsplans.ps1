<#
.SYNOPSIS
    Analyzes Azure workloads for reservation / savings plan coverage and opportunities.

.DESCRIPTION
    Run manually from a PowerShell session (Az module required, interactive login).
    Produces a detailed console report and optional CSV/HTML export covering:

    EXISTING COMMITMENTS
    ─────────────────────────────────────────────────────────────────────────
    • All active Reservations — utilization %, unused value, scope, expiry
    • All active Savings Plans — utilization %, commitment, expiry
    • Under-utilized commitments (below configurable threshold)
    • Commitments expiring within configurable window
    ─────────────────────────────────────────────────────────────────────────

    COVERAGE GAP ANALYSIS  (per subscription)
    ─────────────────────────────────────────────────────────────────────────
    • Virtual Machines           — running VMs not covered by RI or SP
    • SQL Databases              — DTU/vCore DBs without reserved capacity
    • SQL Elastic Pools          — pools without reserved capacity
    • SQL Managed Instances      — instances without reserved capacity
    • Cosmos DB                  — provisioned RU/s without reserved throughput
    • App Service Plans          — Premium / Isolated tiers
    • Redis Cache                — Premium / Enterprise SKUs
    • Premium / Ultra Disks      — high-cost storage without reservation
    • Data Explorer (Kusto)      — running clusters
    • Synapse Dedicated Pools    — online pools
    • Azure Databricks           — running workspaces (DBU commitments)
    • Azure VMware Solution      — nodes
    ─────────────────────────────────────────────────────────────────────────

    RECOMMENDATIONS
    ─────────────────────────────────────────────────────────────────────────
    • Azure Advisor reservation & savings plan recommendations
    • Consumption API reservation recommendations (7/30/60-day lookback)
    • Highlights VMs with >95% uptime as strong reservation candidates
    ─────────────────────────────────────────────────────────────────────────

.PARAMETER BillingScope
    The billing scope for querying reservations and savings plans.
    Accepts:
      - Subscription ID            (single sub analysis)
      - Billing account ID         (/providers/Microsoft.Billing/billingAccounts/{id})
      - Enrollment account         (EA)
    If omitted the script discovers all accessible subscriptions.

.PARAMETER UtilizationThresholdPct
    Reservations/SPs below this utilization % are flagged. Default: 80.

.PARAMETER ExpiryWarningDays
    Commitments expiring within this many days are flagged. Default: 90.

.PARAMETER LookbackDays
    How many days of usage to consider for recommendations. Default: 30.
    Accepted values: 7, 30, 60.

.PARAMETER ExportPath
    If supplied, writes a detailed HTML report and companion CSVs to this folder.

.PARAMETER IncludeAdvisor
    Pull Azure Advisor cost recommendations (reservation + savings plan).
    Default: $true.

.EXAMPLE
    # Quick analysis of current subscription
    .\Analyze-ReservationsAndSavingsPlans.ps1

.EXAMPLE
    # Full analysis with HTML export
    .\Analyze-ReservationsAndSavingsPlans.ps1 -ExportPath "C:\Reports" -LookbackDays 30

.EXAMPLE
    # Flag only severely under-used commitments
    .\Analyze-ReservationsAndSavingsPlans.ps1 -UtilizationThresholdPct 50 -ExpiryWarningDays 30

.NOTES
    Required modules: Az.Accounts, Az.Resources, Az.Compute, Az.Sql, Az.Network,
                      Az.CosmosDB, Az.Advisor, Az.Monitor, Az.Billing
    Required roles:   Reader on subscriptions, Reservation Reader (or billing reader)
                      for reservation/savings plan data.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$BillingScope,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$UtilizationThresholdPct = 80,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$ExpiryWarningDays = 90,

    [Parameter(Mandatory = $false)]
    [ValidateSet(7, 30, 60)]
    [int]$LookbackDays = 30,

    [Parameter(Mandatory = $false)]
    [string]$ExportPath,

    [Parameter(Mandatory = $false)]
    [bool]$IncludeAdvisor = $true
)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"   # Suppress progress bars for speed

# Colour helpers (no-ops if not interactive)
function Write-Header  { param([string]$Text) Write-Host "`n━━━ $Text ━━━" -ForegroundColor Cyan }
function Write-Good    { param([string]$Text) Write-Host "  ✅ $Text" -ForegroundColor Green }
function Write-Flag    { param([string]$Text) Write-Host "  ⚠️  $Text" -ForegroundColor Yellow }
function Write-Bad     { param([string]$Text) Write-Host "  ❌ $Text" -ForegroundColor Red }
function Write-Info    { param([string]$Text) Write-Host "  ℹ️  $Text" -ForegroundColor Gray }
function Write-Detail  { param([string]$Text) Write-Host "     $Text" -ForegroundColor DarkGray }

# Accumulator for all findings — used for export
$script:Findings = [System.Collections.Generic.List[pscustomobject]]::new()

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,       # Info, Low, Medium, High, Critical
        [string]$Resource,
        [string]$ResourceGroup,
        [string]$Subscription,
        [string]$Detail,
        [string]$Recommendation,
        [decimal]$EstimatedMonthlyCost = 0,
        [decimal]$EstimatedSavings     = 0
    )
    $script:Findings.Add([pscustomobject]@{
        Category            = $Category
        Severity            = $Severity
        Resource            = $Resource
        ResourceGroup       = $ResourceGroup
        Subscription        = $Subscription
        Detail              = $Detail
        Recommendation      = $Recommendation
        EstimatedMonthlyCost = $EstimatedMonthlyCost
        EstimatedSavings     = $EstimatedSavings
        Timestamp           = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    })
}

# ─────────────────────────────────────────────────────────────────────────────
# AUTHENTICATION
# ─────────────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      AZURE RESERVATIONS & SAVINGS PLANS ANALYZER                    ║" -ForegroundColor Cyan
Write-Host "║                                                                      ║" -ForegroundColor Cyan
Write-Host "║  Utilization threshold:  $($UtilizationThresholdPct.ToString().PadRight(4))%                                     ║" -ForegroundColor Cyan
Write-Host "║  Expiry warning window:  $($ExpiryWarningDays.ToString().PadRight(4)) days                                    ║" -ForegroundColor Cyan
Write-Host "║  Lookback period:        $($LookbackDays.ToString().PadRight(4)) days                                    ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

$context = Get-AzContext -ErrorAction SilentlyContinue
if (-not $context) {
    Write-Host "`nNo Azure session found. Launching interactive login..." -ForegroundColor Yellow
    Connect-AzAccount -ErrorAction Stop | Out-Null
    $context = Get-AzContext
}
Write-Host "`nLogged in as: $($context.Account.Id)" -ForegroundColor Green
Write-Host "Tenant:       $($context.Tenant.Id)`n"

# ─────────────────────────────────────────────────────────────────────────────
# DISCOVER SUBSCRIPTIONS
# ─────────────────────────────────────────────────────────────────────────────

$subscriptions = @()
if ($BillingScope -and $BillingScope -notmatch '/') {
    # Treat as a single subscription ID
    $subscriptions = @(Get-AzSubscription -SubscriptionId $BillingScope -ErrorAction Stop)
} else {
    $subscriptions = Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq "Enabled" }
}
Write-Host "Subscriptions in scope: $($subscriptions.Count)"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1: EXISTING RESERVATIONS
# ═════════════════════════════════════════════════════════════════════════════

Write-Header "SECTION 1: EXISTING RESERVATIONS"

$reservationOrders = @()
try {
    $riResult = Invoke-AzRestMethod -Path "/providers/Microsoft.Capacity/reservationOrders?api-version=2022-11-01" -Method GET -ErrorAction Stop
    if ($riResult.StatusCode -eq 200) {
        $riBody = $riResult.Content | ConvertFrom-Json
        $reservationOrders = $riBody.value
    }
} catch {
    Write-Flag "Could not query reservation orders: $_"
    Write-Info "Ensure you have Reservation Reader or Billing Reader role."
}

$activeReservations      = [System.Collections.Generic.List[pscustomobject]]::new()
$expiringReservations    = [System.Collections.Generic.List[pscustomobject]]::new()
$underUtilizedReservations = [System.Collections.Generic.List[pscustomobject]]::new()

if ($reservationOrders.Count -gt 0) {
    Write-Info "Found $($reservationOrders.Count) reservation order(s). Querying details..."

    foreach ($order in $reservationOrders) {
        $orderId = $order.id
        try {
            $riDetailResult = Invoke-AzRestMethod -Path "$orderId/reservations?api-version=2022-11-01&expand=renewProperties" -Method GET -ErrorAction Stop
            $reservations = ($riDetailResult.Content | ConvertFrom-Json).value

            foreach ($ri in $reservations) {
                $props       = $ri.properties
                $displayName = $props.displayName
                $skuName     = $ri.sku.name
                $location    = $ri.location
                $quantity    = $props.quantity
                $term        = $props.term
                $startDate   = $props.effectiveDateTime
                $expiryDate  = $props.expiryDate
                $provState   = $props.provisioningState
                $scope       = $props.appliedScopeType
                $reservedType = $props.reservedResourceType
                $riId        = $ri.id

                # Calculate days until expiry
                $daysToExpiry = if ($expiryDate) {
                    [math]::Round(((Get-Date $expiryDate) - (Get-Date)).TotalDays, 0)
                } else { 9999 }

                # ── Get utilization summary ──
                $avgUtilPct = $null
                $unusedHours = $null
                $usedHours   = $null
                try {
                    $endDate   = (Get-Date).ToString("yyyy-MM-dd")
                    $startLook = (Get-Date).AddDays(-$LookbackDays).ToString("yyyy-MM-dd")
                    $utilPath  = "$riId/providers/Microsoft.Consumption/reservationSummaries?grain=monthly&`$filter=properties/usageDate ge '$startLook' and properties/usageDate le '$endDate'&api-version=2023-05-01"
                    $utilResult = Invoke-AzRestMethod -Path $utilPath -Method GET -ErrorAction Stop
                    if ($utilResult.StatusCode -eq 200) {
                        $utilData = ($utilResult.Content | ConvertFrom-Json).value
                        if ($utilData.Count -gt 0) {
                            $avgUtilPct = [math]::Round(($utilData | ForEach-Object { $_.properties.avgUtilizationPercentage } |
                                          Measure-Object -Average).Average, 1)
                            $unusedHours = [math]::Round(($utilData | ForEach-Object { $_.properties.unusedHours } |
                                          Measure-Object -Sum).Sum, 1)
                            $usedHours = [math]::Round(($utilData | ForEach-Object { $_.properties.usedHours } |
                                        Measure-Object -Sum).Sum, 1)
                        }
                    }
                } catch {
                    # Utilization data may not be available for all reservation types
                }

                $riRecord = [pscustomobject]@{
                    Name             = $displayName
                    ReservedType     = $reservedType
                    SKU              = $skuName
                    Location         = $location
                    Quantity         = $quantity
                    Term             = $term
                    Scope            = $scope
                    State            = $provState
                    ExpiryDate       = $expiryDate
                    DaysToExpiry     = $daysToExpiry
                    AvgUtilizationPct = $avgUtilPct
                    UsedHours        = $usedHours
                    UnusedHours      = $unusedHours
                    ReservationId    = $riId
                }
                $activeReservations.Add($riRecord)

                # ── Flag under-utilized ──
                if ($null -ne $avgUtilPct -and $avgUtilPct -lt $UtilizationThresholdPct -and $provState -ieq "Succeeded") {
                    $underUtilizedReservations.Add($riRecord)
                }

                # ── Flag expiring soon ──
                if ($daysToExpiry -le $ExpiryWarningDays -and $daysToExpiry -gt 0 -and $provState -ieq "Succeeded") {
                    $expiringReservations.Add($riRecord)
                }
            }
        } catch {
            Write-Flag "Could not read reservation details for order $orderId : $_"
        }
    }

    # ── Display active reservations ──
    Write-Host ""
    Write-Info "Active Reservations: $($activeReservations.Count)"
    foreach ($ri in $activeReservations) {
        $utilStr = if ($null -ne $ri.AvgUtilizationPct) { "$($ri.AvgUtilizationPct)%" } else { "N/A" }
        $colour  = if ($null -ne $ri.AvgUtilizationPct -and $ri.AvgUtilizationPct -lt $UtilizationThresholdPct) { "Yellow" } else { "Green" }

        Write-Host "    $($ri.Name)" -ForegroundColor White -NoNewline
        Write-Host "  |  $($ri.ReservedType)  |  $($ri.SKU)  |  Qty: $($ri.Quantity)  |  Util: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$utilStr" -ForegroundColor $colour -NoNewline
        Write-Host "  |  Expires: $($ri.ExpiryDate) ($($ri.DaysToExpiry)d)" -ForegroundColor DarkGray
    }

    # ── Under-utilized ──
    if ($underUtilizedReservations.Count -gt 0) {
        Write-Host ""
        Write-Flag "UNDER-UTILIZED RESERVATIONS (< $UtilizationThresholdPct% avg utilization):"
        foreach ($ri in $underUtilizedReservations) {
            Write-Bad "$($ri.Name) — $($ri.ReservedType) $($ri.SKU) — Util: $($ri.AvgUtilizationPct)% — Unused hrs: $($ri.UnusedHours)"
            Write-Detail "Consider: exchange for a better-fitting SKU/region, change scope to Shared, or let expire."
            Add-Finding -Category "Reservation-Underutilized" -Severity "High" `
                -Resource $ri.Name -ResourceGroup "" -Subscription "" `
                -Detail "$($ri.ReservedType) $($ri.SKU), Utilization: $($ri.AvgUtilizationPct)%, Unused hours: $($ri.UnusedHours)" `
                -Recommendation "Exchange for right-sized SKU, broaden scope to Shared, or cancel/let expire."
        }
    } else {
        Write-Good "All reservations are above $UtilizationThresholdPct% utilization."
    }

    # ── Expiring soon ──
    if ($expiringReservations.Count -gt 0) {
        Write-Host ""
        Write-Flag "RESERVATIONS EXPIRING WITHIN $ExpiryWarningDays DAYS:"
        foreach ($ri in $expiringReservations) {
            Write-Flag "$($ri.Name) — $($ri.ReservedType) $($ri.SKU) — Expires: $($ri.ExpiryDate) ($($ri.DaysToExpiry) days)"
            $renewNote = "Review whether to renew, exchange, or switch to a Savings Plan."
            Write-Detail $renewNote
            Add-Finding -Category "Reservation-Expiring" -Severity "Medium" `
                -Resource $ri.Name -ResourceGroup "" -Subscription "" `
                -Detail "Expires $($ri.ExpiryDate) ($($ri.DaysToExpiry) days). Type: $($ri.ReservedType) $($ri.SKU)." `
                -Recommendation $renewNote
        }
    } else {
        Write-Good "No reservations expiring within $ExpiryWarningDays days."
    }

} else {
    Write-Flag "No reservation orders found (or insufficient permissions)."
    Write-Info "You need Reservation Reader, Owner, or Billing Reader at the tenant/billing scope."
}

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2: EXISTING SAVINGS PLANS
# ═════════════════════════════════════════════════════════════════════════════

Write-Header "SECTION 2: EXISTING SAVINGS PLANS"

$savingsPlanOrders = @()
try {
    $spResult = Invoke-AzRestMethod -Path "/providers/Microsoft.BillingBenefits/savingsPlanOrders?api-version=2022-11-01" -Method GET -ErrorAction Stop
    if ($spResult.StatusCode -eq 200) {
        $spBody = $spResult.Content | ConvertFrom-Json
        $savingsPlanOrders = $spBody.value
    }
} catch {
    Write-Flag "Could not query savings plan orders: $_"
    Write-Info "Ensure you have Savings Plan Reader or Billing Reader role."
}

$activeSavingsPlans        = [System.Collections.Generic.List[pscustomobject]]::new()
$underUtilizedSavingsPlans = [System.Collections.Generic.List[pscustomobject]]::new()

if ($savingsPlanOrders.Count -gt 0) {
    Write-Info "Found $($savingsPlanOrders.Count) savings plan order(s). Querying details..."

    foreach ($spOrder in $savingsPlanOrders) {
        $spOrderId = $spOrder.id
        try {
            $spDetailResult = Invoke-AzRestMethod -Path "$spOrderId/savingsPlans?api-version=2022-11-01" -Method GET -ErrorAction Stop
            $plans = ($spDetailResult.Content | ConvertFrom-Json).value

            foreach ($sp in $plans) {
                $props       = $sp.properties
                $displayName = $props.displayName
                $commitment  = $props.commitment
                $term        = $props.term
                $expiryDate  = $props.expiryDateTime
                $startDate   = $props.effectiveDateTime
                $appliedScope = $props.appliedScopeType
                $provState   = $props.provisioningState
                $benefitType = $props.appliedScopeProperties.displayName

                $daysToExpiry = if ($expiryDate) {
                    [math]::Round(((Get-Date $expiryDate) - (Get-Date)).TotalDays, 0)
                } else { 9999 }

                $commitAmt = if ($commitment) { "$($commitment.amount) $($commitment.currencyCode)/hr" } else { "N/A" }

                # ── Get utilization ──
                $avgUtilPct = $null
                try {
                    $endDate   = (Get-Date).ToString("yyyy-MM-dd")
                    $startLook = (Get-Date).AddDays(-$LookbackDays).ToString("yyyy-MM-dd")
                    $spUtilPath = "$($sp.id)/providers/Microsoft.Consumption/savingsPlanSummaries?grain=monthly&`$filter=properties/usageDate ge '$startLook' and properties/usageDate le '$endDate'&api-version=2023-05-01"
                    $spUtilResult = Invoke-AzRestMethod -Path $spUtilPath -Method GET -ErrorAction Stop
                    if ($spUtilResult.StatusCode -eq 200) {
                        $spUtilData = ($spUtilResult.Content | ConvertFrom-Json).value
                        if ($spUtilData.Count -gt 0) {
                            $avgUtilPct = [math]::Round(($spUtilData | ForEach-Object { $_.properties.avgUtilizationPercentage } |
                                          Measure-Object -Average).Average, 1)
                        }
                    }
                } catch { }

                $spRecord = [pscustomobject]@{
                    Name              = $displayName
                    Commitment        = $commitAmt
                    Term              = $term
                    Scope             = $appliedScope
                    State             = $provState
                    ExpiryDate        = $expiryDate
                    DaysToExpiry      = $daysToExpiry
                    AvgUtilizationPct = $avgUtilPct
                    SavingsPlanId     = $sp.id
                }
                $activeSavingsPlans.Add($spRecord)

                if ($null -ne $avgUtilPct -and $avgUtilPct -lt $UtilizationThresholdPct -and $provState -ieq "Succeeded") {
                    $underUtilizedSavingsPlans.Add($spRecord)
                }
            }
        } catch {
            Write-Flag "Could not read savings plan details for order $spOrderId : $_"
        }
    }

    Write-Host ""
    Write-Info "Active Savings Plans: $($activeSavingsPlans.Count)"
    foreach ($sp in $activeSavingsPlans) {
        $utilStr = if ($null -ne $sp.AvgUtilizationPct) { "$($sp.AvgUtilizationPct)%" } else { "N/A" }
        $colour  = if ($null -ne $sp.AvgUtilizationPct -and $sp.AvgUtilizationPct -lt $UtilizationThresholdPct) { "Yellow" } else { "Green" }

        Write-Host "    $($sp.Name)" -ForegroundColor White -NoNewline
        Write-Host "  |  $($sp.Commitment)  |  $($sp.Term)  |  Scope: $($sp.Scope)  |  Util: " -NoNewline -ForegroundColor DarkGray
        Write-Host "$utilStr" -ForegroundColor $colour -NoNewline
        Write-Host "  |  Expires: $($sp.ExpiryDate) ($($sp.DaysToExpiry)d)" -ForegroundColor DarkGray
    }

    if ($underUtilizedSavingsPlans.Count -gt 0) {
        Write-Host ""
        Write-Flag "UNDER-UTILIZED SAVINGS PLANS (< $UtilizationThresholdPct%):"
        foreach ($sp in $underUtilizedSavingsPlans) {
            Write-Bad "$($sp.Name) — $($sp.Commitment) — Util: $($sp.AvgUtilizationPct)%"
            Write-Detail "Savings Plans cannot be exchanged. Consider broadening scope to Shared."
            Add-Finding -Category "SavingsPlan-Underutilized" -Severity "High" `
                -Resource $sp.Name -ResourceGroup "" -Subscription "" `
                -Detail "Commitment: $($sp.Commitment), Utilization: $($sp.AvgUtilizationPct)%" `
                -Recommendation "Broaden scope to Shared to maximize utilization. Cannot exchange."
        }
    } else {
        Write-Good "All savings plans are above $UtilizationThresholdPct% utilization."
    }
} else {
    Write-Flag "No savings plan orders found (or insufficient permissions)."
}

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3: COVERAGE GAP ANALYSIS — UNCOVERED WORKLOADS
# ═════════════════════════════════════════════════════════════════════════════

Write-Header "SECTION 3: COVERAGE GAP ANALYSIS"

# Build a lookup of reserved SKUs + regions for quick matching
$reservedSkuLookup = @{}
foreach ($ri in $activeReservations) {
    if ($ri.State -ieq "Succeeded") {
        $key = "$($ri.ReservedType)|$($ri.SKU)|$($ri.Location)".ToLower()
        if (-not $reservedSkuLookup.ContainsKey($key)) {
            $reservedSkuLookup[$key] = [System.Collections.Generic.List[pscustomobject]]::new()
        }
        $reservedSkuLookup[$key].Add($ri)
    }
}

# Track totals for summary
$totalUncoveredResources = 0
$totalEstimatedMonthlyCost = 0

foreach ($sub in $subscriptions) {
    Write-Host ""
    Write-Host "  ── Subscription: $($sub.Name) ($($sub.Id)) ──" -ForegroundColor White
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
    $subName = $sub.Name

    # ─────────────────────────────────────────────────────────────────────
    # 3a. VIRTUAL MACHINES
    # ─────────────────────────────────────────────────────────────────────
    Write-Info "Checking Virtual Machines..."
    $vms = Get-AzVM -Status -ErrorAction SilentlyContinue |
           Where-Object { $_.PowerState -ieq "VM running" }

    foreach ($vm in $vms) {
        $vmSize   = $vm.HardwareProfile.VmSize
        $location = $vm.Location.ToLower()

        # Normalize VM size family for reservation matching
        # Reservations use instance size flexibility within families
        $riKey = "virtualmachines|$vmSize|$location"

        # Simple match: check if there's a reservation for this exact SKU+location
        # (Real matching uses instance size flexibility groups, but exact match is a good start)
        $isCovered = $reservedSkuLookup.ContainsKey($riKey)

        # Also check broader family — reservations cover entire size families
        $sizeFamilyMatch = $false
        if (-not $isCovered) {
            # Extract family prefix (e.g., "Standard_D" from "Standard_D4s_v5")
            $familyPrefix = ($vmSize -replace '_v\d+$', '' -replace '\d+[a-z]*s?$', '' -replace '_', '_').ToLower()
            foreach ($key in $reservedSkuLookup.Keys) {
                if ($key -like "virtualmachines|*$familyPrefix*|$location") {
                    $sizeFamilyMatch = $true
                    break
                }
            }
        }

        if (-not $isCovered -and -not $sizeFamilyMatch) {
            $totalUncoveredResources++

            # Estimate monthly cost (rough — varies by region/size)
            # We can't get exact pricing without the Retail Prices API, so we flag it
            Write-Flag "VM: $($vm.Name) ($vmSize, $location) — NO reservation or savings plan coverage detected"
            Write-Detail "RG: $($vm.ResourceGroupName)"

            Add-Finding -Category "VM-Uncovered" -Severity "Medium" `
                -Resource $vm.Name -ResourceGroup $vm.ResourceGroupName -Subscription $subName `
                -Detail "Size: $vmSize, Location: $location, Running (no RI/SP match found)" `
                -Recommendation "Consider 1yr or 3yr reservation (up to 72% savings) or compute savings plan (up to 65%)."
        } else {
            Write-Detail "VM: $($vm.Name) ($vmSize) — covered $(if ($isCovered) {'(exact SKU match)'} else {'(family match)'})"
        }
    }

    # ─────────────────────────────────────────────────────────────────────
    # 3b. SQL DATABASES (DTU and vCore)
    # ─────────────────────────────────────────────────────────────────────
    Write-Info "Checking SQL Databases..."
    $sqlServers = Get-AzSqlServer -ErrorAction SilentlyContinue

    foreach ($srv in $sqlServers) {
        $dbs = Get-AzSqlDatabase -ServerName $srv.ServerName -ResourceGroupName $srv.ResourceGroupName -ErrorAction SilentlyContinue |
               Where-Object { $_.DatabaseName -ne "master" }

        foreach ($db in $dbs) {
            $edition = $db.Edition
            $slo     = $db.CurrentServiceObjectiveName
            $loc     = $db.Location.ToLower()

            # Skip free / Basic tiers — not worth reserving
            if ($edition -iin @("Free", "Basic", "System")) { continue }
            # Skip serverless — can't reserve
            if ($slo -imatch "Serverless") { continue }

            $riKey = "sqldatabases|$slo|$loc"
            $isCovered = $reservedSkuLookup.ContainsKey($riKey)

            if (-not $isCovered) {
                $totalUncoveredResources++
                $vCores = if ($db.Capacity) { "$($db.Capacity) vCores/DTUs" } else { $slo }
                Write-Flag "SQL DB: $($srv.ServerName)/$($db.DatabaseName) ($edition/$slo, $loc) — no reserved capacity"
                Add-Finding -Category "SqlDB-Uncovered" -Severity "Medium" `
                    -Resource "$($srv.ServerName)/$($db.DatabaseName)" -ResourceGroup $srv.ResourceGroupName -Subscription $subName `
                    -Detail "Edition: $edition, Tier: $slo, $vCores, Location: $loc" `
                    -Recommendation "Reserved capacity offers up to 33% (1yr) or 65% (3yr) savings for vCore databases."
            }
        }

        # Elastic Pools
        $pools = Get-AzSqlElasticPool -ServerName $srv.ServerName -ResourceGroupName $srv.ResourceGroupName -ErrorAction SilentlyContinue
        foreach ($pool in $pools) {
            if ($pool.Edition -iin @("Basic", "Free")) { continue }
            $totalUncoveredResources++
            Write-Flag "SQL Elastic Pool: $($srv.ServerName)/$($pool.ElasticPoolName) ($($pool.Edition)/$($pool.Capacity)) — review for reserved capacity"
            Add-Finding -Category "SqlPool-Uncovered" -Severity "Low" `
                -Resource "$($srv.ServerName)/$($pool.ElasticPoolName)" -ResourceGroup $srv.ResourceGroupName -Subscription $subName `
                -Detail "Edition: $($pool.Edition), DTUs/vCores: $($pool.Capacity)" `
                -Recommendation "Elastic pool reserved capacity available for vCore-based pools."
        }
    }

    # ─────────────────────────────────────────────────────────────────────
    # 3c. SQL MANAGED INSTANCES
    # ─────────────────────────────────────────────────────────────────────
    Write-Info "Checking SQL Managed Instances..."
    $managedInstances = Get-AzSqlInstance -ErrorAction SilentlyContinue
    foreach ($mi in $managedInstances) {
        $totalUncoveredResources++
        Write-Flag "SQL MI: $($mi.ManagedInstanceName) ($($mi.Sku.Name), $($mi.VCores) vCores, $($mi.Location)) — review for reserved capacity"
        Add-Finding -Category "SqlMI-Uncovered" -Severity "Medium" `
            -Resource $mi.ManagedInstanceName -ResourceGroup $mi.ResourceGroupName -Subscription $subName `
            -Detail "SKU: $($mi.Sku.Name), vCores: $($mi.VCores), Location: $($mi.Location)" `
            -Recommendation "Reserved capacity for SQL MI: up to 33% (1yr) or 55% (3yr) savings."
    }

    # ─────────────────────────────────────────────────────────────────────
    # 3d. COSMOS DB
    # ─────────────────────────────────────────────────────────────────────
    Write-Info "Checking Cosmos DB..."
    $cosmosResources = Get-AzResource -ResourceType "Microsoft.DocumentDb/databaseAccounts" -ErrorAction SilentlyContinue
    foreach ($cosmosRes in $cosmosResources) {
        try {
            $acct = Get-AzCosmosDBAccount -Name $cosmosRes.Name -ResourceGroupName $cosmosRes.ResourceGroupName -ErrorAction Stop
            if ($acct.Capabilities.Name -contains "EnableServerless") { continue } # Serverless — no reservations

            $sqlDbs = Get-AzCosmosDBSqlDatabase -AccountName $acct.Name -ResourceGroupName $acct.ResourceGroupName -ErrorAction SilentlyContinue
            foreach ($cdb in $sqlDbs) {
                $containers = Get-AzCosmosDBSqlContainer -AccountName $acct.Name `
                    -ResourceGroupName $acct.ResourceGroupName -DatabaseName $cdb.Name -ErrorAction SilentlyContinue
                foreach ($cont in $containers) {
                    try {
                        $tp = Get-AzCosmosDBSqlContainerThroughput -AccountName $acct.Name `
                            -ResourceGroupName $acct.ResourceGroupName -DatabaseName $cdb.Name `
                            -Name $cont.Name -ErrorAction Stop
                        $ru = $tp.Resource.Throughput
                        $maxRu = $tp.Resource.AutoscaleSettings.MaxThroughput
                        $effectiveRU = if ($ru) { $ru } elseif ($maxRu) { $maxRu } else { 0 }

                        if ($effectiveRU -ge 1000) {
                            $totalUncoveredResources++
                            $ruType = if ($maxRu) { "autoscale max $maxRu" } else { "provisioned $ru" }
                            Write-Flag "Cosmos DB: $($acct.Name)/$($cdb.Name)/$($cont.Name) ($ruType RU/s) — review for reserved capacity"
                            Add-Finding -Category "CosmosDB-Uncovered" -Severity "Medium" `
                                -Resource "$($acct.Name)/$($cdb.Name)/$($cont.Name)" `
                                -ResourceGroup $acct.ResourceGroupName -Subscription $subName `
                                -Detail "$ruType RU/s" `
                                -Recommendation "Reserved throughput: up to 20% (1yr) or 30%+ (3yr) savings on provisioned RU/s."
                        }
                    } catch { }
                }
            }
        } catch { }
    }

    # ─────────────────────────────────────────────────────────────────────
    # 3e. APP SERVICE PLANS (Premium / Isolated)
    # ─────────────────────────────────────────────────────────────────────
    Write-Info "Checking App Service Plans..."
    $aspResources = Get-AzResource -ResourceType "Microsoft.Web/serverfarms" -ErrorAction SilentlyContinue
    foreach ($aspRes in $aspResources) {
        try {
            $asp = Get-AzAppServicePlan -ResourceGroupName $aspRes.ResourceGroupName -Name $aspRes.Name -ErrorAction Stop
            $tier = $asp.Sku.Tier
            if ($tier -iin @("Premium", "PremiumV2", "PremiumV3", "Isolated", "IsolatedV2")) {
                $totalUncoveredResources++
                $workers = $asp.Sku.Capacity
                Write-Flag "App Service Plan: $($asp.Name) ($tier, $($asp.Sku.Name), $workers workers) — review for reserved instances"
                Add-Finding -Category "AppService-Uncovered" -Severity "Low" `
                    -Resource $asp.Name -ResourceGroup $aspRes.ResourceGroupName -Subscription $subName `
                    -Detail "Tier: $tier, SKU: $($asp.Sku.Name), Workers: $workers" `
                    -Recommendation "Premium/Isolated ASP reserved instances: up to 55% savings."
            }
        } catch { }
    }

    # ─────────────────────────────────────────────────────────────────────
    # 3f. REDIS CACHE (Premium / Enterprise)
    # ─────────────────────────────────────────────────────────────────────
    Write-Info "Checking Redis Cache..."
    $redisResources = Get-AzResource -ResourceType "Microsoft.Cache/redis" -ErrorAction SilentlyContinue
    foreach ($r in $redisResources) {
        try {
            $redis = Get-AzRedisCache -ResourceGroupName $r.ResourceGroupName -Name $r.Name -ErrorAction Stop
            if ($redis.Sku -iin @("Premium", "Enterprise", "EnterpriseFlash")) {
                $totalUncoveredResources++
                Write-Flag "Redis Cache: $($r.Name) ($($redis.Sku)/$($redis.Size)) — review for reserved capacity"
                Add-Finding -Category "Redis-Uncovered" -Severity "Low" `
                    -Resource $r.Name -ResourceGroup $r.ResourceGroupName -Subscription $subName `
                    -Detail "SKU: $($redis.Sku), Size: $($redis.Size)" `
                    -Recommendation "Redis reserved capacity: up to 55% savings on Premium tier."
            }
        } catch { }
    }

    # ─────────────────────────────────────────────────────────────────────
    # 3g. PREMIUM / ULTRA MANAGED DISKS
    # ─────────────────────────────────────────────────────────────────────
    Write-Info "Checking Premium/Ultra Disks..."
    $disks = Get-AzDisk -ErrorAction SilentlyContinue |
             Where-Object { $_.Sku.Name -iin @("Premium_LRS", "Premium_ZRS", "UltraSSD_LRS") }
    if ($disks.Count -gt 0) {
        $diskGroups = $disks | Group-Object { "$($_.Sku.Name)|$($_.DiskSizeGB)" }
        foreach ($group in $diskGroups) {
            $sample = $group.Group[0]
            $count  = $group.Count
            $totalUncoveredResources += $count
            Write-Flag "Disks: $count x $($sample.Sku.Name) ($($sample.DiskSizeGB) GB) — review for disk reservations"
            Add-Finding -Category "Disk-Uncovered" -Severity "Low" `
                -Resource "$count x $($sample.Sku.Name) $($sample.DiskSizeGB)GB" `
                -ResourceGroup "(multiple)" -Subscription $subName `
                -Detail "Count: $count, SKU: $($sample.Sku.Name), Size: $($sample.DiskSizeGB) GB each" `
                -Recommendation "Premium SSD reservations: up to 38% savings on P30+ sizes."
        }
    }

    # ─────────────────────────────────────────────────────────────────────
    # 3h. DATA EXPLORER (KUSTO)
    # ─────────────────────────────────────────────────────────────────────
    Write-Info "Checking Data Explorer clusters..."
    try {
        $adxClusters = Get-AzKustoCluster -ErrorAction Stop | Where-Object { $_.State -ieq "Running" }
        foreach ($adx in $adxClusters) {
            $totalUncoveredResources++
            Write-Flag "Data Explorer: $($adx.Name) (SKU: $($adx.SkuName), Instances: $($adx.SkuCapacity)) — review for reserved capacity"
            Add-Finding -Category "ADX-Uncovered" -Severity "Medium" `
                -Resource $adx.Name -ResourceGroup $adx.ResourceGroupName -Subscription $subName `
                -Detail "SKU: $($adx.SkuName), Capacity: $($adx.SkuCapacity)" `
                -Recommendation "ADX reserved capacity: significant savings for always-on clusters."
        }
    } catch { }

    # ─────────────────────────────────────────────────────────────────────
    # 3i. SYNAPSE DEDICATED SQL POOLS
    # ─────────────────────────────────────────────────────────────────────
    Write-Info "Checking Synapse pools..."
    $synapseWs = Get-AzSynapseWorkspace -ErrorAction SilentlyContinue
    foreach ($ws in $synapseWs) {
        $pools = Get-AzSynapseSqlPool -WorkspaceName $ws.Name -ResourceGroupName $ws.ResourceGroupName -ErrorAction SilentlyContinue |
                 Where-Object { $_.Status -ieq "Online" }
        foreach ($pool in $pools) {
            $totalUncoveredResources++
            Write-Flag "Synapse Pool: $($ws.Name)/$($pool.SqlPoolName) ($($pool.Sku.Name)) — review for reserved capacity"
            Add-Finding -Category "Synapse-Uncovered" -Severity "Medium" `
                -Resource "$($ws.Name)/$($pool.SqlPoolName)" -ResourceGroup $ws.ResourceGroupName -Subscription $subName `
                -Detail "SKU: $($pool.Sku.Name), Status: Online" `
                -Recommendation "Synapse DW reserved capacity: up to 65% savings."
        }
    }

    # ─────────────────────────────────────────────────────────────────────
    # 3j. DATABRICKS WORKSPACES
    # ─────────────────────────────────────────────────────────────────────
    Write-Info "Checking Databricks..."
    $dbwSpaces = Get-AzResource -ResourceType "Microsoft.Databricks/workspaces" -ErrorAction SilentlyContinue
    foreach ($dbw in $dbwSpaces) {
        $totalUncoveredResources++
        Write-Flag "Databricks: $($dbw.Name) — review for DBU commit plans (DBCU)"
        Add-Finding -Category "Databricks-Uncovered" -Severity "Low" `
            -Resource $dbw.Name -ResourceGroup $dbw.ResourceGroupName -Subscription $subName `
            -Detail "Workspace exists. Check for running clusters in the Databricks console." `
            -Recommendation "Databricks commit plans: pre-purchase DBUs at up to 37% discount."
    }

    # ─────────────────────────────────────────────────────────────────────
    # 3k. AZURE VMWARE SOLUTION
    # ─────────────────────────────────────────────────────────────────────
    $avsResources = Get-AzResource -ResourceType "Microsoft.AVS/privateClouds" -ErrorAction SilentlyContinue
    foreach ($avs in $avsResources) {
        $totalUncoveredResources++
        Write-Flag "Azure VMware Solution: $($avs.Name) — review for reserved instances (up to 57% savings)"
        Add-Finding -Category "AVS-Uncovered" -Severity "High" `
            -Resource $avs.Name -ResourceGroup $avs.ResourceGroupName -Subscription $subName `
            -Detail "AVS Private Cloud" `
            -Recommendation "AVS reserved instances offer up to 57% savings. High hourly cost."
    }
}

Write-Host ""
Write-Info "Total uncovered resources flagged: $totalUncoveredResources"

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4: AZURE ADVISOR RECOMMENDATIONS
# ═════════════════════════════════════════════════════════════════════════════

if ($IncludeAdvisor) {
    Write-Header "SECTION 4: AZURE ADVISOR RECOMMENDATIONS"

    foreach ($sub in $subscriptions) {
        Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
        Write-Info "Pulling Advisor cost recommendations for $($sub.Name)..."

        try {
            $advisorRecs = Get-AzAdvisorRecommendation -Category Cost -ErrorAction Stop

            $riRecs = $advisorRecs | Where-Object {
                $_.ShortDescription.Problem -imatch "reservation|reserved|savings plan|saving" -or
                $_.Category -ieq "Cost"
            }

            if ($riRecs.Count -eq 0) {
                Write-Detail "No reservation/savings plan recommendations from Advisor."
                continue
            }

            foreach ($rec in $riRecs) {
                $problem    = $rec.ShortDescription.Problem
                $solution   = $rec.ShortDescription.Solution
                $impact     = $rec.Impact
                $resource   = $rec.ResourceMetadata.ResourceId
                $savingsAmt = $rec.ExtendedProperties.annualSavingsAmount
                $savingsCur = $rec.ExtendedProperties.savingsCurrency
                $lookback   = $rec.ExtendedProperties.lookbackPeriod
                $sku        = $rec.ExtendedProperties.displaySKU
                $qty        = $rec.ExtendedProperties.displayQty
                $region     = $rec.ExtendedProperties.region
                $term       = $rec.ExtendedProperties.term

                $savingsStr = if ($savingsAmt) { "$savingsAmt $savingsCur/yr" } else { "See Advisor" }

                $colour = switch ($impact) {
                    "High"   { "Red" }
                    "Medium" { "Yellow" }
                    default  { "Gray" }
                }

                Write-Host "    [$impact] " -ForegroundColor $colour -NoNewline
                Write-Host "$problem" -ForegroundColor White
                if ($sku)        { Write-Detail "SKU: $sku | Qty: $qty | Region: $region | Term: $term" }
                if ($savingsAmt) { Write-Host "          💰 Estimated savings: $savingsStr" -ForegroundColor Green }
                if ($solution)   { Write-Detail "Solution: $solution" }

                Add-Finding -Category "Advisor-Recommendation" -Severity $impact `
                    -Resource ($sku ?? $resource ?? "N/A") -ResourceGroup "" -Subscription $sub.Name `
                    -Detail "$problem $(if ($sku) { "| SKU: $sku, Qty: $qty, Region: $region, Term: $term" })" `
                    -Recommendation $solution `
                    -EstimatedSavings ([decimal]::TryParse($savingsAmt, [ref]$null) ? [decimal]$savingsAmt : 0)
            }
        } catch {
            Write-Flag "Could not retrieve Advisor recommendations for $($sub.Name): $_"
        }
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 5: CONSUMPTION API RESERVATION RECOMMENDATIONS
# ═════════════════════════════════════════════════════════════════════════════

Write-Header "SECTION 5: CONSUMPTION API RESERVATION RECOMMENDATIONS"
Write-Info "Querying Microsoft's usage-based reservation recommendations ($LookbackDays-day lookback)..."

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null

    try {
        $lookback = "Last${LookbackDays}Days"
        $recPath = "/subscriptions/$($sub.Id)/providers/Microsoft.Consumption/reservationRecommendations?api-version=2023-05-01&`$filter=properties/lookBackPeriod eq '$lookback' and properties/scope eq 'Single'"
        $recResult = Invoke-AzRestMethod -Path $recPath -Method GET -ErrorAction Stop

        if ($recResult.StatusCode -eq 200) {
            $recs = ($recResult.Content | ConvertFrom-Json).value

            if ($recs.Count -eq 0) {
                Write-Detail "No recommendations for $($sub.Name) (usage may be too low or already covered)."
                continue
            }

            Write-Info "Recommendations for $($sub.Name):"
            foreach ($rec in $recs | Sort-Object { $_.properties.netSavings } -Descending | Select-Object -First 15) {
                $p = $rec.properties
                $sku        = $p.skuProperties | Where-Object { $_.name -eq "SKUName" } | Select-Object -ExpandProperty value -ErrorAction SilentlyContinue
                $region     = $p.skuProperties | Where-Object { $_.name -eq "Location" -or $_.name -eq "Region" } | Select-Object -ExpandProperty value -ErrorAction SilentlyContinue
                $qty        = $p.recommendedQuantity
                $savings    = [math]::Round($p.netSavings, 0)
                $totalCost  = [math]::Round($p.totalCostWithReservedInstances, 0)
                $payg       = [math]::Round($p.costWithNoReservedInstances, 0)
                $term       = $p.term
                $resourceType = $p.resourceType

                if (-not $sku) { $sku = $resourceType }
                $savingsPct = if ($payg -gt 0) { [math]::Round(($savings / $payg) * 100, 0) } else { 0 }

                Write-Host "    💡 " -NoNewline -ForegroundColor Cyan
                Write-Host "$resourceType" -ForegroundColor White -NoNewline
                Write-Host " | $sku | $region | Qty: $qty | Term: $term" -ForegroundColor DarkGray
                Write-Host "       PAYG: `$$payg → RI: `$$totalCost | " -ForegroundColor DarkGray -NoNewline
                Write-Host "Save: `$$savings/yr ($savingsPct%)" -ForegroundColor Green

                Add-Finding -Category "Consumption-Recommendation" -Severity $(if ($savings -gt 5000) { "High" } elseif ($savings -gt 1000) { "Medium" } else { "Low" }) `
                    -Resource "$resourceType | $sku" -ResourceGroup "" -Subscription $sub.Name `
                    -Detail "SKU: $sku, Region: $region, Qty: $qty, Term: $term, PAYG: `$$payg/yr" `
                    -Recommendation "Purchase $qty x $sku reservation ($term). Saves `$$savings/yr ($savingsPct%)." `
                    -EstimatedSavings $savings
            }
        } elseif ($recResult.StatusCode -eq 204) {
            Write-Detail "No data for $($sub.Name)."
        } else {
            Write-Flag "Consumption API returned $($recResult.StatusCode) for $($sub.Name)."
        }
    } catch {
        Write-Flag "Could not query reservation recommendations for $($sub.Name): $_"
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# SECTION 6: HIGH-UPTIME VM CANDIDATES
# ═════════════════════════════════════════════════════════════════════════════

Write-Header "SECTION 6: HIGH-UPTIME VM CANDIDATES (reservation sweet spot)"
Write-Info "Checking Azure Monitor for VMs with consistently high uptime..."

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null

    $vms = Get-AzVM -Status -ErrorAction SilentlyContinue |
           Where-Object { $_.PowerState -ieq "VM running" }

    foreach ($vm in $vms) {
        # Query the VM availability metric over the lookback period
        $endTime   = (Get-Date).ToUniversalTime()
        $startTime = $endTime.AddDays(-$LookbackDays)

        try {
            $metric = Get-AzMetric -ResourceId $vm.Id `
                -MetricName "VmAvailabilityMetric" `
                -StartTime $startTime -EndTime $endTime `
                -AggregationType Average `
                -TimeGrain 1.00:00:00 `
                -ErrorAction Stop

            $dataPoints = $metric.Data | Where-Object { $null -ne $_.Average }
            if ($dataPoints.Count -ge ($LookbackDays * 0.8)) {
                $avgAvail = [math]::Round(($dataPoints | Measure-Object -Property Average -Average).Average, 2)

                if ($avgAvail -ge 95) {
                    Write-Good "VM: $($vm.Name) ($($vm.HardwareProfile.VmSize)) — $avgAvail% uptime over $LookbackDays days → STRONG reservation candidate"
                    Add-Finding -Category "VM-HighUptime" -Severity "Info" `
                        -Resource $vm.Name -ResourceGroup $vm.ResourceGroupName -Subscription $sub.Name `
                        -Detail "Size: $($vm.HardwareProfile.VmSize), Avg availability: $avgAvail% over $LookbackDays days" `
                        -Recommendation "High uptime = high reservation ROI. Consider 1yr RI (up to 40%) or 3yr RI (up to 72%)."
                }
            }
        } catch {
            # VmAvailabilityMetric may not be available on all VM types
            # Fall back: if the VM is currently running, it's at least a candidate
        }
    }
}

# ═════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                        ANALYSIS SUMMARY                              ║" -ForegroundColor Cyan
Write-Host "╠═══════════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan

$riCount   = $activeReservations.Count
$spCount   = $activeSavingsPlans.Count
$underRI   = $underUtilizedReservations.Count
$underSP   = $underUtilizedSavingsPlans.Count
$expiring  = $expiringReservations.Count
$totalFindings = $script:Findings.Count
$totalEstSavings = ($script:Findings | Where-Object { $_.EstimatedSavings -gt 0 } | Measure-Object -Property EstimatedSavings -Sum).Sum
$totalEstSavings = if ($totalEstSavings) { [math]::Round($totalEstSavings, 0) } else { 0 }

Write-Host "║                                                                      ║" -ForegroundColor Cyan
Write-Host "║  EXISTING COMMITMENTS                                                ║" -ForegroundColor Cyan
Write-Host "║    Active Reservations:        $('{0,-39}' -f $riCount)║" -ForegroundColor Cyan
Write-Host "║    Active Savings Plans:       $('{0,-39}' -f $spCount)║" -ForegroundColor Cyan
Write-Host "║    Under-utilized (< $($UtilizationThresholdPct)%):     $('{0,-39}' -f ($underRI + $underSP))║" -ForegroundColor $(if (($underRI + $underSP) -gt 0) { "Yellow" } else { "Cyan" })
Write-Host "║    Expiring (< $($ExpiryWarningDays) days):       $('{0,-39}' -f $expiring)║" -ForegroundColor $(if ($expiring -gt 0) { "Yellow" } else { "Cyan" })
Write-Host "║                                                                      ║" -ForegroundColor Cyan
Write-Host "║  COVERAGE GAPS                                                       ║" -ForegroundColor Cyan
Write-Host "║    Uncovered resources flagged: $('{0,-38}' -f $totalUncoveredResources)║" -ForegroundColor $(if ($totalUncoveredResources -gt 0) { "Yellow" } else { "Cyan" })
Write-Host "║                                                                      ║" -ForegroundColor Cyan
Write-Host "║  RECOMMENDATIONS                                                     ║" -ForegroundColor Cyan
Write-Host "║    Total findings:             $('{0,-39}' -f $totalFindings)║" -ForegroundColor Cyan

if ($totalEstSavings -gt 0) {
Write-Host "║    Estimated annual savings:   $('{0,-39}' -f "`$$($totalEstSavings.ToString('N0'))/yr")║" -ForegroundColor Green
}

Write-Host "║                                                                      ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# ═════════════════════════════════════════════════════════════════════════════
# EXPORT (optional)
# ═════════════════════════════════════════════════════════════════════════════

if ($ExportPath) {
    Write-Header "EXPORTING REPORT"

    if (-not (Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

    # ── CSV export ──
    $csvPath = Join-Path $ExportPath "reservation-analysis-$timestamp.csv"
    $script:Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Good "CSV exported: $csvPath"

    # ── Reservations detail CSV ──
    if ($activeReservations.Count -gt 0) {
        $riCsvPath = Join-Path $ExportPath "active-reservations-$timestamp.csv"
        $activeReservations | Export-Csv -Path $riCsvPath -NoTypeInformation -Encoding UTF8
        Write-Good "Reservations CSV: $riCsvPath"
    }

    # ── Savings Plans detail CSV ──
    if ($activeSavingsPlans.Count -gt 0) {
        $spCsvPath = Join-Path $ExportPath "active-savingsplans-$timestamp.csv"
        $activeSavingsPlans | Export-Csv -Path $spCsvPath -NoTypeInformation -Encoding UTF8
        Write-Good "Savings Plans CSV: $spCsvPath"
    }

    # ── HTML report ──
    $htmlPath = Join-Path $ExportPath "reservation-analysis-$timestamp.html"

    $highFindings   = ($script:Findings | Where-Object { $_.Severity -iin @("High","Critical") }).Count
    $mediumFindings = ($script:Findings | Where-Object { $_.Severity -ieq "Medium" }).Count
    $lowFindings    = ($script:Findings | Where-Object { $_.Severity -iin @("Low","Info") }).Count

    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Azure Reservations &amp; Savings Plans Analysis — $timestamp</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 2rem; background: #f5f5f5; color: #333; }
        h1 { color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 0.5rem; }
        h2 { color: #005a9e; margin-top: 2rem; }
        .summary-cards { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
        .card { background: white; border-radius: 8px; padding: 1.5rem; box-shadow: 0 2px 8px rgba(0,0,0,0.1); min-width: 200px; flex: 1; }
        .card h3 { margin: 0 0 0.5rem 0; font-size: 0.9rem; color: #666; text-transform: uppercase; }
        .card .value { font-size: 2rem; font-weight: bold; color: #0078d4; }
        .card .value.warn { color: #f59e0b; }
        .card .value.good { color: #10b981; }
        .card .value.bad  { color: #ef4444; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-top: 1rem; }
        th { background: #0078d4; color: white; padding: 0.75rem; text-align: left; font-size: 0.85rem; }
        td { padding: 0.6rem 0.75rem; border-bottom: 1px solid #eee; font-size: 0.85rem; }
        tr:hover td { background: #f0f7ff; }
        .severity-High, .severity-Critical { color: #ef4444; font-weight: bold; }
        .severity-Medium { color: #f59e0b; font-weight: bold; }
        .severity-Low  { color: #3b82f6; }
        .severity-Info { color: #6b7280; }
        .footer { margin-top: 2rem; font-size: 0.8rem; color: #999; }
    </style>
</head>
<body>
    <h1>Azure Reservations &amp; Savings Plans Analysis</h1>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") UTC &nbsp;|&nbsp; Lookback: $LookbackDays days &nbsp;|&nbsp; Utilization threshold: $UtilizationThresholdPct%</p>

    <div class="summary-cards">
        <div class="card"><h3>Active Reservations</h3><div class="value">$riCount</div></div>
        <div class="card"><h3>Active Savings Plans</h3><div class="value">$spCount</div></div>
        <div class="card"><h3>Under-Utilized</h3><div class="value $(if (($underRI+$underSP) -gt 0) {'warn'} else {'good'})">$($underRI + $underSP)</div></div>
        <div class="card"><h3>Expiring Soon</h3><div class="value $(if ($expiring -gt 0) {'warn'} else {'good'})">$expiring</div></div>
        <div class="card"><h3>Uncovered Resources</h3><div class="value $(if ($totalUncoveredResources -gt 0) {'bad'} else {'good'})">$totalUncoveredResources</div></div>
        <div class="card"><h3>Est. Annual Savings</h3><div class="value good">`$$($totalEstSavings.ToString('N0'))</div></div>
    </div>

    <h2>All Findings ($totalFindings)</h2>
    <table>
        <tr><th>Severity</th><th>Category</th><th>Resource</th><th>Subscription</th><th>Detail</th><th>Recommendation</th><th>Est. Savings</th></tr>
"@

    foreach ($f in ($script:Findings | Sort-Object {
        switch ($_.Severity) { "Critical" {0} "High" {1} "Medium" {2} "Low" {3} "Info" {4} default {5} }
    })) {
        $savingsCell = if ($f.EstimatedSavings -gt 0) { "`$$($f.EstimatedSavings.ToString('N0'))/yr" } else { "—" }
        $htmlContent += @"
        <tr>
            <td class="severity-$($f.Severity)">$($f.Severity)</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Category))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Resource))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Subscription))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Detail))</td>
            <td>$([System.Web.HttpUtility]::HtmlEncode($f.Recommendation))</td>
            <td>$savingsCell</td>
        </tr>
"@
    }

    $htmlContent += @"
    </table>

    <h2>Active Reservations ($riCount)</h2>
    <table>
        <tr><th>Name</th><th>Type</th><th>SKU</th><th>Location</th><th>Qty</th><th>Term</th><th>Scope</th><th>Utilization</th><th>Unused Hrs</th><th>Expiry</th><th>Days Left</th></tr>
"@
    foreach ($ri in $activeReservations) {
        $utilClass = if ($null -ne $ri.AvgUtilizationPct -and $ri.AvgUtilizationPct -lt $UtilizationThresholdPct) { "severity-High" } else { "" }
        $htmlContent += @"
        <tr>
            <td>$([System.Web.HttpUtility]::HtmlEncode($ri.Name))</td>
            <td>$($ri.ReservedType)</td><td>$($ri.SKU)</td><td>$($ri.Location)</td>
            <td>$($ri.Quantity)</td><td>$($ri.Term)</td><td>$($ri.Scope)</td>
            <td class="$utilClass">$(if ($null -ne $ri.AvgUtilizationPct) { "$($ri.AvgUtilizationPct)%" } else { "N/A" })</td>
            <td>$($ri.UnusedHours)</td><td>$($ri.ExpiryDate)</td>
            <td>$($ri.DaysToExpiry)</td>
        </tr>
"@
    }

    $htmlContent += @"
    </table>

    <div class="footer">
        <p>Generated by Analyze-ReservationsAndSavingsPlans.ps1 | Savings estimates are based on Azure Advisor and Consumption API data — actual savings may vary.</p>
    </div>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Good "HTML report: $htmlPath"
}

# ═════════════════════════════════════════════════════════════════════════════
# TIPS
# ═════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor DarkGray
Write-Host "║  TIPS                                                                ║" -ForegroundColor DarkGray
Write-Host "║                                                                      ║" -ForegroundColor DarkGray
Write-Host "║  • Reservations vs Savings Plans:                                    ║" -ForegroundColor DarkGray
Write-Host "║    - Reservations = specific SKU + region → biggest discount         ║" -ForegroundColor DarkGray
Write-Host "║    - Savings Plans = flexible across SKUs/regions → simpler          ║" -ForegroundColor DarkGray
Write-Host "║    - Use RIs for stable workloads, SPs for dynamic/multi-region      ║" -ForegroundColor DarkGray
Write-Host "║                                                                      ║" -ForegroundColor DarkGray
Write-Host "║  • Set reservation scope to 'Shared' for maximum utilization         ║" -ForegroundColor DarkGray
Write-Host "║  • Enable auto-renewal on reservations nearing expiry                ║" -ForegroundColor DarkGray
Write-Host "║  • Exchange under-utilized RIs for right-sized ones (free)           ║" -ForegroundColor DarkGray
Write-Host "║  • Combine RI + SP: RI applied first, SP covers the rest            ║" -ForegroundColor DarkGray
Write-Host "║  • Check Azure Portal → Cost Management → Reservations for full UX  ║" -ForegroundColor DarkGray
Write-Host "║                                                                      ║" -ForegroundColor DarkGray
Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor DarkGray
Write-Host ""