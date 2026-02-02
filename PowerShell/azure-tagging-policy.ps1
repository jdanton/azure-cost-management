<#
.SYNOPSIS
    Deploys an Azure Policy initiative that enforces mandatory resource tagging.

.DESCRIPTION
    Creates and assigns a Policy Initiative (Policy Set) requiring the following tags
    on all resources and resource groups:

    REQUIRED TAGS
    ─────────────────────────────────────────────────────────────────────────
    Tag Name        Description                         Validation
    ─────────────────────────────────────────────────────────────────────────
    CostCenter      Finance/billing charge code          Must not be empty
    Environment     Deployment stage                     Allowed values list
    Department      Owning business unit                 Must not be empty
    CreatedDate     Date the resource was created        Must match YYYY-MM-DD
    Owner           Responsible person/team email        Must not be empty
    Application     Application or workload name         Must not be empty
    ─────────────────────────────────────────────────────────────────────────

    The initiative contains three policy types per tag:

    1. DENY    — blocks resource creation/update if the tag is missing or empty
    2. AUDIT   — reports non-compliance without blocking (for existing resources)
    3. INHERIT — automatically copies the tag value from the resource group to
                 child resources via a "Modify" effect (with remediation)

    MODES
    ─────────────────────────────────────────────────────────────────────────
    -EnforcementMode "Deny"    Blocks non-compliant creates (recommended
                               after a burn-in audit period)
    -EnforcementMode "Audit"   Reports only — nothing is blocked.
                               Use this first to assess existing compliance.
    ─────────────────────────────────────────────────────────────────────────

    ╔═══════════════════════════════════════════════════════════════════════╗
    ║  RECOMMENDED ROLLOUT                                                ║
    ║  1. Deploy with -EnforcementMode Audit                              ║
    ║  2. Review compliance in the Azure Portal (Policy → Compliance)     ║
    ║  3. Run remediation tasks to backfill tags on existing resources     ║
    ║  4. Switch to -EnforcementMode Deny once compliance is high         ║
    ╚═══════════════════════════════════════════════════════════════════════╝

.PARAMETER SubscriptionId
    Target subscription. If omitted, uses the current Az context subscription.

.PARAMETER ManagementGroupName
    Assign at management group scope instead of subscription. Takes precedence
    over SubscriptionId when both are supplied.

.PARAMETER EnforcementMode
    "Deny" (default) or "Audit". Controls whether non-compliant operations
    are blocked or only reported.

.PARAMETER AllowedEnvironments
    Permitted values for the Environment tag. Defaults to:
    dev, development, test, qa, staging, uat, preprod, prod, production, sandbox, dr

.PARAMETER CreateRemediationTasks
    When $true, creates remediation tasks for the Modify (inherit) policies so
    existing resources pick up tags from their resource group.

.PARAMETER InitiativeDisplayName
    Display name for the policy initiative.

.EXAMPLE
    # Audit mode — assess compliance without blocking anything
    .\Deploy-TaggingPolicy.ps1 -EnforcementMode Audit

.EXAMPLE
    # Enforce at management group level with remediation
    .\Deploy-TaggingPolicy.ps1 -ManagementGroupName "mg-corp" -EnforcementMode Deny -CreateRemediationTasks $true

.EXAMPLE
    # Custom environment values
    .\Deploy-TaggingPolicy.ps1 -AllowedEnvironments @("dev","staging","prod","sandbox")
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$ManagementGroupName,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Deny", "Audit")]
    [string]$EnforcementMode = "Deny",

    [Parameter(Mandatory = $false)]
    [string[]]$AllowedEnvironments = @(
        "dev", "development", "test", "qa", "staging",
        "uat", "preprod", "prod", "production", "sandbox", "dr"
    ),

    [Parameter(Mandatory = $false)]
    [bool]$CreateRemediationTasks = $false,

    [Parameter(Mandatory = $false)]
    [string]$InitiativeDisplayName = "Require Mandatory Resource Tags"
)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
$ErrorActionPreference = "Stop"

$initiativeName = "require-mandatory-tags"
$policyCategory = "Tags"
$policyVersion  = "1.0.0"

# The effect to use for "require tag" policies — Deny or Audit
$requireEffect = $EnforcementMode

# Modify policies always use "Modify" effect, but assignment enforcement mode
# determines whether they're actually enforced or just audited
$assignmentEnforcementMode = if ($EnforcementMode -eq "Audit") { "DoNotEnforce" } else { "Default" }

# Define mandatory tags
$mandatoryTags = @(
    @{
        TagName     = "CostCenter"
        DisplayName = "Require CostCenter tag"
        Description = "Resources must have a CostCenter tag for billing allocation."
        Validation  = "NotEmpty"  # Just must exist and not be empty
    },
    @{
        TagName     = "Environment"
        DisplayName = "Require Environment tag with allowed values"
        Description = "Resources must have an Environment tag with an approved value."
        Validation  = "AllowedValues"
    },
    @{
        TagName     = "Department"
        DisplayName = "Require Department tag"
        Description = "Resources must have a Department tag identifying the owning business unit."
        Validation  = "NotEmpty"
    },
    @{
        TagName     = "CreatedDate"
        DisplayName = "Require CreatedDate tag (YYYY-MM-DD)"
        Description = "Resources must have a CreatedDate tag in YYYY-MM-DD format."
        Validation  = "DateFormat"
    },
    @{
        TagName     = "Owner"
        DisplayName = "Require Owner tag"
        Description = "Resources must have an Owner tag (email of responsible person or team)."
        Validation  = "NotEmpty"
    },
    @{
        TagName     = "Application"
        DisplayName = "Require Application tag"
        Description = "Resources must have an Application tag identifying the workload or system."
        Validation  = "NotEmpty"
    }
)

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: BUILD POLICY RULE FOR EACH TAG
# ─────────────────────────────────────────────────────────────────────────────

function New-RequireTagPolicyRule {
    <#
        Creates a policy rule that denies/audits resources missing a tag or
        having an empty value. Supports three validation types:
          - NotEmpty:       tag must exist and not be ""
          - AllowedValues:  tag must be one of the allowed values (case-insensitive)
          - DateFormat:     tag must match YYYY-MM-DD pattern
    #>
    param(
        [string]$TagName,
        [string]$Validation,
        [string]$Effect
    )

    switch ($Validation) {
        "NotEmpty" {
            $rule = @{
                "if" = @{
                    "anyOf" = @(
                        @{
                            "field"  = "[concat('tags[', '$TagName', ']')]"
                            "exists" = "false"
                        },
                        @{
                            "field"  = "[concat('tags[', '$TagName', ']')]"
                            "equals" = ""
                        }
                    )
                }
                "then" = @{
                    "effect" = $Effect
                }
            }
        }

        "AllowedValues" {
            $rule = @{
                "if" = @{
                    "anyOf" = @(
                        @{
                            "field"  = "[concat('tags[', '$TagName', ']')]"
                            "exists" = "false"
                        },
                        @{
                            "field"  = "[concat('tags[', '$TagName', ']')]"
                            "notIn"  = "[parameters('allowedEnvironments')]"
                        }
                    )
                }
                "then" = @{
                    "effect" = $Effect
                }
            }
        }

        "DateFormat" {
            # Require YYYY-MM-DD format using a match condition
            $rule = @{
                "if" = @{
                    "anyOf" = @(
                        @{
                            "field"  = "[concat('tags[', '$TagName', ']')]"
                            "exists" = "false"
                        },
                        @{
                            "field"    = "[concat('tags[', '$TagName', ']')]"
                            "notMatch" = "####-##-##"
                        }
                    )
                }
                "then" = @{
                    "effect" = $Effect
                }
            }
        }
    }

    return $rule
}

function New-InheritTagPolicyRule {
    <#
        Creates a Modify policy rule that copies a tag from the resource group
        to child resources if the tag is missing or empty on the resource.
    #>
    param([string]$TagName)

    $rule = @{
        "if" = @{
            "allOf" = @(
                @{
                    "field"    = "[concat('tags[', '$TagName', ']')]"
                    "notEquals" = "[resourceGroup().tags['$TagName']]"
                },
                @{
                    "value"    = "[resourceGroup().tags['$TagName']]"
                    "notEquals" = ""
                }
            )
        }
        "then" = @{
            "effect"  = "Modify"
            "details" = @{
                "roleDefinitionIds" = @(
                    "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"  # Contributor
                )
                "operations" = @(
                    @{
                        "operation" = "addOrReplace"
                        "field"     = "[concat('tags[', '$TagName', ']')]"
                        "value"     = "[resourceGroup().tags['$TagName']]"
                    }
                )
            }
        }
    }

    return $rule
}

# ─────────────────────────────────────────────────────────────────────────────
# AUTHENTICATE & SET SCOPE
# ─────────────────────────────────────────────────────────────────────────────

Write-Output ""
Write-Output "╔═══════════════════════════════════════════════════════════════════════╗"
Write-Output "║          AZURE TAGGING POLICY DEPLOYMENT                             ║"
Write-Output "║                                                                      ║"
Write-Output "║  Enforcement: $('{0,-55}' -f $EnforcementMode)║"
Write-Output "║  Tags:        $('{0,-55}' -f ($mandatoryTags.TagName -join ', '))║"
Write-Output "╚═══════════════════════════════════════════════════════════════════════╝"
Write-Output ""

# Ensure we're connected
$context = Get-AzContext -ErrorAction SilentlyContinue
if (-not $context) {
    Write-Output "No Azure context found. Attempting managed identity login..."
    Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
    $context = Get-AzContext
}

# Determine scope
if ($ManagementGroupName) {
    $scope = "/providers/Microsoft.Management/managementGroups/$ManagementGroupName"
    $scopeDisplay = "Management Group: $ManagementGroupName"
    $definitionScope = $scope
} else {
    if (-not $SubscriptionId) { $SubscriptionId = $context.Subscription.Id }
    Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
    $scope = "/subscriptions/$SubscriptionId"
    $scopeDisplay = "Subscription: $SubscriptionId"
    $definitionScope = $scope
}

Write-Output "Scope: $scopeDisplay"
Write-Output ""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: CREATE INDIVIDUAL POLICY DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

Write-Output "━━━ Step 1: Creating policy definitions ━━━"

$policyDefinitionIds = [System.Collections.Generic.List[object]]::new()
$inheritPolicyIds    = [System.Collections.Generic.List[string]]::new()

foreach ($tag in $mandatoryTags) {
    $tagName = $tag.TagName

    # ── 1a. Require tag policy (Deny/Audit) ──
    $requirePolicyName = "require-tag-$($tagName.ToLower())"
    $requireRule = New-RequireTagPolicyRule -TagName $tagName -Validation $tag.Validation -Effect $requireEffect

    # Build parameters block (only needed for AllowedValues)
    $requireParams = @{}
    if ($tag.Validation -eq "AllowedValues") {
        $requireParams = @{
            "allowedEnvironments" = @{
                "type"     = "Array"
                "metadata" = @{
                    "displayName" = "Allowed Environment values"
                    "description" = "The list of permitted values for the Environment tag."
                }
                "defaultValue" = $AllowedEnvironments
            }
        }
    }

    $requirePolicyDef = @{
        Name            = $requirePolicyName
        DisplayName     = $tag.DisplayName
        Description     = $tag.Description
        Policy          = ($requireRule | ConvertTo-Json -Depth 20)
        Parameter       = if ($requireParams.Count -gt 0) { ($requireParams | ConvertTo-Json -Depth 10) } else { $null }
        Mode            = "Indexed"
        Metadata        = (@{ category = $policyCategory; version = $policyVersion } | ConvertTo-Json)
    }

    # Add scope parameter
    if ($ManagementGroupName) {
        $requirePolicyDef["ManagementGroupName"] = $ManagementGroupName
    } else {
        $requirePolicyDef["SubscriptionId"] = $SubscriptionId
    }

    # Remove null Parameter to avoid errors
    if (-not $requirePolicyDef.Parameter) { $requirePolicyDef.Remove("Parameter") }

    Write-Output "  Creating: $($tag.DisplayName)..."
    $createdRequire = New-AzPolicyDefinition @requirePolicyDef -ErrorAction Stop

    # Build the reference for the initiative
    $policyRef = @{
        policyDefinitionId = $createdRequire.PolicyDefinitionId
    }
    if ($tag.Validation -eq "AllowedValues") {
        $policyRef["parameters"] = @{
            "allowedEnvironments" = @{
                "value" = "[parameters('allowedEnvironments')]"
            }
        }
    }
    $policyDefinitionIds.Add($policyRef)

    # ── 1b. Inherit tag from resource group (Modify) ──
    $inheritPolicyName = "inherit-tag-from-rg-$($tagName.ToLower())"
    $inheritRule = New-InheritTagPolicyRule -TagName $tagName

    $inheritPolicyDef = @{
        Name            = $inheritPolicyName
        DisplayName     = "Inherit $tagName tag from resource group"
        Description     = "Automatically copies the $tagName tag from the parent resource group if missing or different on the resource."
        Policy          = ($inheritRule | ConvertTo-Json -Depth 20)
        Mode            = "Indexed"
        Metadata        = (@{ category = $policyCategory; version = $policyVersion } | ConvertTo-Json)
    }

    if ($ManagementGroupName) {
        $inheritPolicyDef["ManagementGroupName"] = $ManagementGroupName
    } else {
        $inheritPolicyDef["SubscriptionId"] = $SubscriptionId
    }

    Write-Output "  Creating: Inherit $tagName from resource group..."
    $createdInherit = New-AzPolicyDefinition @inheritPolicyDef -ErrorAction Stop

    $policyDefinitionIds.Add(@{
        policyDefinitionId = $createdInherit.PolicyDefinitionId
    })
    $inheritPolicyIds.Add($createdInherit.PolicyDefinitionId)
}

Write-Output "  ✅ Created $($policyDefinitionIds.Count) policy definitions."
Write-Output ""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: CREATE THE POLICY INITIATIVE (SET DEFINITION)
# ─────────────────────────────────────────────────────────────────────────────

Write-Output "━━━ Step 2: Creating policy initiative ━━━"

# Initiative-level parameters (passed through to child policies)
$initiativeParams = @{
    "allowedEnvironments" = @{
        "type"     = "Array"
        "metadata" = @{
            "displayName" = "Allowed Environment Tag Values"
            "description" = "Permitted values for the Environment tag (case-insensitive)."
        }
        "defaultValue" = $AllowedEnvironments
    }
}

$initiativeDef = @{
    Name             = $initiativeName
    DisplayName      = $InitiativeDisplayName
    Description      = "Enforces mandatory tags ($( ($mandatoryTags.TagName) -join ', ' )) on all resources. Includes deny/audit rules and automatic inheritance from resource groups. Version $policyVersion."
    PolicyDefinition = ($policyDefinitionIds | ConvertTo-Json -Depth 20)
    Parameter        = ($initiativeParams | ConvertTo-Json -Depth 10)
    Metadata         = (@{ category = $policyCategory; version = $policyVersion } | ConvertTo-Json)
}

if ($ManagementGroupName) {
    $initiativeDef["ManagementGroupName"] = $ManagementGroupName
} else {
    $initiativeDef["SubscriptionId"] = $SubscriptionId
}

Write-Output "  Creating initiative: $InitiativeDisplayName..."
$createdInitiative = New-AzPolicySetDefinition @initiativeDef -ErrorAction Stop
Write-Output "  ✅ Initiative created: $($createdInitiative.PolicySetDefinitionId)"
Write-Output ""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: ASSIGN THE INITIATIVE
# ─────────────────────────────────────────────────────────────────────────────

Write-Output "━━━ Step 3: Assigning initiative ━━━"

$assignmentName = "assign-mandatory-tags"

$assignmentParams = @{
    Name                = $assignmentName
    DisplayName         = "$InitiativeDisplayName ($(if ($EnforcementMode -eq 'Audit') {'Audit Only'} else {'Enforced'}))"
    Description         = "Assigned by Deploy-TaggingPolicy.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm') UTC. Mode: $EnforcementMode."
    PolicySetDefinition = $createdInitiative
    Scope               = $scope
    EnforcementMode     = $assignmentEnforcementMode
    Location            = "eastus"  # Required for managed identity (used by Modify remediation)
    IdentityType        = "SystemAssigned"
    PolicyParameterObject = @{
        allowedEnvironments = $AllowedEnvironments
    }
}

Write-Output "  Assigning to scope: $scopeDisplay"
Write-Output "  Enforcement mode:   $assignmentEnforcementMode"
$assignment = New-AzPolicyAssignment @assignmentParams -ErrorAction Stop
Write-Output "  ✅ Assignment created: $($assignment.PolicyAssignmentId)"
Write-Output ""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: GRANT THE ASSIGNMENT'S MANAGED IDENTITY CONTRIBUTOR ROLE
# ─────────────────────────────────────────────────────────────────────────────
# The Modify policies need Contributor to write tags. The assignment creates a
# system-assigned managed identity that needs this role on the target scope.

Write-Output "━━━ Step 4: Granting Contributor role to assignment managed identity ━━━"

$principalId = $assignment.Identity.PrincipalId
if ($principalId) {
    # Small delay to allow AAD replication
    Write-Output "  Waiting 15 seconds for identity propagation..."
    Start-Sleep -Seconds 15

    try {
        $existingRole = Get-AzRoleAssignment -ObjectId $principalId -Scope $scope `
                            -RoleDefinitionName "Contributor" -ErrorAction SilentlyContinue

        if (-not $existingRole) {
            New-AzRoleAssignment -ObjectId $principalId `
                -Scope $scope `
                -RoleDefinitionName "Contributor" `
                -ErrorAction Stop | Out-Null
            Write-Output "  ✅ Contributor role assigned to principal $principalId."
        } else {
            Write-Output "  ✅ Contributor role already exists."
        }
    } catch {
        Write-Output "  ⚠️  Could not assign role: $_"
        Write-Output "  You may need to manually grant Contributor to principal $principalId on scope $scope."
    }
} else {
    Write-Output "  ⚠️  No managed identity principal found on assignment. Modify (inherit) policies won't remediate."
}
Write-Output ""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5: CREATE REMEDIATION TASKS (optional)
# ─────────────────────────────────────────────────────────────────────────────

if ($CreateRemediationTasks) {
    Write-Output "━━━ Step 5: Creating remediation tasks for tag inheritance ━━━"

    foreach ($inheritId in $inheritPolicyIds) {
        $policyName = ($inheritId -split '/')[-1]
        $remediationName = "remediate-$policyName"

        Write-Output "  Creating remediation: $remediationName..."
        try {
            Start-AzPolicyRemediation `
                -Name $remediationName `
                -PolicyAssignmentId $assignment.PolicyAssignmentId `
                -PolicyDefinitionReferenceId $inheritId `
                -Scope $scope `
                -ErrorAction Stop | Out-Null
            Write-Output "  ✅ Remediation task created."
        } catch {
            # PolicyDefinitionReferenceId might need the definition name, not full ID
            Write-Output "  ⚠️  Could not start remediation for $policyName : $_"
            Write-Output "     You can create remediation tasks manually in the Portal → Policy → Remediation."
        }
    }
    Write-Output ""
} else {
    Write-Output "━━━ Step 5: Remediation tasks skipped (set -CreateRemediationTasks `$true to enable) ━━━"
    Write-Output ""
}

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

Write-Output "╔═══════════════════════════════════════════════════════════════════════╗"
Write-Output "║                       DEPLOYMENT COMPLETE                            ║"
Write-Output "╠═══════════════════════════════════════════════════════════════════════╣"
Write-Output "║                                                                      ║"
Write-Output "║  Initiative:    $($initiativeName.PadRight(50))║"
Write-Output "║  Assignment:    $($assignmentName.PadRight(50))║"
Write-Output "║  Scope:         $($scopeDisplay.PadRight(50))║"
Write-Output "║  Enforcement:   $($EnforcementMode.PadRight(50))║"
Write-Output "║                                                                      ║"
Write-Output "║  REQUIRED TAGS                                                       ║"

foreach ($tag in $mandatoryTags) {
    $line = "    • $($tag.TagName.PadRight(16)) ($($tag.Validation))"
    Write-Output "║  $($line.PadRight(66))║"
}

Write-Output "║                                                                      ║"
Write-Output "║  Allowed Environment values:                                         ║"
$envLine = "    $($AllowedEnvironments -join ', ')"
# Wrap long environment lists
if ($envLine.Length -gt 66) {
    $chunks = [System.Collections.Generic.List[string]]::new()
    $current = "    "
    foreach ($env in $AllowedEnvironments) {
        if (($current + $env + ", ").Length -gt 66) {
            $chunks.Add($current.TrimEnd(", "))
            $current = "    $env, "
        } else {
            $current += "$env, "
        }
    }
    $chunks.Add($current.TrimEnd(", "))
    foreach ($chunk in $chunks) {
        Write-Output "║  $($chunk.PadRight(66))║"
    }
} else {
    Write-Output "║  $($envLine.PadRight(66))║"
}

Write-Output "║                                                                      ║"
Write-Output "║  NEXT STEPS                                                          ║"
if ($EnforcementMode -eq "Audit") {
Write-Output "║    1. Wait ~30 min for initial compliance scan                       ║"
Write-Output "║    2. Review: Portal → Policy → Compliance                           ║"
Write-Output "║    3. Remediate existing resources (Portal or -CreateRemediationTasks)║"
Write-Output "║    4. Re-run with -EnforcementMode Deny when ready                   ║"
} else {
Write-Output "║    1. New resources without required tags will be BLOCKED             ║"
Write-Output "║    2. Existing resources are NOT retroactively blocked                ║"
Write-Output "║    3. Run remediation tasks to backfill inherited tags                ║"
Write-Output "║    4. Review: Portal → Policy → Compliance                           ║"
}
Write-Output "║                                                                      ║"
Write-Output "╚═══════════════════════════════════════════════════════════════════════╝"

# ─────────────────────────────────────────────────────────────────────────────
# UNINSTALL HELPER (printed to output for convenience)
# ─────────────────────────────────────────────────────────────────────────────

Write-Output ""
Write-Output "To REMOVE all deployed policies, run:"
Write-Output "─────────────────────────────────────────────────────────────────────────"
Write-Output "  Remove-AzPolicyAssignment -Name '$assignmentName' -Scope '$scope'"
Write-Output "  Remove-AzPolicySetDefinition -Name '$initiativeName' -Force"
foreach ($tag in $mandatoryTags) {
    Write-Output "  Remove-AzPolicyDefinition -Name 'require-tag-$($tag.TagName.ToLower())' -Force"
    Write-Output "  Remove-AzPolicyDefinition -Name 'inherit-tag-from-rg-$($tag.TagName.ToLower())' -Force"
}
Write-Output "─────────────────────────────────────────────────────────────────────────"