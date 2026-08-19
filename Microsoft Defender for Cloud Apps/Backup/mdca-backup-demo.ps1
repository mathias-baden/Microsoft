function Connect-ToDestination {
    param (
        [string]$AppId,
        [string]$ClientSecretValue,
        [string]$TenantId,
        [string]$SubscriptionId
    )

    try {
        Write-Host "##[section] Connecting to the Destination..."
        $secureClientSecretValuePwd = $ClientSecretValue | ConvertTo-SecureString -AsPlainText -Force
        $psCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AppId, $secureClientSecretValuePwd
        Connect-AzAccount -ServicePrincipal -Credential $psCredential -Tenant $TenantId

        Set-AzContext -SubscriptionId $SubscriptionId
    } catch {
        throw "Error connecting to Destination: $_"
    }
}

function Get-AllPolicies {
    param (
        [string]$Token
    )

    $headers = @{
        "Authorization" = "Token $Token"
    }

    $allPolicies = @()
    try {
        Write-Host "##[section] Getting all policies..."
        $url = "https://yourtenant.portal.cloudappsecurity.com/cas/api/v1/policies/"

        While ($null -ne $url) {
            $data = Invoke-RestMethod -Headers $headers -Uri $url -Method Get
            $allPolicies += $data.data
            $url = $data.'@Odata.NextLink'
        }
    } catch {
        throw "Error getting policies: $_"
    }
    return $allPolicies
}

function Save-PolicyToFile {
    param (
        [PSCustomObject]$Policy
    )

    $policyName = $Policy.name
    if ($policyName.Length -gt 250) {
        $policyName = $policyName.Substring(0, 250)
    }

    $policy | ConvertTo-Json | Out-File "$env:temp\$policyName.json"
    return "$env:temp\$policyName.json"
}

Connect-ToDestination -AppId "YOUR APP ID" -ClientSecretValue "YOUR APP CLIENT SECRET" -TenantId "YOUR TENANT ID" -SubscriptionId "YOUR SUBSCRIPTION ID"

try {
    $azStorageAccount = Get-AzStorageAccount -Name "YOUR STORAGE ACCOUNT" -ResourceGroupName "YOUR RESSOURCE GROUP"
    $azStorageAccountContext = $azStorageAccount.Context
} catch {
    throw "Error connection to Destination Storage Account: $_"
}

$policies = Get-AllPolicies -Token "YOUR MDCA API TOKEN"
foreach ($policy in $policies) {
    $filePath = Save-PolicyToFile -Policy $policy
    Set-AzStorageBlobContent -File $filePath -Container "YOUR CONTAINER" -Blob "Policies\$($policy.name).json" -Context $azStorageAccountContext -Force
}
