[OutputType([string])]
param ([Parameter(Mandatory=$true)]
        [string]$credentialName)

$guestSKU = 'Guest'
$guestQualifyingSKUs = @('AAD_PREMIUM',
                        'AAD_PREMIUM_P2')
$skuTranslate = @{'AAD_PREMIUM' = 'AzureActvDrctryPremP1';
                    'AAD_PREMIUM_P2' = 'AzureActvDrctryPremP2';
                    'ADALLOM_STANDALONE' = 'CloudAppSec';
                    'ATA' = 'AzureATPforUsrs';
                    'DESKLESSPACK' = 'O365F3';
                    'EMS' = 'EntMobandSecE3Full';
                    'ENTERPRISEPACK' = 'O365E3';
                    'ENTERPRISEPREMIUM' = 'O365E5';
                    'EQUIVIO_ANALYTICS' = 'Office 365 Advanced Compliance';
                    'IDENTITY_THREAT_PROTECTION' = 'M365E5Security';
                    'INFOPROTECTION_P2' = 'AzureInfoProtPremP2';
                    'INFORMATION_PROTECTION_COMPLIANCE' = 'M365E5Compliance';
                    'INTUNE_A_D' = 'Intune Device';
                    'INTUNE_A_VL' = 'IntunUSL';
                    'MCOEV' = 'Phone Sys';
                    'MCOMEETADV' = 'Audio Conf';
                    'POWER_BI_PRO' = 'PwrBIPro';
                    'PROJECTPREMIUM' = 'ProjectPlan5';
                    'PROJECTPROFESSIONAL' = 'ProjectPlan3';
                    'RIGHTSMANAGEMENT' = 'AzureInfoProtPremP1';
                    'SPE_E3' = 'M365E3';
                    'STANDARDPACK' = 'O365E1';
                    'THREAT_INTELLIGENCE' = 'O365AdvThrtPrtctnPln2';
                    'VISIOCLIENT' = 'VisioPlan2';
                    'VISIOONLINE_PLAN1' = 'VisioPlan1'}
$knownIssuers = @{}
$preferredKey = 'extension'
$extensionProperty = ''

Connect-AzureAD -Credential (Get-AutomationPSCredential -Name $credentialName) | Out-Null
Connect-MsolService -Credential (Get-AutomationPSCredential -Name $credentialName) | Out-Null

#region: Input
$sortedSKUs = Get-AzureADSubscribedSku | Sort-Object -Property SkuPartNumber
$sortedSubscriptions = Get-MsolSubscription | Sort-Object -Property SkuPartNumber
$users = Get-AzureADUser -All $true | Select-Object ObjectId,AccountEnabled,AssignedLicenses,CompanyName,DisplayName,ExtensionProperty,GivenName,Surname,UsageLocation,UserPrincipalName,UserType
$licenses = @{}
foreach ($user in $users | Where-Object{$_.AssignedLicenses.Count -gt 0})
{
    if ($null -ne ($license = Get-AzureADUserLicenseDetail -ObjectId $user.ObjectId))
    {
        if ($null -eq ($company = $user.CompanyName))
        {
            $company = ''
        }
        if ($null -eq ($extension = $user.ExtensionProperty[$extensionProperty]))
        {
            $extension = ''
        }
        if ($null -eq ($location = $user.UsageLocation))
        {
            $location = ''
        }
        switch ([string]$preferredKey)
        {
            'company'
            {
                $key = $company
            }
            'extension'
            {
                $key = $extension
            }
            'location'
            {
                $key = $location
            }
            default
            {
                $key = "$location-$extension-$company"
            }
        }
        if ($key -eq '')
        {
            $key = "Domain: $($user.UserPrincipalName.Split('@') | Select-Object -Last 1)"
        }
        if (-not $licenses.ContainsKey($key))
        {
            $licenses.Add($key, @{})
        }
        foreach ($SKU in $license.SkuPartNumber)
        {
            if (-not $licenses[$key].ContainsKey($SKU))
            {
                $licenses[$key].Add($SKU, 0)
            }
            $licenses[$key][$SKU]++
        }
        $licenses[$key].Add("$($user.UserPrincipalName);$($user.GivenName);$($user.Surname);$($user.DisplayName);$($user.AccountEnabled)", $license.SkuPartNumber)
    }
}
foreach ($user in $users | Where-Object{$_.UserType -eq 'Guest'})
{
    if ($null -eq ($company = $user.CompanyName))
    {
        $company = ''
    }
    if ($null -ne ($manager = (Get-AzureADUserManager -ObjectId $user.ObjectId)))
    {
        if ($null -eq ($extension = $manager.ExtensionProperty[$extensionProperty]))
        {
            $extension = ''
        }
    }
    else
    {
        $extension = ''
    }
    if ($null -eq ($location = $user.UsageLocation))
    {
        $location = ''
    }
    switch ([string]$preferredKey)
    {
        'company'
        {
            $key = $company
        }
        'extension'
        {
            $key = $extension
        }
        'location'
        {
            $key = $location
        }
        default
        {
            $key = "$location-$extension-$company"
        }
    }
    if ($key -eq '')
    {
        $key = "Domain: $($user.UserPrincipalName.Split('@') | Select-Object -Last 1)"
    }
    if (-not $licenses.ContainsKey($key))
    {
        $licenses.Add($key, @{})
    }
    if (-not $licenses[$key].ContainsKey($guestSKU))
    {
        $licenses[$key].Add($guestSKU, 0)
    }
    $licenses[$key][$guestSKU]++
}
#endregion

#region: Output enabled licenses
Get-Item -Path $resultsFolder -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path $resultsFolder -ItemType Directory -Force | Out-Null
$outputCommon = [System.Text.StringBuilder]::new()
# Headers
$outputCommon.Append("Name;Type;$guestSKU") | Out-Null
foreach ($SKU in $sortedSKUs.SkuPartNumber)
{
    if ($skuTranslate.ContainsKey($SKU))
    {
        $outputCommon.Append(";$($skuTranslate[$SKU])") | Out-Null
    }
    else
    {
        $outputCommon.Append(";$SKU") | Out-Null
    }
}
$outputCommon.AppendLine() | Out-Null
$outputCommon.AppendLine("Total;Enabled;$((($guestQualifyingSKUs | ForEach-Object{$guestQualifyingSKU = $_; Get-AzureADSubscribedSku | Where-Object{$_.ServicePlans.ServicePlanName -contains $guestQualifyingSKU}} | Select-Object -Unique).PrepaidUnits.Enabled | Measure-Object -Sum).Sum * 5);$($sortedSKUs.PrepaidUnits.Enabled -join ';')") | Out-Null
# non-Microsoft licenses
foreach ($subscriptionIssuer in ($sortedSubscriptions | Where-Object{$_.OwnerObjectId -ne $null -and $_.Status -eq 'Enabled'} | Select-Object -Property OwnerObjectId -Unique).OwnerObjectId)
{
    if ($knownIssuers.ContainsKey($subscriptionIssuer.ToString()))
    {
        $outputCommon.Append($knownIssuers[$subscriptionIssuer.ToString()]) | Out-Null
    }
    else
    {
        $outputCommon.Append("$subscriptionIssuer (Unknown)") | Out-Null
    }
    $outputCommon.Append(';Enabled;') | Out-Null
    foreach ($SKU in $sortedSKUs.SkuPartNumber)
    {
        $outputCommon.Append(";$(($sortedSubscriptions | Where-Object{$_.SkuPartNumber -eq $SKU -and $_.OwnerObjectId -eq $subscriptionIssuer -and $_.Status -eq 'Enabled'} | Measure-Object TotalLicenses -Sum).Sum)") | Out-Null
    }
    $outputCommon.AppendLine() | Out-Null
}
# paid Microsoft licenses
$outputCommon.Append("Microsoft (Paid);Enabled;") | Out-Null
foreach ($SKU in $sortedSKUs.SkuPartNumber)
{
    $outputCommon.Append(";$(($sortedSubscriptions | Where-Object{$_.SkuPartNumber -eq $SKU -and $_.OwnerObjectId -eq $null -and $_.NextLifecycleDate -ne $null -and $_.Status -eq 'Enabled'} | Measure-Object TotalLicenses -Sum).Sum)") | Out-Null
}
$outputCommon.AppendLine() | Out-Null
# free Microsoft licenses
$outputCommon.Append("Microsoft (Free);Enabled;") | Out-Null
foreach ($SKU in $sortedSKUs.SkuPartNumber)
{
    $outputCommon.Append(";$(($sortedSubscriptions | Where-Object{$_.SkuPartNumber -eq $SKU -and $_.OwnerObjectId -eq $null -and $_.NextLifecycleDate -eq $null -and $_.Status -eq 'Enabled'} | Measure-Object TotalLicenses -Sum).Sum)") | Out-Null
}
$outputCommon.AppendLine() | Out-Null
#endregion

#region: Output consumed licenses
$outputCommon.AppendLine("Total;Consumed;$(($licenses.Keys | ForEach-Object{$licenses[$_][$guestSKU]} | Measure-Object -Sum).Sum);$($sortedSKUs.ConsumedUnits -join ';')") | Out-Null
foreach ($key in $licenses.Keys | Sort-Object)
{
    $outputCommon.Append("$key;Consumed") | Out-Null
    $outputCommon.Append(";$($licenses[$key][$guestSKU])") | Out-Null
    foreach ($SKU in $sortedSKUs.SkuPartNumber)
    {
        $outputCommon.Append(";$($licenses[$key][$SKU])") | Out-Null
    }
    $outputCommon.AppendLine() | Out-Null
    
    $outputSpecific = [System.Text.StringBuilder]::new()
    $outputSpecific.Append('UserPrincipalName;FirstName;LastName;DisplayName;AccountEnabled') | Out-Null
    foreach ($SKU in $sortedSKUs.SkuPartNumber)
    {
        if ($skuTranslate.ContainsKey($SKU))
        {
            $outputSpecific.Append(";$($skuTranslate[$SKU])") | Out-Null
        }
        else
        {
            $outputSpecific.Append(";$SKU") | Out-Null
        }
    }
    $outputSpecific.AppendLine() | Out-Null
    foreach ($user in (Compare-Object @($licenses[$key].Keys) $sortedSKUs.SkuPartNumber | Where-Object{$_.SideIndicator -eq '<='}).InputObject)
    {
        $outputSpecific.Append($user) | Out-Null
        foreach ($SKU in $sortedSKUs.SkuPartNumber)
        {
            if($licenses[$key][$user] -contains $SKU)
            {
                $outputSpecific.Append(';x') | Out-Null
            }
            else
            {
                $outputSpecific.Append(';') | Out-Null
            }
        }
        $outputSpecific.AppendLine() | Out-Null
    }
    $key | Write-Output
    '<content separator>' | Write-Output
    $outputSpecific.ToString() | Write-Output
    '<file separator>' | Write-Output
}
'Overview' | Write-Output
'<content separator>' | Write-Output
$outputCommon.ToString() | Write-Output
#endregion
