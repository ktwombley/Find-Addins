<#
 # Find-Addins
 #
 # Find Office addins installed by your users. It includes COM Addins and VSTO Addins. I hope it includes Web Addins too.
#>


#used internally to attempt to translate SIDs to usernames
function tl($sid) {
    try {
        (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate( [System.Security.Principal.NTAccount]).Value +' (HKU:\'+$sid+')'
    }
    catch {
        '(HKU:\'+$sid+')'
    }
}

# at the end we output the properties in order, so these wind up at the top.
[System.Collections.ArrayList]$props = @('Where','Product','PSPath')
[System.Collections.ArrayList]$outp = @()

$outp = get-childitem -Path 'Microsoft.PowerShell.Core\Registry::HKEY_USERS' -ErrorAction SilentlyContinue | ForEach-Object {
    $_.PSPath+'\Software\Microsoft\Office'; $_.PSPath+'\Software\WOW6432Node\Microsoft\Office'
} |  get-childitem -ErrorAction SilentlyContinue | ForEach-Object {
    $product = $_.PSChildName
    Write-Verbose $product
    get-childitem -Path ($_.PSPath+'\Addins') -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue | 
            Add-Member -MemberType NoteProperty -Name 'Where' -Value (tl($_.PSPath.Split('\')[2])) -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Product' -Value $product -PassThru
    }
} | ForEach-Object {
    foreach ($p in $_.PSObject.Properties.Name) {
        if ($p -notin $props) {
            $props.Add($p) | Out-Null
        } 
    }
    $_
}
        
    
$outp.AddRange((get-childitem -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office' -ErrorAction SilentlyContinue | ForEach-Object {
    $product = $_.PSChildName
    Write-Verbose $product
    get-childitem -Path ($_.PSPath+'\Addins') -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue | 
            Add-Member -MemberType NoteProperty -Name 'Where' -Value 'HKLM:\SOFTWARE' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Product' -Value $product -PassThru
    }
} | ForEach-Object {
    foreach ($p in $_.PSObject.Properties.Name) {
        if ($p -notin $props) {
            $props.Add($p) | Out-Null
        } 
    }
    $_
})) | out-null

$outp.AddRange((get-childitem -Path 'HKLM:\SOFTWARE\Microsoft\Office' -ErrorAction SilentlyContinue |  ForEach-Object {
    $product = $_.PSChildName
    Write-Verbose $product
    get-childitem -Path ($_.PSPath+'\Addins') -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue | 
            Add-Member -MemberType NoteProperty -Name 'Where' -Value 'HKLM:\SOFTWARE' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Product' -Value $product -PassThru
    }
} | ForEach-Object {
    foreach ($p in $_.PSObject.Properties.Name) {
        if ($p -notin $props) {
            $props.Add($p) | Out-Null
        } 
    }
    $_
})) | out-null

# remove this crap
$props.Remove('PSParentPath') | Out-Null
$props.Remove('PSProvider') | Out-Null

$outp | Select-Object -Property $props
