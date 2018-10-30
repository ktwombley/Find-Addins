<#
.Synopsis
   Find Office addins installed by your users. It includes COM Addins, VSTO Addins, and Web Addins.
.DESCRIPTION
   Find-Addins checks the registry and scans user %APPDATA% folders looking for Office Add-Ins.

   Use it to detect unexpected Add-Ins; such as those installed by a malicious user.
.EXAMPLE
   Find-Addins.ps1
.EXAMPLE
   Find-Addins.ps1 -OutPath C:\Temp\addinscan.csv
#>
[CmdletBinding()]
[Alias()]
[OutputType([PSObject])]
Param
(
    # Write results to a CSV file
    [Parameter(Mandatory=$false,
                Position=0)]
    $OutPath
)



#used internally to attempt to translate SIDs to usernames
function tl($sid) {
    try {
        (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate( [System.Security.Principal.NTAccount]).Value +' (HKU:\'+$sid+')'
    }
    catch {
        '(HKU:\'+$sid+')'
    }
}

<#
.Synopsis
   Get-ChildItem skipping reparse points
.DESCRIPTION
   I can't believe I had to write this.
.EXAMPLE
   PS> Get-NoRPChildItem -Path "use this just like get-childitem, except it's not insane."
.EXAMPLE
   Another example of how to use this cmdlet
#>
function Get-NoRPChildItem
{
    [CmdletBinding()]
    Param
    (
        # Param1 help description
        [Parameter()]
        [String]$Attributes,

        # Param1 help description
        [Parameter()]
        [switch]$Directory,

        # Param1 help description
        [Parameter()]
        [switch]$File,
        
        # Param1 help description
        [Parameter()]
        [switch]$Hidden,
        
        # Param1 help description
        [Parameter()]
        [switch]$ReadOnly,
        
        # Param1 help description
        [Parameter()]
        [switch]$System,
        
        # Param1 help description
        [Parameter()]
        [switch]$Force,

        # Param1 help description
        [Parameter()]
        [switch]$UseTransaction,

        # Param1 help description
        [Parameter()]
        [UInt32]$Depth,

        # Param1 help description
        [Parameter()]
        [String[]]$Exclude,
        
        # Param1 help description
        [Parameter()]
        [String]$Filter,
        
        # Param1 help description
        [Parameter()]
        [String[]]$Include,

        # Param1 help description
        [Parameter()]
        [String[]]$LiteralPath,
        
        # Param1 help description
        [Parameter()]
        [switch]$Name,
        
        # Param1 help description
        [Parameter()]
        [String[]]$Path,

        # Param1 help description
        [Parameter()]
        [switch]$Recurse


    )

    Process
    {
        [hashtable]$returnargs = $PSBoundParameters
        $returnargs.Remove('Recurse')
        
        [hashtable]$searchargs = @{}
        if ($Force) {
            $searchargs.Add('Force', $true)
        }
        if ($PSBoundParameters.ContainsKey('Path')) {
            $searchargs.Add('Path', $PSBoundParameters['Path'])
        }
        if ($PSBoundParameters.ContainsKey('LiteralPath')) {
            $searchargs.Add('LiteralPath', $PSBoundParameters['LiteralPath'])
        }
        
        Get-ChildItem @returnargs

        if ($Recurse -and ((-not $PSBoundParameters.ContainsKey('Depth')) -or $Depth -gt 0)) {
            [System.Collections.Stack]$todo = New-Object -TypeName System.Collections.Stack
            Get-ChildItem @searchargs | ?{ $_.PSIsContainer -and $_.Attributes -notlike '*ReparsePoint*' } | select -expand PSPath | ForEach-Object {
                $todo.push($_)
            }

            while ($todo.Count -gt 0) {
                $curr = $todo.pop()
                if ($PSBoundParameters.ContainsKey('Path')) {
                    $searchargs['Path'] = $curr
                    $returnargs['Path'] = $curr
                }
                if ($PSBoundParameters.ContainsKey('LiteralPath')) {
                    $searchargs['LiteralPath'] = $curr
                    $returnargs['LiteralPath'] = $curr
                }

                Get-ChildItem @returnargs

                Get-ChildItem @searchargs | ?{ $_.PSIsContainer -and $_.Attributes -notlike '*ReparsePoint*' } | select -expand PSPath | ForEach-Object {
                    $todo.push($_)
                }

            }

        }

    }
}



# at the end we output the properties in order, so these wind up at the top.
[System.Collections.ArrayList]$props = @('Where','Product','PSPath')

Write-Verbose "Searching HKEY_USERS"
[System.Collections.ArrayList]$outp = get-childitem -Path 'Microsoft.PowerShell.Core\Registry::HKEY_USERS' -ErrorAction SilentlyContinue | ForEach-Object {
    $_.PSPath+'\Software\Microsoft\Office'; $_.PSPath+'\Software\WOW6432Node\Microsoft\Office'
} |  get-childitem -ErrorAction SilentlyContinue | ForEach-Object {
    $product = $_.PSChildName
    get-childitem -Path ($_.PSPath+'\Addins') -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue | 
            Add-Member -MemberType NoteProperty -Name 'Where' -Value (tl($_.PSPath.Split('\')[2])) -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Product' -Value $product -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AddinType' -Value 'COM/VSTO' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Id' -Value $_.PSChildName -PassThru

    }
} | ForEach-Object {
    foreach ($p in $_.PSObject.Properties.Name) {
        if ($p -notin $props) {
            $props.Add($p) | Out-Null
        } 
    }
    $_
}  

Write-Verbose "Searching HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office"
$morestuff = get-childitem -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office' -ErrorAction SilentlyContinue | ForEach-Object {
    $product = $_.PSChildName
    get-childitem -Path ($_.PSPath+'\Addins') -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue | 
            Add-Member -MemberType NoteProperty -Name 'Where' -Value 'HKLM:\SOFTWARE' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Product' -Value $product -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AddinType' -Value 'COM/VSTO' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Id' -Value $_.PSChildName -PassThru
    }
} | ForEach-Object {
    foreach ($p in $_.PSObject.Properties.Name) {
        if ($p -notin $props) {
            $props.Add($p) | Out-Null
        } 
    }
    $_
}
if($morestuff) {
    $outp.AddRange(@($morestuff)) | out-null
}

Write-Verbose "Searching HKLM:\SOFTWARE\Microsoft\Office"
$morestuff = get-childitem -Path 'HKLM:\SOFTWARE\Microsoft\Office' -ErrorAction SilentlyContinue |  ForEach-Object {
    $product = $_.PSChildName
    get-childitem -Path ($_.PSPath+'\Addins') -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue | 
            Add-Member -MemberType NoteProperty -Name 'Where' -Value 'HKLM:\SOFTWARE' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Product' -Value $product -PassThru |
            Add-Member -MemberType NoteProperty -Name 'AddinType' -Value 'COM/VSTO' -PassThru |
            Add-Member -MemberType NoteProperty -Name 'Id' -Value $_.PSChildName -PassThru 
    }
} | ForEach-Object {
    foreach ($p in $_.PSObject.Properties.Name) {
        if ($p -notin $props) {
            $props.Add($p) | Out-Null
        } 
    }
    $_
}
if($morestuff) {
    $outp.AddRange(@($morestuff)) | out-null
}

Write-Verbose "Searching Filesystem"
$morestuff = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object {
    $p = $_
    $u = tl($p.PSChildName)
    
    $profpath = $p | Get-ItemPropertyValue -Name ProfileImagePath
    $profpath = Join-Path -Path $profpath -ChildPath "AppData"

    Write-Verbose "  Searching files for user $($u)"
    Get-NoRPChildItem -path ($profpath) -Recurse -ErrorAction SilentlyContinue | Where-Object -Property FullName -Like "*\Microsoft\Office\*\Manifests\*" | ForEach-Object {
        Write-Verbose "    Parsing manifest file $($_.FullName)"
        [xml]$x = Get-Content $_.FullName -ErrorAction SilentlyContinue
        if ($x) {
            $urls = Select-Xml -Xml $x -XPath ".//@*" | ForEach-Object {$_.Node} | Where-Object -Property Value -like "http*" | Select-Object -ExpandProperty '#text'
            New-Object PSObject -Property @{
                    Id=$x.OfficeApp.Id;
                    PSPath=$_.FullName;
                    Version=$x.OfficeApp.Version;
                    ProviderName=$x.OfficeApp.ProviderName;
                    FriendlyName=$x.OfficeApp.DisplayName.DefaultValue;
                    Description=$x.OfficeApp.Description.DefaultValue;
                    Permissions=($x.OfficeApp.Permissions -join " ");
                    Where=$u;
                    Product=$x.OfficeApp.type;
                    URLs=($urls -join " ");
                    AddinType='Web'
            }
        }
    }

}| ForEach-Object {
    foreach ($p in $_.PSObject.Properties.Name) {
        if ($p -notin $props) {
            $props.Add($p) | Out-Null
        } 
    }
    $_
}
if($morestuff) {
    $outp.AddRange(@($morestuff)) | out-null
}


# remove this crap
$props.Remove('PSParentPath') | Out-Null
$props.Remove('PSProvider') | Out-Null
$props.Remove('PSChildName') | Out-Null

if ($OutPath) {
    $outp | Select-Object -Property $props | Export-Csv -Path $OutPath -NoTypeInformation
} else {
    $outp | Select-Object -Property $props
}
