<#
.SYNOPSIS
    Print what an MSI will actually do to a machine.

.DESCRIPTION
    Reads the package's own tables rather than trusting the .wxs that produced
    it. The point of the exercise is to catch the gap between what the source
    says and what got built - a registry key that silently did not make it into
    the package looks identical, from the source, to one that did.

    Reads only. Nothing here installs anything.

.EXAMPLE
    pwsh installer/inspect.ps1 installer/out/Redoubt-0.1.0-x64.msi
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

$ErrorActionPreference = 'Stop'
$full = (Resolve-Path $Path).Path

$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($full, 0))

function Invoke-MsiQuery {
    param([string]$Sql, [int]$Columns)

    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @($Sql))
    $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
    while ($true) {
        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        if (-not $record) { break }
        $fields = for ($c = 1; $c -le $Columns; $c++) {
            $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @($c))
        }
        '    ' + ($fields -join '  |  ')
    }
}

# MSI SQL reserves a lot of ordinary words - Key and Name among them - so every
# identifier is quoted with backticks.
$sections = [ordered]@{
    'Identity' = @('SELECT `Property`, `Value` FROM `Property` WHERE `Property` = ''ProductName'' OR `Property` = ''ProductVersion'' OR `Property` = ''Manufacturer'' OR `Property` = ''UpgradeCode''', 2)
    'Files installed' = @('SELECT `FileName`, `FileSize` FROM `File`', 2)
    'Service' = @('SELECT `Name`, `DisplayName`, `StartType`, `Arguments` FROM `ServiceInstall`', 4)
    'Service control' = @('SELECT `Name`, `Event` FROM `ServiceControl`', 2)
    'Registry' = @('SELECT `Root`, `Key`, `Name`, `Value` FROM `Registry`', 4)
    'Shortcuts' = @('SELECT `Name`, `Target`, `Arguments` FROM `Shortcut`', 3)
}

foreach ($name in $sections.Keys) {
    Write-Output "$name :"
    $sql, $cols = $sections[$name]
    try {
        $rows = Invoke-MsiQuery -Sql $sql -Columns $cols
        if ($rows) { $rows } else { '    (none)' }
    } catch {
        Write-Output "    (table absent or unreadable: $($_.Exception.Message))"
    }
    Write-Output ''
}
