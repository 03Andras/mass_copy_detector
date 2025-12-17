
<#
Mass Copy Detector by NA
https://github.com/03Andras/mass_copy_detector

POPIS:
  Monitoruje veľké dátové prenosy na sieťových diskoch pomocou Audit 4663 alebo LastAccess.
  Zhromažďuje informácie o súboroch modifikovaných v časovom okne a posiela údaje na API.

POUŽITIE:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\masscopy.ps1 -Minuty 10 -PrahMB 100 -ApiToken "<TOKEN>"

PARAMETRE:
  -Minuty         Časové okno v minútach (predvolené: 5)
  -PrahMB         Prah v MB (predvolené: 100)
  -ApiUrl         URL API (napr: https://CONFIGURE-YOUR-SERVER-URL/masscopy/)
  -ApiToken       Bezpečnostný token (predvolené: Heslo)
#>

# =============================================================================
# KONFIGURÁCIA - PARAMETRE
# =============================================================================
[CmdletBinding()]
param(
    [int]$Minuty        = 5,
    [int]$PrahMB        = 100,
    [string]$ApiUrl     = 'https://CONFIGURE-YOUR-SERVER-URL/masscopy/',
    [string]$ApiToken   = 'Heslo',
    [switch]$PreskocAudit,
    [switch]$Restartovany
)

# =============================================================================
# POMOCNÉ FUNKCIE
# =============================================================================

# Kontrola admin práv
$jeAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Kontrola, či je nastavená API URL
if ($ApiUrl -like '*CONFIGURE-YOUR-SERVER-URL*') {
    Write-Warning "API URL nie je nakonfigurovaná! Upravte parameter -ApiUrl alebo nastavte predvolenú hodnotu v skripte."
    Write-Warning "Skript pokračuje, ale odosielanie dát na API zlyhá."
}

# =============================================================================
# SAMOINSTALACIA DO C:\masscopy A TASK SCHEDULER
# =============================================================================
$cielovaCesta = 'C:\masscopy'
$cielovyScript = Join-Path $cielovaCesta 'masscopy.ps1'
$aktualnyScript = $PSCommandPath

# Kontrola, či skript už beží z cieľového umiestnenia
$bezieZCielovejCesty = $aktualnyScript -and ($aktualnyScript -like "$cielovaCesta\*")

if ($jeAdmin -and -not $bezieZCielovejCesty) {
    # Vytvor cieľový priečinok, ak neexistuje
    if (-not (Test-Path $cielovaCesta)) {
        try {
            New-Item -ItemType Directory -Path $cielovaCesta -Force | Out-Null
        } catch {
            Write-Warning "Nemožno vytvoriť priečinok $cielovaCesta"
        }
    }
    
    # Skopíruj skript do cieľovej lokácie
    if (Test-Path $cielovaCesta) {
        # Kontrola, či cieľový skript už existuje
        $shouldCopy = $true
        if (Test-Path $cielovyScript) {
            # Ak už existuje, skontroluj či je iný
            try {
                $aktualnyHash = (Get-FileHash -Path $aktualnyScript -Algorithm SHA256).Hash
                $cielovyHash = (Get-FileHash -Path $cielovyScript -Algorithm SHA256).Hash
                $shouldCopy = ($aktualnyHash -ne $cielovyHash)
            } catch {
                # Ak zlyháva hash, skopíruj tak či tak
                $shouldCopy = $true
            }
        }
        
        if ($shouldCopy) {
            try {
                Copy-Item -Path $aktualnyScript -Destination $cielovyScript -Force
            } catch {
                Write-Warning "Nemožno skopírovať skript do $cielovaCesta"
            }
        }
    }
    
    # Nastav Task Scheduler na spustenie každých 5 minút
    $taskName = 'MassCopyDetector'
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    
    if (-not $existingTask) {
        try {
            $action = New-ScheduledTaskAction -Execute "powershell.exe" `
                -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$cielovyScript`" -Minuty $Minuty -PrahMB $PrahMB -ApiUrl `"$ApiUrl`" -ApiToken `"$ApiToken`""
            
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue)
            
            $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -RestartCount 3 `
                -RestartInterval (New-TimeSpan -Minutes 1)
            
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
                -Principal $principal -Settings $settings -Description "Mass Copy Detector by NA - Monitors large data transfers" | Out-Null
            
        } catch {
            Write-Warning "Nemožno vytvoriť naplánovanú úlohu: $_"
        }
    }
}

function Quote-Arg([string]$s) { '"' + $s.Replace('"','""') + '"' }

function Get-PrihlasenyPouzivatel {
    try {
        $session = (Get-CimInstance Win32_ComputerSystem).UserName
        if ($session -match '\\') {
            return $session.Split('\')[1]
        }
        return $session
    } catch {
        return $env:USERNAME
    }
}

# =============================================================================
# REŠTART POD KONTEXTOM POUŽÍVATEĽA (AK JE SPUSTENÝ AKO ADMIN)
# =============================================================================
if ($jeAdmin -and -not $Restartovany) {
    try {
        $pouzivatel = Get-PrihlasenyPouzivatel
        
        $args = @()
        foreach ($k in $PSBoundParameters.Keys) {
            if ($k -eq 'Restartovany') { continue }
            $v = $PSBoundParameters[$k]
            if ($v -is [switch]) {
                if ($v.IsPresent) { $args += "-$k" }
            } else {
                $args += "-$k " + (Quote-Arg $v)
            }
        }
        $args += '-Restartovany'
        $argStr = $args -join ' '
        
        $taskName = "MassCopy_" + (Get-Random)
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" $argStr"
        $principal = New-ScheduledTaskPrincipal -UserId $pouzivatel -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        Start-Sleep -Seconds 2
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        exit
    } catch {
        exit
    }
}

# =============================================================================
# NASTAVENIE AUDIT POLITIKY
# =============================================================================
function Enable-AuditSubcategories {
    param([switch]$Preskoc)
    if ($Preskoc -or -not $jeAdmin) { return }
    $guids = @('{0cce923f-69ae-11d9-bed3-505054503030}','{0cce9225-69ae-11d9-bed3-505054503030}')
    foreach ($g in $guids) {
        try { & auditpol.exe /set /subcategory:"$g" /success:enable | Out-Null } catch { }
    }
}

Enable-AuditSubcategories -Preskoc:$PreskocAudit

# =============================================================================
# ZISKANIE SIEŤOVÝCH DISKOV
# =============================================================================
function Get-SietoveDisk {
    $zoznam = @()

    # 1) COM: WScript.Network
    try {
        $nw = New-Object -ComObject WScript.Network
        $arr = @($nw.EnumNetworkDrives())
        for ($i = 0; $i -lt $arr.Count; $i += 2) {
            $pismeno = $arr[$i]
            $cesta   = $arr[$i + 1]
            if ($pismeno -match '^[A-Z]:$') {
                $zoznam += [PSCustomObject]@{ DeviceID = $pismeno; ProviderName = $cesta }
            }
        }
    } catch { }

    # 2) CIM fallback (DriveType=4)
    try {
        $zoznam += Get-CimInstance Win32_LogicalDisk -Filter "DriveType=4" |
            Where-Object { $_.DeviceID -match '^[A-Z]:$' } |
            Select-Object DeviceID, ProviderName
    } catch { }

    # 3) HKU registry
    try {
        Get-ChildItem -Path Registry::HKEY_USERS -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'S-1-5-21-' } |
            ForEach-Object {
                $sid = $_.PSChildName
                $netKey = "Registry::HKEY_USERS\\$sid\\Network"
                if (Test-Path $netKey) {
                    Get-ChildItem -Path $netKey -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            $pismeno = $_.PSChildName + ':'
                            $vzdialeny = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).RemotePath
                            if ($pismeno -match '^[A-Z]:$' -and $vzdialeny) {
                                $zoznam += [PSCustomObject]@{ DeviceID = $pismeno; ProviderName = $vzdialeny; SID = $sid }
                            }
                        }
                }
            }
    } catch { }

    # 4) PSDrive
    try {
        $zoznam += Get-PSDrive -PSProvider FileSystem |
            Where-Object { $_.DisplayRoot -and ($_.Name -match '^[A-Z]$') } |
            Select-Object @{n='DeviceID';e={"$($_.Name):"}}, @{n='ProviderName';e={$_.DisplayRoot}}
    } catch { }

    # Dedup
    $zoznam = $zoznam |
        Group-Object DeviceID |
        ForEach-Object { $_.Group | Select-Object -First 1 }

    return $zoznam
}

$sietoveDisk = Get-SietoveDisk
if (-not $sietoveDisk) { exit 0 }

$pismenaDiskov = $sietoveDisk.DeviceID
$casovyLimit = (Get-Date).AddMinutes(-$Minuty)

# =============================================================================
# ZBER DAT Z AUDIT LOGU A FALLBACK
# =============================================================================

function Get-VelkostMBBezpecne {
    param([string]$Cesta)
    try {
        $polozka = Get-Item -LiteralPath $Cesta -ErrorAction Stop
        return [Math]::Round(($polozka.Length / 1MB), 4)
    } catch {
        return 0
    }
}

function Get-Audit4663PodlaDiska {
    $data = @()
    try {
        $udalosti = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4663; StartTime=$casovyLimit } -ErrorAction Stop
        foreach ($e in $udalosti) {
            $xml = [xml]$e.ToXml()
            $nazovObj    = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ObjectName' }  | Select-Object -ExpandProperty '#text'
            $typObj      = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ObjectType' }  | Select-Object -ExpandProperty '#text'
            $pristupMask = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'AccessMask' }  | Select-Object -ExpandProperty '#text'
            $idProcesu   = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessId' }   | Select-Object -ExpandProperty '#text'
            $nazovProc   = $xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ProcessName' } | Select-Object -ExpandProperty '#text'

            if ($typObj -ne 'File') { continue }
            if (-not $nazovObj) { continue }

            $disk = $pismenaDiskov | Where-Object { $nazovObj.StartsWith($_) } | Select-Object -First 1
            if ($null -eq $disk) { continue }

            $data += [PSCustomObject]@{
                Drive      = $disk
                ObjectName = $nazovObj
                AccessMask = $pristupMask
                ProcessId  = $idProcesu
                Process    = $nazovProc
                SizeMB     = Get-VelkostMBBezpecne -Cesta $nazovObj
            }
        }
    } catch { }

    # Dedup
    $unique = $data | Group-Object Drive, ObjectName | ForEach-Object {
        $d = $_.Group | Sort-Object SizeMB -Descending | Select-Object -First 1
        [PSCustomObject]@{
            Drive      = $d.Drive
            ObjectName = $d.ObjectName
            SizeMB     = $d.SizeMB
        }
    }
    return $unique
}

function Get-FallbackPristupPodlaDiska {
    $riadky = @()
    foreach ($d in $sietoveDisk) {
        $koren = "$($d.DeviceID)\"
        try {
            Get-ChildItem -LiteralPath $koren -File -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { ($_.LastAccessTime -ge $casovyLimit) -or ($_.LastWriteTime -ge $casovyLimit) } |
                ForEach-Object {
                    $riadky += [PSCustomObject]@{
                        Drive      = $d.DeviceID
                        ObjectName = $_.FullName
                        SizeMB     = [Math]::Round(($_.Length / 1MB), 4)
                    }
                }
        } catch { }
    }
    return $riadky
}

# =============================================================================
# SPRACOVANIE A ODOSLANIE DAT NA API
# =============================================================================

$riadky4663 = Get-Audit4663PodlaDiska
$pouziZalohu = ($riadky4663.Count -eq 0)
$riadky = if ($pouziZalohu) { Get-FallbackPristupPodlaDiska } else { $riadky4663 }

$suhrn = $riadky | Group-Object Drive | ForEach-Object {
    $suma = ($_.Group | Measure-Object -Property SizeMB -Sum).Sum
    $subory = $_.Group | Select-Object ObjectName, SizeMB | Sort-Object SizeMB -Descending
    [PSCustomObject]@{
        Drive    = $_.Name
        Files    = $_.Count
        TotalMB  = [Math]::Round($suma, 2)
        FileList = $subory
    }
}

$prekrocene = $suhrn | Where-Object { $_.TotalMB -ge $PrahMB } | Select-Object -ExpandProperty Drive
$pouzitaMetoda = if ($pouziZalohu) { 'fallback_lastaccess' } else { 'audit_4663' }

# Zisti stav inštalácie a Task Schedulera
$taskStatus = 'not_configured'
$installedPath = 'unknown'
try {
    $task = Get-ScheduledTask -TaskName 'MassCopyDetector' -ErrorAction SilentlyContinue
    if ($task) {
        $taskStatus = $task.State.ToString().ToLower()
    }
} catch { }

if ($aktualnyScript) {
    $installedPath = $aktualnyScript
}

$payload = [ordered]@{
    machine           = $env:COMPUTERNAME
    user              = $env:USERNAME
    timestamp         = (Get-Date).ToString('o')
    timeWindowMinutes = $Minuty
    thresholdMB       = $PrahMB
    method            = $pouzitaMetoda
    drives            = $suhrn
    exceeded          = @($prekrocene)
    alert             = ($prekrocene.Count -gt 0)
    installedPath     = $installedPath
    taskSchedulerStatus = $taskStatus
    runningAsAdmin    = $jeAdmin
}

try {
    $json    = $payload | ConvertTo-Json -Depth 8
    $headers = @{ 'Content-Type' = 'application/json'; 'X-Api-Token' = $ApiToken }
    $resp = Invoke-RestMethod -Method POST -Uri $ApiUrl -Headers $headers -Body $json -TimeoutSec 30
} catch { }
