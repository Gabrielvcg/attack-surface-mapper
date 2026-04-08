[CmdletBinding()]
param(
    [string[]]$Labs = @('juice-shop', 'dvwa'),
    [string[]]$Profiles = @('passive-stealth', 'passive-recon-safe'),
    [switch]$IncludeEnum,
    [switch]$KeepLabsRunning
)

$ErrorActionPreference = 'Stop'

$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$scannerImage = 'python:3.11-slim'

if ($IncludeEnum -and ($Profiles -notcontains 'passive-recon-enum')) {
    $Profiles += 'passive-recon-enum'
}

$labDefinitions = @{
    'juice-shop' = @{
        Container = 'asm-lab-juice'
        Image = 'bkimminich/juice-shop'
        HostPort = 3000
        ContainerPort = 3000
        Target = 'http://host.docker.internal:3000'
        HealthUrl = 'http://localhost:3000'
    }
    'dvwa' = @{
        Container = 'asm-lab-dvwa'
        Image = 'vulnerables/web-dvwa'
        HostPort = 8080
        ContainerPort = 80
        Target = 'http://host.docker.internal:8080'
        HealthUrl = 'http://localhost:8080'
    }
}

function Invoke-Docker {
    param([string[]]$Arguments)
    Write-Host "docker $($Arguments -join ' ')" -ForegroundColor DarkGray
    & docker @Arguments
}

function Stop-LabContainer {
    param([string]$Name)
    try {
        $existing = & docker ps -aq --filter "name=^${Name}$"
        if ($existing) {
            & docker rm -f $Name | Out-Null
        }
    } catch {
        Write-Warning "No se pudo limpiar el contenedor ${Name}: $($_.Exception.Message)"
    }
}

function Wait-HttpReady {
    param(
        [string]$Url,
        [string]$Name,
        [int]$TimeoutSeconds = 180
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -TimeoutSec 5 -UseBasicParsing
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                Write-Host "$Name listo en $Url (status $($response.StatusCode))" -ForegroundColor Green
                return
            }
        } catch {
            Start-Sleep -Seconds 2
            continue
        }
        Start-Sleep -Seconds 2
    }

    throw "Timeout esperando a que $Name estuviera listo en $Url"
}

function Start-Lab {
    param([string]$LabName)

    if (-not $labDefinitions.ContainsKey($LabName)) {
        throw "Lab no soportado: $LabName"
    }

    $lab = $labDefinitions[$LabName]
    Stop-LabContainer -Name $lab.Container
    Invoke-Docker -Arguments @(
        'run', '-d', '--rm',
        '--name', $lab.Container,
        '-p', "$($lab.HostPort):$($lab.ContainerPort)",
        $lab.Image
    ) | Out-Null
    Wait-HttpReady -Url $lab.HealthUrl -Name $LabName
    return $lab
}

function Invoke-Scan {
    param(
        [string]$Target,
        [string]$Profile,
        [string]$RunName
    )

    $innerCommand = "pip install -q -r requirements.txt && python main.py --profile $Profile --run-name $RunName $Target"
    Invoke-Docker -Arguments @(
        'run', '--rm',
        '-v', "${workspace}:/workspace",
        '-w', '/workspace',
        $scannerImage,
        'sh', '-lc', $innerCommand
    )
}

$executedRuns = New-Object System.Collections.Generic.List[string]
$startedLabs = New-Object System.Collections.Generic.List[string]

try {
    foreach ($labName in $Labs) {
        $lab = Start-Lab -LabName $labName
        $startedLabs.Add($lab.Container) | Out-Null

        foreach ($profile in $Profiles) {
            $safeLab = $labName.Replace('-', '_')
            $safeProfile = $profile.Replace('-', '_')
            $runName = "lab_${safeLab}_${safeProfile}"
            Write-Host "Ejecutando $profile contra $labName -> $runName" -ForegroundColor Cyan
            Invoke-Scan -Target $lab.Target -Profile $profile -RunName $runName
            $executedRuns.Add((Join-Path 'scans' $runName)) | Out-Null
        }
    }
} finally {
    if (-not $KeepLabsRunning) {
        foreach ($containerName in $startedLabs) {
            Stop-LabContainer -Name $containerName
        }
    }
}

Write-Host ''
Write-Host 'Validacion completada. Runs generados:' -ForegroundColor Green
foreach ($run in $executedRuns) {
    Write-Host " - $run"
}
