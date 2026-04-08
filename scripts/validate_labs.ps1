[CmdletBinding()]
param(
    [string[]]$Labs = @('juice-shop', 'dvwa'),
    [string[]]$Profiles = @('passive-stealth', 'passive-recon-safe'),
    [switch]$IncludeEnum,
    [int]$MinFindings = 1,
    [string]$ReviewMatrixOutput = 'reviews/lab_findings_review.csv',
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

function Export-ReviewMatrix {
    param(
        [System.Collections.Generic.List[string]]$Runs,
        [string]$OutputPath
    )

    if (-not $Runs -or $Runs.Count -eq 0) {
        return
    }

    $runArgs = ($Runs | ForEach-Object { $_ -replace '\\', '/' }) -join ' '
    $innerCommand = "pip install -q -r requirements.txt && python scripts/export_review_matrix.py $runArgs --output $OutputPath"
    Invoke-Docker -Arguments @(
        'run', '--rm',
        '-v', "${workspace}:/workspace",
        '-w', '/workspace',
        $scannerImage,
        'sh', '-lc', $innerCommand
    )

    $matrixPath = Join-Path $workspace ($OutputPath -replace '/', '\')
    if (-not (Test-Path $matrixPath)) {
        throw "No se generó la matriz de revisión esperada: $matrixPath"
    }
    Write-Host "Matriz de revisión exportada: $matrixPath" -ForegroundColor Green
}

function Assert-RequiredJsonProperty {
    param(
        $Object,
        [string]$PropertyName,
        [string]$Context
    )

    if (-not ($Object.PSObject.Properties.Name -contains $PropertyName)) {
        throw "Falta la propiedad '$PropertyName' en $Context"
    }
}

function Assert-RunOutputs {
    param(
        [string]$RunName,
        [string]$Target,
        [int]$MinimumFindings
    )

    $slug = ($Target -replace '[^a-zA-Z0-9._-]+', '_')
    if ($slug.Length -gt 80) {
        $slug = $slug.Substring(0, 80)
    }
    if (-not $slug) {
        $slug = 'target'
    }

    $runDir = Join-Path $workspace "scans\$RunName"
    $manifestPath = Join-Path $runDir 'run_manifest.json'
    $aggregatePath = Join-Path $runDir 'reports\aggregate_summary.json'
    $summaryPath = Join-Path $runDir "targets\$slug\reports\report.summary.json"

    foreach ($path in @($manifestPath, $aggregatePath, $summaryPath)) {
        if (-not (Test-Path $path)) {
            throw "No se generó el artefacto esperado: $path"
        }
    }

    $manifest = Get-Content -Path $manifestPath -Raw | ConvertFrom-Json
    $aggregate = Get-Content -Path $aggregatePath -Raw | ConvertFrom-Json
    $summary = Get-Content -Path $summaryPath -Raw | ConvertFrom-Json

    Assert-RequiredJsonProperty -Object $summary -PropertyName 'comparison' -Context $summaryPath
    Assert-RequiredJsonProperty -Object $summary -PropertyName 'comparison_summary' -Context $summaryPath
    Assert-RequiredJsonProperty -Object $summary -PropertyName 'top_findings' -Context $summaryPath
    Assert-RequiredJsonProperty -Object $summary -PropertyName 'stats' -Context $summaryPath
    Assert-RequiredJsonProperty -Object $aggregate -PropertyName 'summary' -Context $aggregatePath
    Assert-RequiredJsonProperty -Object $manifest -PropertyName 'effective_config' -Context $manifestPath
    Assert-RequiredJsonProperty -Object $manifest -PropertyName 'results_summary' -Context $manifestPath

    if ([int]$summary.stats.total_findings -lt $MinimumFindings) {
        throw "Se esperaban al menos $MinimumFindings hallazgos en $summaryPath y solo hubo $($summary.stats.total_findings)"
    }
    if ([int]$manifest.results_summary.successful_targets -lt 1) {
        throw "El manifest no refleja targets exitosos en $manifestPath"
    }
    if ([int]$aggregate.summary.total_findings -lt $MinimumFindings) {
        throw "El agregado no refleja el mínimo esperado de hallazgos en $aggregatePath"
    }
    if (@($summary.top_findings).Count -lt 1) {
        throw "No hay top_findings en $summaryPath"
    }

    $topFinding = @($summary.top_findings)[0]
    foreach ($property in @('finding_id', 'correlation_id', 'asset_host', 'asset_host_resolved')) {
        Assert-RequiredJsonProperty -Object $topFinding -PropertyName $property -Context "$summaryPath top_findings[0]"
    }
    if (-not $topFinding.finding_id) {
        throw "top_findings[0].finding_id está vacío en $summaryPath"
    }
    if (-not $topFinding.correlation_id) {
        throw "top_findings[0].correlation_id está vacío en $summaryPath"
    }

    Write-Host "Validación estructural OK para $RunName" -ForegroundColor Green
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
            Assert-RunOutputs -RunName $runName -Target $lab.Target -MinimumFindings $MinFindings
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

Export-ReviewMatrix -Runs $executedRuns -OutputPath $ReviewMatrixOutput

Write-Host ''
Write-Host 'Validacion completada. Runs generados:' -ForegroundColor Green
foreach ($run in $executedRuns) {
    Write-Host " - $run"
}
