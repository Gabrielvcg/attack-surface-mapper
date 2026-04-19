[CmdletBinding()]
param(
    [string]$RunName = 'es_local_juice_shop_passive_recon_safe',
    [string]$IndexPrefix = 'asm-local',
    [string]$Profile = 'passive-recon-safe',
    [string]$ScannerImage = 'python:3.11-slim',
    [string]$ElasticsearchImage = 'docker.elastic.co/elasticsearch/elasticsearch:8.13.4',
    [string]$ElasticsearchContainer = 'asm-es',
    [string]$ElasticsearchUrl = 'http://localhost:9200',
    [string]$LabContainer = 'asm-juice',
    [string]$LabImage = 'bkimminich/juice-shop',
    [string]$Target = 'http://host.docker.internal:3000',
    [string]$HealthUrl = 'http://localhost:3000',
    [int]$MinimumFindings = 1,
    [switch]$KeepElasticsearchRunning,
    [switch]$KeepLabRunning
)

$ErrorActionPreference = 'Stop'

$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$runDir = Join-Path $workspace "scans\$RunName"
$bundleDir = Join-Path $runDir 'elasticsearch'

function Resolve-DockerCli {
    $candidates = @()

    $candidates += 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
    $candidates += 'docker.exe'
    $candidates += 'docker'
    
    try {
        $command = Get-Command docker -ErrorAction Stop
        if ($command -and $command.Source) {
            $candidates += $command.Source
        }
    } catch {
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if (-not $candidate) {
            continue
        }
        try {
            if ($candidate -match '[\\/]') {
                if (Test-Path $candidate) {
                    return $candidate
                }
                continue
            }

            $resolved = Get-Command $candidate -ErrorAction Stop
            if ($resolved -and $resolved.Source) {
                return $resolved.Source
            }
        } catch {
            continue
        }
    }

    throw 'No se encontró docker CLI. Abre Docker Desktop y verifica que docker.exe esté disponible en PATH.'
}

$dockerCli = Resolve-DockerCli

function Invoke-Docker {
    param([string[]]$Arguments)
    Write-Host "$dockerCli $($Arguments -join ' ')" -ForegroundColor DarkGray
    & $dockerCli @Arguments
}

function Stop-ContainerIfExists {
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

function Invoke-ScannerInContainer {
    param([string]$Command)

    Invoke-Docker -Arguments @(
        'run', '--rm',
        '-v', "${workspace}:/workspace",
        '-w', '/workspace',
        $ScannerImage,
        'sh', '-lc', "pip install -q -r requirements.txt && $Command"
    )
}

function Assert-PathExists {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        throw "No se encontrÃ³ el artefacto esperado: $Path"
    }
}

function Get-JsonFile {
    param([string]$Path)
    return Get-Content -Path $Path -Raw | ConvertFrom-Json
}

function Invoke-EsRequest {
    param(
        [string]$Method,
        [string]$Url,
        [string]$ContentType,
        [byte[]]$Body
    )

    $params = @{
        Method = $Method
        Uri = $Url
        TimeoutSec = 60
        UseBasicParsing = $true
    }
    if ($ContentType) {
        $params['ContentType'] = $ContentType
    }
    if ($null -ne $Body) {
        $params['Body'] = $Body
    }

    return Invoke-RestMethod @params
}

function Remove-EsIndexIfPresent {
    param([string]$IndexName)

    try {
        Invoke-WebRequest -Method Delete -Uri "$ElasticsearchUrl/$IndexName" -TimeoutSec 30 -UseBasicParsing | Out-Null
        Write-Host "Indice eliminado: $IndexName" -ForegroundColor Yellow
    } catch {
        if ($_.Exception.Response -and ($_.Exception.Response.StatusCode.value__ -eq 404)) {
            return
        }
        $message = $_.ErrorDetails.Message
        if (-not $message) {
            $message = $_.Exception.Message
        }
        throw "No se pudo eliminar el indice ${IndexName}: $message"
    }
}

function New-EsIndexFromFile {
    param(
        [string]$IndexName,
        [string]$MappingPath
    )

    $body = [System.IO.File]::ReadAllBytes($MappingPath)
    Invoke-EsRequest -Method 'Put' -Url "$ElasticsearchUrl/$IndexName" -ContentType 'application/json' -Body $body | Out-Null
    Write-Host "Indice creado: $IndexName" -ForegroundColor Green
}

function Invoke-EsBulkFromFile {
    param(
        [string]$IndexName,
        [string]$BulkPath
    )

    $body = [System.IO.File]::ReadAllBytes($BulkPath)
    $response = Invoke-EsRequest -Method 'Post' -Url "$ElasticsearchUrl/$IndexName/_bulk" -ContentType 'application/x-ndjson' -Body $body
    if ($response.errors) {
        $failed = @()
        foreach ($item in $response.items) {
            $op = $item.PSObject.Properties.Name | Select-Object -First 1
            $status = [int]$item.$op.status
            if ($status -ge 400) {
                $failed += "$($item.$op._id): $($item.$op.error.reason)"
            }
        }
        throw "Bulk con errores en ${IndexName}: $($failed -join '; ')"
    }
    Write-Host "Bulk OK en ${IndexName}: $(@($response.items).Count) documentos procesados" -ForegroundColor Green
}

function Get-EsCount {
    param([string]$IndexName)
    return [int](Invoke-EsRequest -Method 'Get' -Url "$ElasticsearchUrl/$IndexName/_count" -ContentType '' -Body $null).count
}

function Invoke-EsRefresh {
    param([string]$IndexName)

    Invoke-EsRequest -Method 'Post' -Url "$ElasticsearchUrl/$IndexName/_refresh" -ContentType '' -Body $null | Out-Null
    Write-Host "Refresh OK en ${IndexName}" -ForegroundColor Green
}

function Assert-RequiredProperty {
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
    $manifestPath = Join-Path $runDir 'run_manifest.json'
    $aggregatePath = Join-Path $runDir 'reports\aggregate_summary.json'

    Assert-PathExists -Path $manifestPath
    Assert-PathExists -Path $aggregatePath

    $summaryPaths = Get-ChildItem -Path (Join-Path $runDir 'targets') -Filter 'report.summary.json' -Recurse -File
    if (-not $summaryPaths) {
        throw "No se encontrÃ³ ningÃºn report.summary.json dentro de $runDir\targets"
    }

    $aggregate = Get-JsonFile -Path $aggregatePath
    if ([int]$aggregate.summary.total_findings -lt $MinimumFindings) {
        throw "El agregado refleja menos hallazgos de los esperados: $($aggregate.summary.total_findings) < $MinimumFindings"
    }
}

function Assert-BundleOutputs {
    foreach ($name in @(
        'findings_mapping.json',
        'summaries_mapping.json',
        'runs_mapping.json',
        'findings_bulk.ndjson',
        'summaries_bulk.ndjson',
        'runs_bulk.ndjson',
        'manual_kibana_devtools.md',
        'ingest_with_curl.sh',
        'ingest_with_python.py',
        'export_manifest.json'
    )) {
        Assert-PathExists -Path (Join-Path $bundleDir $name)
    }
}

function Assert-FindingDocumentContract {
    param([string]$IndexName)

    $response = Invoke-EsRequest -Method 'Get' -Url "$ElasticsearchUrl/$IndexName/_search?size=1" -ContentType '' -Body $null
    if (-not $response.hits.hits -or @($response.hits.hits).Count -lt 1) {
        throw "No se recuperÃ³ ningÃºn finding desde $IndexName"
    }

    $doc = @($response.hits.hits)[0]._source
    foreach ($property in @('finding_id', 'correlation_id', 'priority_score', 'finding_role', 'validated', 'validation_basis')) {
        Assert-RequiredProperty -Object $doc -PropertyName $property -Context "$IndexName _source"
    }

    if (-not $doc.finding_id) {
        throw "finding_id estÃ¡ vacÃ­o en $IndexName"
    }
    if (-not $doc.correlation_id) {
        throw "correlation_id estÃ¡ vacÃ­o en $IndexName"
    }

    Write-Host "Contrato de findings verificado en $IndexName" -ForegroundColor Green
}

function Assert-RunManifestDocument {
    param([string]$IndexName)

    $response = Invoke-EsRequest -Method 'Get' -Url "$ElasticsearchUrl/$IndexName/_search?size=1" -ContentType '' -Body $null
    if (-not $response.hits.hits -or @($response.hits.hits).Count -lt 1) {
        throw "No se recuperÃ³ ningÃºn documento de run desde $IndexName"
    }

    $doc = @($response.hits.hits)[0]._source
    if ($doc.document_type -ne 'run_manifest') {
        throw "Se esperaba document_type=run_manifest en $IndexName y se obtuvo '$($doc.document_type)'"
    }

    Write-Host "Documento run_manifest verificado en $IndexName" -ForegroundColor Green
}

$startedEs = $false
$startedLab = $false

try {
    Stop-ContainerIfExists -Name $ElasticsearchContainer
    Invoke-Docker -Arguments @(
        'run', '-d', '--name', $ElasticsearchContainer,
        '-p', '9200:9200',
        '-e', 'discovery.type=single-node',
        '-e', 'xpack.security.enabled=false',
        '-e', 'ES_JAVA_OPTS=-Xms1g -Xmx1g',
        $ElasticsearchImage
    ) | Out-Null
    $startedEs = $true
    Wait-HttpReady -Url $ElasticsearchUrl -Name 'Elasticsearch' -TimeoutSeconds 240
    Wait-HttpReady -Url "$ElasticsearchUrl/_cluster/health" -Name 'Elasticsearch cluster health' -TimeoutSeconds 240

    Stop-ContainerIfExists -Name $LabContainer
    Invoke-Docker -Arguments @(
        'run', '-d', '--rm',
        '--name', $LabContainer,
        '-p', '3000:3000',
        $LabImage
    ) | Out-Null
    $startedLab = $true
    Wait-HttpReady -Url $HealthUrl -Name 'Juice Shop' -TimeoutSeconds 240

    if (Test-Path $runDir) {
        Write-Host "Limpiando run previo: $runDir" -ForegroundColor Yellow
        Remove-Item -Recurse -Force -LiteralPath $runDir
    }

    Write-Host "Ejecutando escaneo $Profile contra $Target -> $RunName" -ForegroundColor Cyan
    Invoke-ScannerInContainer -Command "python main.py --profile $Profile --run-name $RunName $Target"
    Assert-RunOutputs

    Write-Host "Exportando bundle Elasticsearch para $RunName" -ForegroundColor Cyan
    Invoke-ScannerInContainer -Command "python scripts/export_elasticsearch_bundle.py --run-dir scans/$RunName --index-prefix $IndexPrefix"
    Assert-BundleOutputs

    $bundleManifest = Get-JsonFile -Path (Join-Path $bundleDir 'export_manifest.json')
    $findingsIndex = [string]$bundleManifest.indices.findings
    $summariesIndex = [string]$bundleManifest.indices.summaries
    $runsIndex = [string]$bundleManifest.indices.runs

    foreach ($indexName in @($findingsIndex, $summariesIndex, $runsIndex)) {
        Remove-EsIndexIfPresent -IndexName $indexName
    }

    New-EsIndexFromFile -IndexName $findingsIndex -MappingPath (Join-Path $bundleDir 'findings_mapping.json')
    New-EsIndexFromFile -IndexName $summariesIndex -MappingPath (Join-Path $bundleDir 'summaries_mapping.json')
    New-EsIndexFromFile -IndexName $runsIndex -MappingPath (Join-Path $bundleDir 'runs_mapping.json')

    Invoke-EsBulkFromFile -IndexName $findingsIndex -BulkPath (Join-Path $bundleDir 'findings_bulk.ndjson')
    Invoke-EsBulkFromFile -IndexName $summariesIndex -BulkPath (Join-Path $bundleDir 'summaries_bulk.ndjson')
    Invoke-EsBulkFromFile -IndexName $runsIndex -BulkPath (Join-Path $bundleDir 'runs_bulk.ndjson')
    Invoke-EsRefresh -IndexName $findingsIndex
    Invoke-EsRefresh -IndexName $summariesIndex
    Invoke-EsRefresh -IndexName $runsIndex

    $initialFindingsCount = Get-EsCount -IndexName $findingsIndex
    $initialSummariesCount = Get-EsCount -IndexName $summariesIndex
    $initialRunsCount = Get-EsCount -IndexName $runsIndex

    if ($initialFindingsCount -lt 1) {
        throw "El indice $findingsIndex no contiene findings"
    }
    if ($initialSummariesCount -lt 1) {
        throw "El indice $summariesIndex no contiene summaries"
    }
    if ($initialRunsCount -lt 1) {
        throw "El indice $runsIndex no contiene run docs"
    }

    Assert-FindingDocumentContract -IndexName $findingsIndex
    Assert-RunManifestDocument -IndexName $runsIndex

    Write-Host "Probando reingesta idempotente" -ForegroundColor Cyan
    Invoke-EsBulkFromFile -IndexName $findingsIndex -BulkPath (Join-Path $bundleDir 'findings_bulk.ndjson')
    Invoke-EsBulkFromFile -IndexName $summariesIndex -BulkPath (Join-Path $bundleDir 'summaries_bulk.ndjson')
    Invoke-EsBulkFromFile -IndexName $runsIndex -BulkPath (Join-Path $bundleDir 'runs_bulk.ndjson')
    Invoke-EsRefresh -IndexName $findingsIndex
    Invoke-EsRefresh -IndexName $summariesIndex
    Invoke-EsRefresh -IndexName $runsIndex

    $reingestedFindingsCount = Get-EsCount -IndexName $findingsIndex
    $reingestedSummariesCount = Get-EsCount -IndexName $summariesIndex
    $reingestedRunsCount = Get-EsCount -IndexName $runsIndex

    if ($reingestedFindingsCount -ne $initialFindingsCount) {
        throw "La reingesta cambiÃ³ el conteo de findings: $initialFindingsCount -> $reingestedFindingsCount"
    }
    if ($reingestedSummariesCount -ne $initialSummariesCount) {
        throw "La reingesta cambiÃ³ el conteo de summaries: $initialSummariesCount -> $reingestedSummariesCount"
    }
    if ($reingestedRunsCount -ne $initialRunsCount) {
        throw "La reingesta cambiÃ³ el conteo de runs: $initialRunsCount -> $reingestedRunsCount"
    }

    Write-Host "Probando borrado y recreaciÃ³n de Ã­ndices" -ForegroundColor Cyan
    foreach ($indexName in @($findingsIndex, $summariesIndex, $runsIndex)) {
        Remove-EsIndexIfPresent -IndexName $indexName
    }

    New-EsIndexFromFile -IndexName $findingsIndex -MappingPath (Join-Path $bundleDir 'findings_mapping.json')
    New-EsIndexFromFile -IndexName $summariesIndex -MappingPath (Join-Path $bundleDir 'summaries_mapping.json')
    New-EsIndexFromFile -IndexName $runsIndex -MappingPath (Join-Path $bundleDir 'runs_mapping.json')

    Invoke-EsBulkFromFile -IndexName $findingsIndex -BulkPath (Join-Path $bundleDir 'findings_bulk.ndjson')
    Invoke-EsBulkFromFile -IndexName $summariesIndex -BulkPath (Join-Path $bundleDir 'summaries_bulk.ndjson')
    Invoke-EsBulkFromFile -IndexName $runsIndex -BulkPath (Join-Path $bundleDir 'runs_bulk.ndjson')
    Invoke-EsRefresh -IndexName $findingsIndex
    Invoke-EsRefresh -IndexName $summariesIndex
    Invoke-EsRefresh -IndexName $runsIndex

    if ((Get-EsCount -IndexName $findingsIndex) -ne $initialFindingsCount) {
        throw "El recreate no restaurÃ³ el conteo esperado en $findingsIndex"
    }
    if ((Get-EsCount -IndexName $summariesIndex) -ne $initialSummariesCount) {
        throw "El recreate no restaurÃ³ el conteo esperado en $summariesIndex"
    }
    if ((Get-EsCount -IndexName $runsIndex) -ne $initialRunsCount) {
        throw "El recreate no restaurÃ³ el conteo esperado en $runsIndex"
    }

    Write-Host ''
    Write-Host 'Validacion local de Elasticsearch completada.' -ForegroundColor Green
    Write-Host "Run: $runDir"
    Write-Host "Bundle: $bundleDir"
    Write-Host "Indices: $findingsIndex, $summariesIndex, $runsIndex"
    Write-Host "Conteos: findings=$initialFindingsCount summaries=$initialSummariesCount runs=$initialRunsCount"
} finally {
    if (-not $KeepLabRunning -and $startedLab) {
        Stop-ContainerIfExists -Name $LabContainer
    }
    if (-not $KeepElasticsearchRunning -and $startedEs) {
        Stop-ContainerIfExists -Name $ElasticsearchContainer
    }
}
