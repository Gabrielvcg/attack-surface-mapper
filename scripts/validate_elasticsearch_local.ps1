[CmdletBinding()]
param(
    [string]$RunName = 'es_local_juice_shop_passive_recon_safe',
    [string]$IndexPrefix = 'asm-local',
    [string]$Profile = 'passive-recon-safe',
    [string]$ScannerImage = 'python:3.11-slim',
    [string]$ElasticsearchImage = 'docker.elastic.co/elasticsearch/elasticsearch:8.13.4',
    [string]$ElasticsearchContainer = 'asm-es',
    [string]$ElasticsearchUrl = 'http://localhost:9200',
    [int]$ElasticsearchHostPort = 9200,
    [int]$ElasticsearchContainerPort = 9200,
    [string]$ElasticsearchUsername = '',
    [string]$ElasticsearchPassword = '',
    [string]$ElasticsearchApiKey = '',
    [switch]$SkipCertificateCheck,
    [string]$LabContainer = 'asm-juice',
    [string]$LabImage = 'bkimminich/juice-shop',
    [int]$LabHostPort = 3000,
    [int]$LabContainerPort = 3000,
    [string]$ScannerTargetHost = 'host.docker.internal',
    [string]$Target = '',
    [string]$HealthUrl = '',
    [int]$MinimumFindings = 1,
    [string]$DockerCli = '',
    [switch]$AddHostGateway,
    [switch]$KeepElasticsearchRunning,
    [switch]$KeepLabRunning
)

$ErrorActionPreference = 'Stop'

$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$runDir = Join-Path $workspace "scans\$RunName"
$bundleDir = Join-Path $runDir 'elasticsearch'
$isWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Windows
)

function Resolve-DockerCli {
    if ($DockerCli) {
        if (($DockerCli -match '[\\/]') -and -not (Test-Path $DockerCli)) {
            throw "The path passed with -DockerCli does not exist: $DockerCli"
        }
        return $DockerCli
    }

    $candidates = @()
    if ($isWindows) {
        $candidates += 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
    }
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

    throw 'Docker CLI was not found. Start Docker and verify docker is available in PATH.'
}

$dockerCli = Resolve-DockerCli

function Invoke-Docker {
    param([string[]]$Arguments)

    Write-Host "$dockerCli $($Arguments -join ' ')" -ForegroundColor DarkGray
    & $dockerCli @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker failed with exit code $LASTEXITCODE"
    }
}

function Get-ContainerId {
    param([string]$Name)
    return (& $dockerCli ps -aq --filter "name=^${Name}$")
}

function Test-ContainerRunning {
    param([string]$Name)

    $containerId = Get-ContainerId -Name $Name
    if (-not $containerId) {
        return $false
    }
    $running = (& $dockerCli inspect -f '{{.State.Running}}' $Name 2>$null)
    return ($running -eq 'true')
}

function Stop-ContainerIfExists {
    param([string]$Name)

    try {
        $existing = Get-ContainerId -Name $Name
        if ($existing) {
            & $dockerCli rm -f $Name | Out-Null
        }
    } catch {
        Write-Warning "Could not remove container ${Name}: $($_.Exception.Message)"
    }
}

function Ensure-Container {
    param(
        [string]$Name,
        [string[]]$RunArguments
    )

    if (Test-ContainerRunning -Name $Name) {
        Write-Host "Reusing running container: $Name" -ForegroundColor Yellow
        return $false
    }

    Stop-ContainerIfExists -Name $Name
    Invoke-Docker -Arguments $RunArguments | Out-Null
    return $true
}

function Get-HttpRequestOptions {
    $params = @{}

    if ($ElasticsearchApiKey) {
        $params['Headers'] = @{ Authorization = "ApiKey $ElasticsearchApiKey" }
    } elseif ($ElasticsearchUsername -and $ElasticsearchPassword) {
        $raw = "${ElasticsearchUsername}:${ElasticsearchPassword}"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($raw))
        $params['Headers'] = @{ Authorization = "Basic $encoded" }
    }

    if ($SkipCertificateCheck) {
        $restParams = (Get-Command Invoke-RestMethod).Parameters
        if ($restParams.ContainsKey('SkipCertificateCheck')) {
            $params['SkipCertificateCheck'] = $true
        }
    }

    return $params
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
            $options = Get-HttpRequestOptions
            $response = Invoke-WebRequest -Uri $Url -TimeoutSec 5 -UseBasicParsing @options
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
                Write-Host "$Name ready at $Url (status $($response.StatusCode))" -ForegroundColor Green
                return
            }
        } catch {
            Start-Sleep -Seconds 2
            continue
        }
        Start-Sleep -Seconds 2
    }

    throw "Timeout waiting for $Name at $Url"
}

function Invoke-ScannerInContainer {
    param([string]$Command)

    $arguments = @(
        'run', '--rm',
        '-v', "${workspace}:/workspace",
        '-w', '/workspace'
    )
    if ($AddHostGateway) {
        $arguments += @('--add-host', "${ScannerTargetHost}:host-gateway")
    }
    $arguments += @(
        $ScannerImage,
        'sh', '-lc', "pip install -q -r requirements.txt && $Command"
    )

    Invoke-Docker -Arguments $arguments
}

function Assert-PathExists {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Expected artifact was not generated: $Path"
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
    foreach ($entry in (Get-HttpRequestOptions).GetEnumerator()) {
        $params[$entry.Key] = $entry.Value
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
        $options = Get-HttpRequestOptions
        Invoke-WebRequest -Method Delete -Uri "$ElasticsearchUrl/$IndexName" -TimeoutSec 30 -UseBasicParsing @options | Out-Null
        Write-Host "Index removed: $IndexName" -ForegroundColor Yellow
    } catch {
        if ($_.Exception.Response -and ($_.Exception.Response.StatusCode.value__ -eq 404)) {
            return
        }
        $message = $_.ErrorDetails.Message
        if (-not $message) {
            $message = $_.Exception.Message
        }
        throw "Could not remove index ${IndexName}: $message"
    }
}

function New-EsIndexFromFile {
    param(
        [string]$IndexName,
        [string]$MappingPath
    )

    $body = [System.IO.File]::ReadAllBytes($MappingPath)
    Invoke-EsRequest -Method 'Put' -Url "$ElasticsearchUrl/$IndexName" -ContentType 'application/json' -Body $body | Out-Null
    Write-Host "Index created: $IndexName" -ForegroundColor Green
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
        throw "Bulk errors in ${IndexName}: $($failed -join '; ')"
    }
    Write-Host "Bulk OK in ${IndexName}: $(@($response.items).Count) documents processed" -ForegroundColor Green
}

function Get-EsCount {
    param([string]$IndexName)
    return [int](Invoke-EsRequest -Method 'Get' -Url "$ElasticsearchUrl/$IndexName/_count" -ContentType '' -Body $null).count
}

function Invoke-EsRefresh {
    param([string]$IndexName)

    Invoke-EsRequest -Method 'Post' -Url "$ElasticsearchUrl/$IndexName/_refresh" -ContentType '' -Body $null | Out-Null
    Write-Host "Refresh OK in ${IndexName}" -ForegroundColor Green
}

function Assert-RequiredProperty {
    param(
        $Object,
        [string]$PropertyName,
        [string]$Context
    )

    if (-not ($Object.PSObject.Properties.Name -contains $PropertyName)) {
        throw "Missing property '$PropertyName' in $Context"
    }
}

function Assert-RunOutputs {
    $manifestPath = Join-Path $runDir 'run_manifest.json'
    $aggregatePath = Join-Path $runDir 'reports\aggregate_summary.json'

    Assert-PathExists -Path $manifestPath
    Assert-PathExists -Path $aggregatePath

    $summaryPaths = Get-ChildItem -Path (Join-Path $runDir 'targets') -Filter 'report.summary.json' -Recurse -File
    if (-not $summaryPaths) {
        throw "No report.summary.json was found under $runDir/targets"
    }

    $aggregate = Get-JsonFile -Path $aggregatePath
    if ([int]$aggregate.summary.total_findings -lt $MinimumFindings) {
        throw "Aggregate findings below expected minimum: $($aggregate.summary.total_findings) < $MinimumFindings"
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
        throw "No finding document was returned from $IndexName"
    }

    $doc = @($response.hits.hits)[0]._source
    foreach ($property in @('finding_id', 'correlation_id', 'priority_score', 'finding_role', 'validated', 'validation_basis')) {
        Assert-RequiredProperty -Object $doc -PropertyName $property -Context "$IndexName _source"
    }

    if (-not $doc.finding_id) {
        throw "finding_id is empty in $IndexName"
    }
    if (-not $doc.correlation_id) {
        throw "correlation_id is empty in $IndexName"
    }

    Write-Host "Finding contract verified in $IndexName" -ForegroundColor Green
}

function Assert-RunManifestDocument {
    param([string]$IndexName)

    $response = Invoke-EsRequest -Method 'Get' -Url "$ElasticsearchUrl/$IndexName/_search?size=1" -ContentType '' -Body $null
    if (-not $response.hits.hits -or @($response.hits.hits).Count -lt 1) {
        throw "No run document was returned from $IndexName"
    }

    $doc = @($response.hits.hits)[0]._source
    if ($doc.document_type -ne 'run_manifest') {
        throw "Expected document_type=run_manifest in $IndexName and got '$($doc.document_type)'"
    }

    Write-Host "run_manifest document verified in $IndexName" -ForegroundColor Green
}

$startedEs = $false
$startedLab = $false

try {
    if (-not $Target) {
        $Target = "http://${ScannerTargetHost}:$LabHostPort"
    }
    if (-not $HealthUrl) {
        $HealthUrl = "http://localhost:$LabHostPort"
    }

    $startedEs = Ensure-Container -Name $ElasticsearchContainer -RunArguments @(
        'run', '-d', '--name', $ElasticsearchContainer,
        '-p', "${ElasticsearchHostPort}:${ElasticsearchContainerPort}",
        '-e', 'discovery.type=single-node',
        '-e', 'xpack.security.enabled=false',
        '-e', 'ES_JAVA_OPTS=-Xms1g -Xmx1g',
        $ElasticsearchImage
    )
    Wait-HttpReady -Url $ElasticsearchUrl -Name 'Elasticsearch' -TimeoutSeconds 240
    Wait-HttpReady -Url "$ElasticsearchUrl/_cluster/health" -Name 'Elasticsearch cluster health' -TimeoutSeconds 240

    $startedLab = Ensure-Container -Name $LabContainer -RunArguments @(
        'run', '-d', '--rm',
        '--name', $LabContainer,
        '-p', "${LabHostPort}:${LabContainerPort}",
        $LabImage
    )
    Wait-HttpReady -Url $HealthUrl -Name 'Juice Shop' -TimeoutSeconds 240

    if (Test-Path $runDir) {
        Write-Host "Removing previous run: $runDir" -ForegroundColor Yellow
        Remove-Item -Recurse -Force -LiteralPath $runDir
    }

    Write-Host "Running scan $Profile against $Target -> $RunName" -ForegroundColor Cyan
    Invoke-ScannerInContainer -Command "python main.py --profile $Profile --run-name $RunName $Target"
    Assert-RunOutputs

    Write-Host "Exporting Elasticsearch bundle for $RunName" -ForegroundColor Cyan
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
        throw "Index $findingsIndex does not contain findings"
    }
    if ($initialSummariesCount -lt 1) {
        throw "Index $summariesIndex does not contain summaries"
    }
    if ($initialRunsCount -lt 1) {
        throw "Index $runsIndex does not contain run documents"
    }

    Assert-FindingDocumentContract -IndexName $findingsIndex
    Assert-RunManifestDocument -IndexName $runsIndex

    Write-Host "Testing idempotent reingestion" -ForegroundColor Cyan
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
        throw "Reingestion changed findings count: $initialFindingsCount -> $reingestedFindingsCount"
    }
    if ($reingestedSummariesCount -ne $initialSummariesCount) {
        throw "Reingestion changed summaries count: $initialSummariesCount -> $reingestedSummariesCount"
    }
    if ($reingestedRunsCount -ne $initialRunsCount) {
        throw "Reingestion changed runs count: $initialRunsCount -> $reingestedRunsCount"
    }

    Write-Host "Testing index deletion and recreation" -ForegroundColor Cyan
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
        throw "Recreate did not restore expected count in $findingsIndex"
    }
    if ((Get-EsCount -IndexName $summariesIndex) -ne $initialSummariesCount) {
        throw "Recreate did not restore expected count in $summariesIndex"
    }
    if ((Get-EsCount -IndexName $runsIndex) -ne $initialRunsCount) {
        throw "Recreate did not restore expected count in $runsIndex"
    }

    Write-Host ''
    Write-Host 'Local Elasticsearch validation completed.' -ForegroundColor Green
    Write-Host "Run: $runDir"
    Write-Host "Bundle: $bundleDir"
    Write-Host "Indices: $findingsIndex, $summariesIndex, $runsIndex"
    Write-Host "Counts: findings=$initialFindingsCount summaries=$initialSummariesCount runs=$initialRunsCount"
} finally {
    if (-not $KeepLabRunning -and $startedLab) {
        Stop-ContainerIfExists -Name $LabContainer
    }
    if (-not $KeepElasticsearchRunning -and $startedEs) {
        Stop-ContainerIfExists -Name $ElasticsearchContainer
    }
}
