[CmdletBinding()]
param(
    [string]$ImageName = 'attack-surface-mapper-scanner',
    [string]$Dockerfile = 'Dockerfile.scanner',
    [string]$NucleiVersion = '3.3.9',
    [string]$DockerCli = ''
)

$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Resolve-DockerCli {
    if ($DockerCli) {
        return $DockerCli
    }
    $windowsDocker = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
    if (Test-Path $windowsDocker) {
        return $windowsDocker
    }
    $command = Get-Command docker -ErrorAction Stop
    return $command.Source
}

$docker = Resolve-DockerCli

Write-Host "Building scanner image: $ImageName" -ForegroundColor Cyan
& $docker build `
    -f (Join-Path $workspace $Dockerfile) `
    --build-arg "NUCLEI_VERSION=$NucleiVersion" `
    -t $ImageName `
    $workspace

if ($LASTEXITCODE -ne 0) {
    throw "docker build failed with exit code $LASTEXITCODE"
}

Write-Host "Scanner image ready: $ImageName" -ForegroundColor Green
