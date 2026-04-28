[CmdletBinding()]
param(
    [string]$ImageName = 'attack-surface-mapper-scanner',
    [string]$DockerCli = '',
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScannerArgs
)

$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if ($ImageName -and $ImageName.StartsWith('-')) {
    $ScannerArgs = @($ImageName) + $ScannerArgs
    $ImageName = 'attack-surface-mapper-scanner'
}

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

if (-not $ScannerArgs -or $ScannerArgs.Count -eq 0) {
    $ScannerArgs = @('--help')
}

& $docker run --rm `
    -v "${workspace}:/workspace" `
    -w /workspace `
    $ImageName `
    python main.py @ScannerArgs

if ($LASTEXITCODE -ne 0) {
    throw "scanner exited with code $LASTEXITCODE"
}
