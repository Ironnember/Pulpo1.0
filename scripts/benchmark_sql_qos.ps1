[CmdletBinding()]
param(
    [string]$Python = 'python',
    [ValidateRange(1,100)][int]$Iterations = 10,
    [ValidateRange(1,20)][int]$Repeats = 4,
    [ValidateRange(1,8)][int]$Callers = 8,
    [switch]$Observe,
    [switch]$CheckOnly
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$benchmark = Join-Path $PSScriptRoot 'benchmark_sql_qos.py'
# Pass arguments directly; avoid nested python -c quoting in Windows PowerShell.
& $Python $benchmark --check-only
if ($LASTEXITCODE -ne 0) { throw 'Dependency check failed. Use -Python with a prepared custody-service test environment.' }
& $Python $benchmark --self-test
if ($LASTEXITCODE -ne 0) { throw 'Correctness checks failed; benchmark was not started.' }
if ($CheckOnly) { return }
$resultDirectory = Join-Path $repoRoot 'perf-results'
New-Item -ItemType Directory -Force -Path $resultDirectory | Out-Null
$runName = 'sql-qos-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + $PID
$resultPath = Join-Path $resultDirectory ($runName + '.json')
$logPath = Join-Path $resultDirectory ($runName + '.log')
$benchmarkArguments = @($benchmark, '--iterations', "$Iterations", '--repeats', "$Repeats", '--callers', "$Callers", '--json', $resultPath)
if ($Observe) { $benchmarkArguments += '--observe' }
& $Python @benchmarkArguments 2>&1 | Tee-Object -FilePath $logPath
if ($LASTEXITCODE -ne 0) { throw "Benchmark failed. See $logPath" }
Write-Host "Results: $resultPath"
Write-Host "Log:     $logPath"
