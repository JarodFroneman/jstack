param(
    [string]$CodexHome,
    [switch]$ManageAgents
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$InstallArguments = @(
    (Join-Path $ScriptDir "install.py"),
    "--repo-root",
    $RepoRoot
)
if ($PSBoundParameters.ContainsKey("CodexHome")) {
    $InstallArguments += @("--codex-home", $CodexHome)
}
if ($ManageAgents) {
    $InstallArguments += "--manage-agents"
}

& python @InstallArguments
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
