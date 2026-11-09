# Starts a ucanrun runner on Windows at boot, as the current user and without
# administrator rights, using a scheduled task.
#
#   powershell -ExecutionPolicy Bypass -File runner-windows.ps1 [-Ucr C:\path\ucr.exe]
#
# Enroll first:  ucr.exe runner enroll URL CODE --name NAME
# Registering the task needs an elevated PowerShell; the runner itself then
# runs with a limited token.
param(
  [string]$Ucr = "$env:USERPROFILE\.local\bin\ucr.exe",
  [string]$Name = "ucanrun runner",
  [switch]$Remove
)
$ErrorActionPreference = "Stop"

if ($Remove) {
  Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "Removed the task '$Name'."
  exit 0
}
if (-not (Test-Path $Ucr)) { throw "ucr.exe not found at $Ucr" }
$dir = Join-Path $env:APPDATA "ucanrun"
if (-not (Test-Path (Join-Path $dir "runner.json"))) {
  throw "Not enrolled yet. Run: ucr.exe runner enroll URL CODE --name NAME"
}

# The task does not get the user's environment, so the key directory is
# passed on the command line.
$action = New-ScheduledTaskAction -Execute $Ucr -Argument "runner serve --dir `"$dir`"" -WorkingDirectory $dir
$trigger = New-ScheduledTaskTrigger -AtStartup
# S4U: runs whether or not the user is signed in, stores no password, and has
# no access to network shares. Limited: no administrator rights.
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
  -MultipleInstances IgnoreNew
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
  -Description "Runs approved ucanrun jobs under the rules in $dir\runner.toml"
Register-ScheduledTask -TaskName $Name -InputObject $task -Force | Out-Null
Start-ScheduledTask -TaskName $Name
Write-Host "Registered and started the task '$Name' (limited rights, starts at boot)."
Write-Host "Check it in the ucanrun web UI: Overview, Devices and rights."
