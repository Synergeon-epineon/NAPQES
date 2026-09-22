#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys the Legacy Shield web demo to Azure App Service.

.DESCRIPTION
    Packages the FastAPI app, its static frontend, and the required NAPQES
    Python modules from the repo root into a flat zip, then deploys to
    Azure App Service (Linux, Python 3.11).

    Steps:
      1. Copies demos/legacy_shield/webdemo/* to a temp staging directory.
      2. Copies napqes.py, napqes_kem.py, and traffic_analysis_bench.py
         alongside app.py so imports work without the repo-root sys.path hack.
      3. Patches the one sys.path line in app.py (parents[3] -> parent).
      4. Zips the staging directory and deploys via az webapp deployment
         source config-zip.

.PARAMETER ResourceGroup
    Azure resource group name (created if it does not exist).

.PARAMETER AppName
    Azure Web App name -- must be globally unique across all of Azure.

.PARAMETER Location
    Azure region (default: westeurope).

.PARAMETER Sku
    App Service Plan SKU (default: B1).

.PARAMETER PythonVersion
    Python runtime version for the Web App (default: 3.11).

.PARAMETER SubscriptionId
    Pin a specific Azure subscription. Run 'az account list -o table' to list.

.EXAMPLE
    .\deploy-legacy-shield.ps1 -AppName "qaeigis-lshield-demo"

.EXAMPLE
    .\deploy-legacy-shield.ps1 `
        -ResourceGroup  "rg-loc-energy-demo" `
        -AppName        "loc-energy-lshield" `
        -Location       "koreacentral" `
        -SubscriptionId "137849bf-dcba-43ba-8bb7-c1a4acf52446"
#>

param(
    [string]$ResourceGroup  = "rg-legacy-shield-demo",
    [string]$AppName        = "legacy-shield-demo",
    [string]$Location       = "westeurope",
    [string]$Sku            = "B1",
    [string]$PythonVersion  = "3.11",
    [string]$SubscriptionId = "137849bf-dcba-43ba-8bb7-c1a4acf52446"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
$RepoRoot   = $PSScriptRoot
$WebdemoSrc = Join-Path $RepoRoot "demos\legacy_shield\webdemo"

$RootModules = @(
    "napqes.py",
    "napqes_kem.py",
    "traffic_analysis_bench.py"
)

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
function Step([string]$msg) { Write-Host "`n>>> $msg" -ForegroundColor Cyan }
function OK  ([string]$msg) { Write-Host "    $msg"  -ForegroundColor Green }

# Wrapper: run an az command and throw on non-zero exit.
# Temporarily uses Continue so that az WARNING lines on stderr
# don't trigger PowerShell's Stop preference.
function Invoke-Az {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    az @args
    $ec = $LASTEXITCODE
    $ErrorActionPreference = $saved
    if ($ec -ne 0) {
        throw "Azure CLI command failed (exit $ec).`n  Command: az $args"
    }
}

# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------
Step "Checking prerequisites"

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI not found. Install from https://aka.ms/installazurecliwindows then re-run."
}
OK "Azure CLI found"

$account = az account show --query "{name:name,sub:id}" -o json 2>$null | ConvertFrom-Json
if (-not $account) {
    throw "Not logged in to Azure. Run 'az login' first."
}

if ($SubscriptionId -ne "") {
    Invoke-Az account set --subscription $SubscriptionId
    $account = az account show --query "{name:name,sub:id}" -o json | ConvertFrom-Json
    OK "Subscription : $($account.name) ($($account.sub))"
} else {
    Write-Host ""
    Write-Host "  Active subscription: $($account.name)" -ForegroundColor Yellow
    Write-Host "  Subscription ID    : $($account.sub)"  -ForegroundColor Yellow
    Write-Host "  If this is wrong, re-run with -SubscriptionId <id>" -ForegroundColor DarkGray
    Write-Host ""
    OK "Subscription confirmed"
}

# --------------------------------------------------------------------------
# Resolve runtime string
# --------------------------------------------------------------------------
# The exact string varies by CLI version (PYTHON|3.11 vs PYTHON:3.11).
# Query the list of valid runtimes and pick the right one automatically.
Step "Resolving Python $PythonVersion runtime string for Linux"

$runtimes = az webapp list-runtimes --os linux -o json 2>$null | ConvertFrom-Json
$runtime  = $runtimes | Where-Object { $_ -match "(?i)python[|:]$([regex]::Escape($PythonVersion))" } |
            Select-Object -First 1

if (-not $runtime) {
    Write-Host "  Available Python runtimes:" -ForegroundColor Yellow
    $runtimes | Where-Object { $_ -match "(?i)python" } | ForEach-Object { Write-Host "    $_" }
    throw "Python $PythonVersion not found in available runtimes. Choose one from the list above and re-run with -PythonVersion."
}
OK "Runtime string: $runtime"

# --------------------------------------------------------------------------
# Source validation
# --------------------------------------------------------------------------
if (-not (Test-Path $WebdemoSrc)) {
    throw "Web demo source not found: $WebdemoSrc"
}
OK "Source dir   : $WebdemoSrc"

foreach ($mod in $RootModules) {
    if (-not (Test-Path (Join-Path $RepoRoot $mod))) {
        throw "Required Python module not found at repo root: $mod"
    }
}
OK "Root modules : $($RootModules -join ', ')"

# --------------------------------------------------------------------------
# Build deployment package
# --------------------------------------------------------------------------
Step "Building deployment package"

$TmpDir  = Join-Path $env:TEMP "legacy-shield-deploy-$(Get-Random)"
$ZipPath = Join-Path $env:TEMP "legacy-shield-deploy.zip"

New-Item -ItemType Directory -Path $TmpDir | Out-Null

try {
    # Copy-Item with * wildcards has a known PowerShell bug where subdirectory
    # contents are silently dropped. robocopy /E is reliable on all Windows versions.
    # Exit codes 0-7 are success (0=no files, 1=files copied, 3=extra, etc.).
    robocopy "$WebdemoSrc" "$TmpDir" /E /NFL /NDL /NJH /NJS | Out-Null
    if ($LASTEXITCODE -ge 8) {
        throw "robocopy failed (exit $LASTEXITCODE) copying webdemo source."
    }
    OK "Copied webdemo files (incl. static/)"

    foreach ($mod in $RootModules) {
        Copy-Item (Join-Path $RepoRoot $mod) $TmpDir -Force
        OK "Copied $mod"
    }

    # Patch app.py: in the flat package the modules sit next to app.py,
    # so .parent is correct instead of .parents[3].
    $appPy   = Join-Path $TmpDir "app.py"
    $content = Get-Content $appPy -Raw
    $patched = $content -replace '(?<=Path\(__file__\)\.resolve\(\))\.parents\[3\]', '.parent'
    if ($patched -eq $content) {
        Write-Warning "sys.path patch not applied -- pattern not found. Imports may fail."
    } else {
        Set-Content $appPy -Value $patched -NoNewline
        OK "Patched sys.path in app.py (parents[3] -> parent)"
    }

    if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }

    # Windows PowerShell 5.1 uses .NET Framework whose ZipFile::CreateFromDirectory
    # stores entries with backslashes (static\app.js). Linux cannot extract these as
    # a directory. Build the zip manually with forward-slash paths instead.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zipStream = [System.IO.Compression.ZipFile]::Open($ZipPath, 'Create')
    Get-ChildItem -Path $TmpDir -Recurse -File | ForEach-Object {
        $entryName = $_.FullName.Substring($TmpDir.Length + 1) -replace '\\', '/'
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $zipStream, $_.FullName, $entryName,
            [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
    $zipStream.Dispose()
    $zipSizeKB = [math]::Round((Get-Item $ZipPath).Length / 1KB, 1)

    # Verify forward-slash static/ entries exist before uploading
    $zip         = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    $totalCount  = $zip.Entries.Count
    $staticCount = @($zip.Entries | Where-Object { $_.FullName -like "static/*" }).Count
    $allEntries  = $zip.Entries | Select-Object -ExpandProperty FullName
    $zip.Dispose()
    if ($staticCount -eq 0) {
        Write-Host "  Entries in zip:" -ForegroundColor Yellow
        $allEntries | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        throw "static/ still missing after zip rebuild ($totalCount entries). See entries above."
    }
    OK "Package : $ZipPath ($zipSizeKB KB, $staticCount static/ files with forward-slash paths)"

    # --------------------------------------------------------------------------
    # Azure resources  (idempotent -- safe to re-run after partial failures)
    # --------------------------------------------------------------------------
    $planName = "$AppName-plan"

    # Resource group
    Step "Resource group: $ResourceGroup ($Location)"
    $savedPref = $ErrorActionPreference ; $ErrorActionPreference = "Continue"
    $rgJson = az group show --name $ResourceGroup -o json 2>$null | ConvertFrom-Json
    $ErrorActionPreference = $savedPref

    if ($rgJson) {
        $existingLocation = $rgJson.location
        if ($existingLocation -ne $Location) {
            Write-Host "  CONFLICT: resource group exists in '$existingLocation', not '$Location'." -ForegroundColor Red
            Write-Host "  Either delete it first:" -ForegroundColor Yellow
            Write-Host "    az group delete --name $ResourceGroup --yes --no-wait" -ForegroundColor Cyan
            Write-Host "  Or pass a different -ResourceGroup name." -ForegroundColor Yellow
            throw "Resource group location mismatch. See above."
        }
        OK "Resource group already exists -- reusing"
    } else {
        Invoke-Az group create --name $ResourceGroup --location $Location --output none
        OK "Resource group created"
    }

    # App Service Plan
    Step "App Service Plan: $planName ($Sku, Linux)"
    $savedPref = $ErrorActionPreference ; $ErrorActionPreference = "Continue"
    $planJson = az appservice plan show --name $planName --resource-group $ResourceGroup -o json 2>$null | ConvertFrom-Json
    $ErrorActionPreference = $savedPref

    if ($planJson) {
        OK "Plan already exists -- reusing"
    } else {
        Invoke-Az appservice plan create `
            --name           $planName `
            --resource-group $ResourceGroup `
            --location       $Location `
            --sku            $Sku `
            --is-linux `
            --output         none
        OK "Plan created"
    }

    # Web App
    Step "Web App: $AppName"
    $savedPref = $ErrorActionPreference ; $ErrorActionPreference = "Continue"
    $appJson = az webapp show --name $AppName --resource-group $ResourceGroup -o json 2>$null | ConvertFrom-Json
    $ErrorActionPreference = $savedPref

    if ($appJson) {
        OK "Web App already exists -- will redeploy"
    } else {
        Invoke-Az webapp create `
            --name           $AppName `
            --resource-group $ResourceGroup `
            --plan           $planName `
            --runtime        $runtime `
            --output         none
        OK "Web App created (runtime: $runtime)"
    }

    Step "Configuring startup command and app settings"
    Invoke-Az webapp config set `
        --name           $AppName `
        --resource-group $ResourceGroup `
        --startup-file   "uvicorn app:app --host 0.0.0.0 --port 8000" `
        --output         none

    Invoke-Az webapp config appsettings set `
        --name           $AppName `
        --resource-group $ResourceGroup `
        --settings       WEBSITES_PORT=8000 SCM_DO_BUILD_DURING_DEPLOYMENT=true ENABLE_ORYX_BUILD=true PYTHONUNBUFFERED=1 `
        --output         none
    OK "Settings applied"

    # Clear stale Oryx build cache (output.tar.zst) so Azure rebuilds from
    # our new zip rather than reusing a previously cached bad build.
    Step "Clearing Oryx build cache"
    $savedPref = $ErrorActionPreference ; $ErrorActionPreference = "Continue"
    $creds = az webapp deployment list-publishing-credentials `
        --name $AppName --resource-group $ResourceGroup `
        --query "{u:publishingUserName,p:publishingPassword}" -o json |
        ConvertFrom-Json
    $ErrorActionPreference = $savedPref

    if ($creds) {
        $b64  = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($creds.u):$($creds.p)"))
        $kudu = "https://$AppName.scm.azurewebsites.net/api/vfs/site/wwwroot/output.tar.zst"
        try {
            Invoke-WebRequest -Uri $kudu -Method DELETE `
                -Headers @{ Authorization = "Basic $b64" } -ErrorAction Stop | Out-Null
            OK "Removed cached output.tar.zst"
        } catch {
            OK "No cached output.tar.zst to remove (clean slate)"
        }
    }

    Step "Deploying package (this may take 2-3 minutes)"
    $savedPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $deployed = $false
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        Write-Host "    Attempt $attempt of 3..." -ForegroundColor DarkGray
        az webapp deploy `
            --name           $AppName `
            --resource-group $ResourceGroup `
            --src-path       $ZipPath `
            --type           zip `
            --clean          true `
            --restart        true `
            --output         none
        if ($LASTEXITCODE -eq 0) {
            $deployed = $true
            break
        }
        Write-Host "    Attempt $attempt failed (exit $LASTEXITCODE)." -ForegroundColor Yellow
        if ($attempt -lt 3) { Start-Sleep -Seconds 15 }
    }

    $ErrorActionPreference = $savedPref

    if (-not $deployed) {
        throw "Deployment failed after 3 attempts. Stream logs with:`n  az webapp log tail --name $AppName --resource-group $ResourceGroup"
    }
    OK "Deployment complete"

    # --------------------------------------------------------------------------
    # Summary
    # --------------------------------------------------------------------------
    $url = "https://$AppName.azurewebsites.net"
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "  Legacy Shield demo deployed successfully  " -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  URL : $url" -ForegroundColor Yellow
    Write-Host "  App : $AppName"
    Write-Host "  RG  : $ResourceGroup ($Location)"
    Write-Host ""
    Write-Host "  Benchmark runs in a background thread on first request (~30 s)."
    Write-Host "  Subsequent visits use the cached result."
    Write-Host ""
    Write-Host "  Stream logs:"
    Write-Host "    az webapp log tail --name $AppName --resource-group $ResourceGroup"
    Write-Host ""
    Write-Host "  Tear down:"
    Write-Host "    az group delete --name $ResourceGroup --yes --no-wait"
}
finally {
    if (Test-Path $TmpDir) { Remove-Item $TmpDir -Recurse -Force }
}
