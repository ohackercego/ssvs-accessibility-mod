$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$fw   = "C:\Windows\Microsoft.NET\Framework\v4.0.30319"
$csc  = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (!(Test-Path -LiteralPath $csc)) { $csc = Join-Path $fw "csc.exe" }

$src = Join-Path $here "SsvsNarrator.cs"
$out = Join-Path $here "SsvsNarrator.exe"

& $csc /nologo /noconfig /target:exe /platform:x64 /optimize+ /out:"$out" `
    /reference:"$fw\System.dll" `
    /reference:"$fw\System.Core.dll" `
    /reference:"$fw\System.Windows.Forms.dll" `
    /reference:"$fw\System.Drawing.dll" `
    "$src"

if ($LASTEXITCODE -ne 0) { throw "compile failed (exit $LASTEXITCODE)" }

$prismBin = Join-Path $here "prism\prism-sdk-v0.18.3\windows\x64\dynamic\release\bin"
if (Test-Path -LiteralPath $prismBin) {
    Copy-Item (Join-Path $prismBin "*.*") -Destination $here -Force
}

$client = "C:\Users\azure\AppData\Local\Temp\opencode\ssvs\nvdaClient\x64\nvdaControllerClient.dll"
$dest   = Join-Path $here "nvdaControllerClient.dll"
if (Test-Path -LiteralPath $client) {
    Copy-Item -LiteralPath $client -Destination $dest -Force
}

Write-Host "built : $out (x64 with Prism)"
