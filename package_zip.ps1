$modDir = 'D:\Program Files (x86)\Steam\steamapps\common\SAMURAI SHODOWN V SPECIAL\mod'
$zipPath = 'D:\Program Files (x86)\Steam\steamapps\common\SAMURAI SHODOWN V SPECIAL\SSVS_Mod_Acessibilidade.zip'
$tempDir = Join-Path $env:TEMP 'SSVS_Mod_Distrib'

if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
New-Item -ItemType Directory -Path $tempDir | Out-Null

$requiredFiles = @(
    'SsvsNarrator.exe',
    'Iniciar_Narrador.bat',
    'LEIAME.txt',
    'prism.dll',
    'nvdaControllerClient.dll',
    'SpeechCore.dll',
    'SRAL.dll',
    'tolk.dll',
    'UniversalSpeech.dll'
)

foreach ($file in $requiredFiles) {
    $src = Join-Path $modDir $file
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $tempDir -Force
        Write-Host "Adicionado: $file"
    } else {
        Write-Warning "Arquivo ausente: $file"
    }
}

if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
Compress-Archive -Path "$tempDir\*" -DestinationPath $zipPath -Force
Remove-Item -Recurse -Force $tempDir

Write-Host "ZIP gerado com sucesso: $zipPath"
Get-Item $zipPath | Select-Object Name, Length, LastWriteTime
