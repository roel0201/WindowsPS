# CCDC Rapid Tool Downloader
$toolDir = "C:\tools"
if (!(Test-Path $toolDir)) { New-Item -ItemType Directory -Path $toolDir }

$tools = @{
    "PingCastle.zip"  = "https://www.pingcastle.com/edge/PingCastle_Latest.zip"
    "AdFind.zip"      = "http://www.joeware.net/freetools/tools/adfind/adfind.zip"
    "Autoruns.zip"    = "https://download.sysinternals.com/files/Autoruns.zip"
    "TCPView.zip"     = "https://download.sysinternals.com/files/TCPView.zip"
    "ProcessHacker.zip" = "https://github.com/processhacker/processhacker/releases/download/v2.39/processhacker-2.39-setup.exe"
}

Write-Host "--- Starting Tool Download to $toolDir ---" -ForegroundColor Cyan

foreach ($tool in $tools.Keys) {
    $url = $tools[$tool]
    $dest = Join-Path $toolDir $tool
    
    try {
        Write-Host "Downloading $tool..." -NoNewline
        Invoke-WebRequest -Uri $url -OutFile $dest -ErrorAction Stop
        Write-Host " [OK]" -ForegroundColor Green
    }
    catch {
        Write-Host " [FAILED]" -ForegroundColor Red
    }
}

# Unzip everything for immediate use
Get-ChildItem "$toolDir\*.zip" | ForEach-Object {
    $folderName = $_.BaseName
    $targetPath = Join-Path $toolDir $folderName
    if (!(Test-Path $targetPath)) { New-Item -ItemType Directory -Path $targetPath }
    Expand-Archive -Path $_.FullName -DestinationPath $targetPath -Force
    Remove-Item $_.FullName # Clean up the zip
}

Write-Host "--- All Tools Extracted to $toolDir ---" -ForegroundColor Green
