# upload.ps1

param (
    [string]$DestinationDir = "downloads_a"
)

# Ensure the destination directory exists
if (-not (Test-Path $DestinationDir)) {
    New-Item -ItemType Directory -Path $DestinationDir | Out-Null
}

# Load Windows Forms to use the file browser GUI
Add-Type -AssemblyName System.Windows.Forms

$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = "Select a file to seed (Upload)"
$dialog.Filter = "All Files (*.*)|*.*"
$dialog.InitialDirectory = [Environment]::GetFolderPath("UserProfile") + "\Downloads"

# Open the dialog and wait for the user to pick a file
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $sourcePath = $dialog.FileName
    Write-Host "`nSelected File: $sourcePath" -ForegroundColor Cyan

    Write-Host "Calculating SHA-256 hash... Please wait."
    $hash = (Get-FileHash -Path $sourcePath -Algorithm SHA256).Hash.ToLower()
    $size = (Get-Item -Path $sourcePath).Length
    
    $destPath = Join-Path -Path $DestinationDir -ChildPath $hash

    # Copy the file to the agent's storage folder with the hash as the name
    Copy-Item -Path $sourcePath -Destination $destPath -Force

    # NEW: Create a metadata sidecar file
    $originalName = Split-Path $sourcePath -Leaf
    $meta = @{ file_name = $originalName }
    $meta | ConvertTo-Json -Depth 1 | Out-File -FilePath "$destPath.meta" -Encoding utf8

    Write-Host "`n--- Upload Complete ---" -ForegroundColor Green
    Write-Host "Hash: $hash"
    Write-Host "Size: $size bytes"
    Write-Host "Path: $destPath"
}
else {
    Write-Host "Upload canceled by user." -ForegroundColor Yellow
}