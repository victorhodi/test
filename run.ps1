<#
.SYNOPSIS
    Remote Software Deployment and Execution Script
.DESCRIPTION
    This script facilitates the remote deployment and execution of software on multiple servers.
    It handles connectivity testing, file transfers, software extraction, license deployment,
    scheduled task creation, execution verification, and comprehensive reporting.
.PARAMETER ServerListPath
    Path to a text file containing server names, one per line
.PARAMETER SoftwareZipPath
    Path to the zipped software package
.PARAMETER LicenseFolderPath
    Path to the folder containing license files (named as servername.lic)
.PARAMETER TargetFolderPath
    Path on remote servers where software will be deployed
.PARAMETER LogFolderPath
    Path for storing log files (default: C:\SoftwareDeploymentLogs)
.PARAMETER ReportPath
    Path for the CSV deployment report (default: .\DeploymentReport.csv)
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerListPath,
    
    [Parameter(Mandatory=$true)]
    [string]$SoftwareZipPath,
    
    [Parameter(Mandatory=$true)]
    [string]$LicenseFolderPath,
    
    [Parameter(Mandatory=$true)]
    [string]$TargetFolderPath,
    
    [Parameter(Mandatory=$false)]
    [string]$LogFolderPath = "C:\SoftwareDeploymentLogs",
    
    [Parameter(Mandatory=$false)]
    [string]$ReportPath = ".\DeploymentReport.csv"
)

#region Functions

# Initialize logging
function Initialize-Logging {
    if (-not (Test-Path -Path $LogFolderPath)) {
        New-Item -Path $LogFolderPath -ItemType Directory -Force | Out-Null
    }
    
    $logFile = Join-Path -Path $LogFolderPath -ChildPath "Deployment_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    return $logFile
}

# Write log entry
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$true)]
        [string]$LogFile,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] - $Message"
    
    Add-Content -Path $LogFile -Value $logEntry
    
    switch ($Level) {
        "INFO" { Write-Host $logEntry -ForegroundColor Green }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
    }
}

# Test server connectivity using different methods
function Test-ServerConnectivity {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServerName,
        
        [Parameter(Mandatory=$true)]
        [string]$LogFile
    )
    
    try {
        Write-Log -Message "Testing connectivity to server: $ServerName" -LogFile $LogFile
        
        # Initialize result object
        $result = [PSCustomObject]@{
            ServerName = $ServerName
            IsAccessible = $false
            IsWindows = $false
            ConnectionMethod = $null
            ErrorMessage = $null
        }
        
        # Try ping first with retry for unstable networks
        $pingSuccess = $false
        $retryCount = 3
        
        for ($i = 1; $i -le $retryCount; $i++) {
            $pingResult = Test-Connection -ComputerName $ServerName -Count 1 -Quiet -ErrorAction SilentlyContinue
            
            if ($pingResult) {
                $pingSuccess = $true
                break
            }
            
            Write-Log -Message "Ping attempt $i of $retryCount failed for $ServerName, retrying..." -LogFile $LogFile -Level "WARNING"
            Start-Sleep -Seconds 2
        }
        
        if (-not $pingSuccess) {
            $result.ErrorMessage = "Server not responding to ping after $retryCount attempts"
            return $result
        }
        
        # Try WinRM (Windows Remote Management)
        $winrmTest = $null
        try {
            $winrmTest = Test-WSMan -ComputerName $ServerName -ErrorAction SilentlyContinue
        }
        catch {
            # WinRM test failed, continue to other methods
        }
        
        if ($winrmTest) {
            $result.IsAccessible = $true
            $result.IsWindows = $true
            $result.ConnectionMethod = "WinRM"
            Write-Log -Message "Server $ServerName is accessible via WinRM" -LogFile $LogFile
            return $result
        }
        
        # Try SMB (File Sharing)
        $smbPath = "\\$ServerName\C$"
        $smbTest = Test-Path -Path $smbPath -ErrorAction SilentlyContinue
        
        if ($smbTest) {
            $result.IsAccessible = $true
            $result.IsWindows = $true
            $result.ConnectionMethod = "SMB"
            Write-Log -Message "Server $ServerName is accessible via SMB" -LogFile $LogFile
            return $result
        }
        
        # Try SSH (for Linux servers)
        if (Get-Command -Name "ssh" -ErrorAction SilentlyContinue) {
            try {
                $sshResult = & ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no $ServerName "uname -a" 2>&1
                
                if ($LASTEXITCODE -eq 0) {
                    $result.IsAccessible = $true
                    $result.IsWindows = $false
                    $result.ConnectionMethod = "SSH"
                    Write-Log -Message "Server $ServerName is accessible via SSH (Linux)" -LogFile $LogFile
                    return $result
                }
            }
            catch {
                # SSH failed, continue to other methods
            }
        }
        
        # If we reach here and haven't established connectivity, server is inaccessible
        $result.ErrorMessage = "Unable to establish connectivity via WinRM, SMB, or SSH"
        Write-Log -Message "Server $ServerName is not accessible via any tested method" -LogFile $LogFile -Level "WARNING"
        return $result
    }
    catch {
        $result.ErrorMessage = "Error testing connectivity: $_"
        Write-Log -Message "Error testing connectivity to $ServerName: $_" -LogFile $LogFile -Level "ERROR"
        return $result
    }
}

# Copy software package to target server
function Copy-SoftwarePackage {
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$ServerInfo,
        
        [Parameter(Mandatory=$true)]
        [string]$SoftwareZipPath,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetFolderPath,
        
        [Parameter(Mandatory=$true)]
        [string]$LogFile
    )
    
    try {
        Write-Log -Message "Copying software package to server: $($ServerInfo.ServerName)" -LogFile $LogFile
        
        $result = [PSCustomObject]@{
            Success = $false
            ErrorMessage = $null
        }
        
        # Only process Windows servers
        if (-not $ServerInfo.IsWindows) {
            $result.ErrorMessage = "Server is Linux, deployment not supported for this script"
            Write-Log -Message "Server $($ServerInfo.ServerName) is Linux, deployment not supported" -LogFile $LogFile -Level "WARNING"
            return $result
        }
        
        # Create target folder if it doesn't exist
        $remotePath = "\\$($ServerInfo.ServerName)\$($TargetFolderPath.Replace(':', '$'))"
        
        if (-not (Test-Path -Path $remotePath -ErrorAction SilentlyContinue)) {
            try {
                if ($ServerInfo.ConnectionMethod -eq "SMB") {
                    # Create folder via SMB
                    New-Item -Path $remotePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
                }
                elseif ($ServerInfo.ConnectionMethod -eq "WinRM") {
                    # Create folder via WinRM
                    Invoke-Command -ComputerName $ServerInfo.ServerName -ScriptBlock {
                        param($path)
                        if (-not (Test-Path -Path $path)) {
                            New-Item -Path $path -ItemType Directory -Force | Out-Null
                        }
                    } -ArgumentList $TargetFolderPath -ErrorAction Stop
                }
            }
            catch {
                $result.ErrorMessage = "Failed to create target folder: $_"
                Write-Log -Message "Failed to create target folder on $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
                return $result
            }
        }
        
        # Copy software package
        $fileName = Split-Path -Path $SoftwareZipPath -Leaf
        $destinationPath = Join-Path -Path $remotePath -ChildPath $fileName
        
        try {
            if ($ServerInfo.ConnectionMethod -eq "SMB") {
                # Copy via SMB with retry for network instability
                $retryCount = 3
                $success = $false
                
                for ($i = 1; $i -le $retryCount; $i++) {
                    try {
                        Copy-Item -Path $SoftwareZipPath -Destination $destinationPath -Force -ErrorAction Stop
                        $success = $true
                        break
                    }
                    catch {
                        Write-Log -Message "Copy attempt $i of $retryCount failed: $_" -LogFile $LogFile -Level "WARNING"
                        Start-Sleep -Seconds 5
                    }
                }
                
                if (-not $success) {
                    throw "Failed to copy file after $retryCount attempts"
                }
            }
            elseif ($ServerInfo.ConnectionMethod -eq "WinRM") {
                # For WinRM, use a more efficient approach for file transfer
                Invoke-Command -ComputerName $ServerInfo.ServerName -ScriptBlock {
                    param($sourceServer, $sourcePath, $destPath)
                    
                    $sourceUNC = "\\$sourceServer\$($sourcePath.Replace(':', '$'))"
                    Copy-Item -Path $sourceUNC -Destination $destPath -Force
                } -ArgumentList $env:COMPUTERNAME, $SoftwareZipPath, (Join-Path -Path $TargetFolderPath -ChildPath $fileName) -ErrorAction Stop
            }
            
            $result.Success = $true
            Write-Log -Message "Successfully copied software package to $($ServerInfo.ServerName)" -LogFile $LogFile
            return $result
        }
        catch {
            $result.ErrorMessage = "Failed to copy software package: $_"
            Write-Log -Message "Failed to copy software package to $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
            return $result
        }
    }
    catch {
        $result.ErrorMessage = "Unexpected error copying software package: $_"
        Write-Log -Message "Unexpected error copying software package to $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
        return $result
    }
}

# Extract software package on target server
function Extract-SoftwarePackage {
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$ServerInfo,
        
        [Parameter(Mandatory=$true)]
        [string]$SoftwareZipPath,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetFolderPath,
        
        [Parameter(Mandatory=$true)]
        [string]$LogFile
    )
    
    try {
        Write-Log -Message "Extracting software package on server: $($ServerInfo.ServerName)" -LogFile $LogFile
        
        $result = [PSCustomObject]@{
            Success = $false
            ExtractedFolderPath = $null
            ErrorMessage = $null
        }
        
        $fileName = Split-Path -Path $SoftwareZipPath -Leaf
        $targetZipPath = Join-Path -Path $TargetFolderPath -ChildPath $fileName
        $extractedFolderName = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
        $extractedFolderPath = Join-Path -Path $TargetFolderPath -ChildPath $extractedFolderName
        
        $result.ExtractedFolderPath = $extractedFolderPath
        
        try {
            if ($ServerInfo.ConnectionMethod -eq "WinRM") {
                # Extract via WinRM
                Invoke-Command -ComputerName $ServerInfo.ServerName -ScriptBlock {
                    param($zipPath, $extractPath)
                    
                    # Create the extraction folder if it doesn't exist
                    if (-not (Test-Path -Path $extractPath)) {
                        New-Item -Path $extractPath -ItemType Directory -Force | Out-Null
                    }
                    
                    # Extract the zip file
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    try {
                        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractPath)
                    }
                    catch {
                        # If directory already exists, try to extract file by file
                        $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
                        foreach($entry in $zip.Entries) {
                            $entryTargetPath = [System.IO.Path]::Combine($extractPath, $entry.FullName)
                            $entryDir = [System.IO.Path]::GetDirectoryName($entryTargetPath)
                            
                            if(!(Test-Path $entryDir)) {
                                New-Item -ItemType Directory -Path $entryDir -Force | Out-Null
                            }
                            
                            if(!$entry.FullName.EndsWith('/')) {
                                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $entryTargetPath, $true)
                            }
                        }
                        $zip.Dispose()
                    }
                } -ArgumentList $targetZipPath, $extractedFolderPath -ErrorAction Stop
            }
            elseif ($ServerInfo.ConnectionMethod -eq "SMB") {
                # Extract via local PowerShell and SMB
                $remotePath = "\\$($ServerInfo.ServerName)\$($TargetFolderPath.Replace(':', '$'))"
                $remoteZipPath = Join-Path -Path $remotePath -ChildPath $fileName
                $remoteExtractPath = Join-Path -Path $remotePath -ChildPath $extractedFolderName
                
                # Create the extraction folder if it doesn't exist
                if (-not (Test-Path -Path $remoteExtractPath)) {
                    New-Item -Path $remoteExtractPath -ItemType Directory -Force | Out-Null
                }
                
                # Extract the zip file
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                try {
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($remoteZipPath, $remoteExtractPath)
                }
                catch {
                    # If directory already exists, try to extract file by file
                    $zip = [System.IO.Compression.ZipFile]::OpenRead($remoteZipPath)
                    foreach($entry in $zip.Entries) {
                        $entryTargetPath = [System.IO.Path]::Combine($remoteExtractPath, $entry.FullName)
                        $entryDir = [System.IO.Path]::GetDirectoryName($entryTargetPath)
                        
                        if(!(Test-Path $entryDir)) {
                            New-Item -ItemType Directory -Path $entryDir -Force | Out-Null
                        }
                        
                        if(!$entry.FullName.EndsWith('/')) {
                            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $entryTargetPath, $true)
                        }
                    }
                    $zip.Dispose()
                }
            }
            
            $result.Success = $true
            Write-Log -Message "Successfully extracted software package on $($ServerInfo.ServerName)" -LogFile $LogFile
            return $result
        }
        catch {
            $result.ErrorMessage = "Failed to extract software package: $_"
            Write-Log -Message "Failed to extract software package on $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
            return $result
        }
    }
    catch {
        $result.ErrorMessage = "Unexpected error extracting software package: $_"
        Write-Log -Message "Unexpected error extracting software package on $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
        return $result
    }
}

# Copy license file to target server
function Copy-LicenseFile {
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$ServerInfo,
        
        [Parameter(Mandatory=$true)]
        [string]$LicenseFolderPath,
        
        [Parameter(Mandatory=$true)]
        [string]$ExtractedFolderPath,
        
        [Parameter(Mandatory=$true)]
        [string]$LogFile
    )
    
    try {
        Write-Log -Message "Copying license file for server: $($ServerInfo.ServerName)" -LogFile $LogFile
        
        $result = [PSCustomObject]@{
            Success = $false
            ErrorMessage = $null
        }
        
        # Look for a license file matching the server name
        $serverName = $ServerInfo.ServerName
        $licenseFileName = "$serverName.lic"
        $licensePath = Join-Path -Path $LicenseFolderPath -ChildPath $licenseFileName
        
        if (-not (Test-Path -Path $licensePath)) {
            $result.ErrorMessage = "License file not found for server $serverName"
            Write-Log -Message "License file not found for server $serverName" -LogFile $LogFile -Level "ERROR"
            return $result
        }
        
        try {
            if ($ServerInfo.ConnectionMethod -eq "WinRM") {
                # Copy license via WinRM
                $licenseDest = Join-Path -Path $ExtractedFolderPath -ChildPath "license.lic"
                
                Invoke-Command -ComputerName $ServerInfo.ServerName -ScriptBlock {
                    param($sourceLicense, $destLicense, $sourceServer)
                    
                    $sourceUNC = "\\$sourceServer\$($sourceLicense.Replace(':', '$'))"
                    Copy-Item -Path $sourceUNC -Destination $destLicense -Force
                } -ArgumentList $licensePath, $licenseDest, $env:COMPUTERNAME -ErrorAction Stop
            }
            elseif ($ServerInfo.ConnectionMethod -eq "SMB") {
                # Copy license via SMB
                $remoteExtractPath = "\\$($ServerInfo.ServerName)\$($ExtractedFolderPath.Replace(':', '$'))"
                $remoteLicensePath = Join-Path -Path $remoteExtractPath -ChildPath "license.lic"
                Copy-Item -Path $licensePath -Destination $remoteLicensePath -Force -ErrorAction Stop
            }
            
            $result.Success = $true
            Write-Log -Message "Successfully copied license file to $($ServerInfo.ServerName)" -LogFile $LogFile
            return $result
        }
        catch {
            $result.ErrorMessage = "Failed to copy license file: $_"
            Write-Log -Message "Failed to copy license file to $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
            return $result
        }
    }
    catch {
        $result.ErrorMessage = "Unexpected error copying license file: $_"
        Write-Log -Message "Unexpected error copying license file to $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
        return $result
    }
}

# Create scheduled task to run the software as SYSTEM
function Create-ScheduledTask {
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$ServerInfo,
        
        [Parameter(Mandatory=$true)]
        [string]$ExtractedFolderPath,
        
        [Parameter(Mandatory=$true)]
        [string]$LogFile
    )
    
    try {
        Write-Log -Message "Creating scheduled task on server: $($ServerInfo.ServerName)" -LogFile $LogFile
        
        $result = [PSCustomObject]@{
            Success = $false
            TaskName = $null
            ErrorMessage = $null
        }
        
        # Define task name - use a unique name based on timestamp
        $taskName = "SoftwareExecution_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $result.TaskName = $taskName
        
        # Assume executable is named "application.exe" in the extracted folder
        $executablePath = Join-Path -Path $ExtractedFolderPath -ChildPath "application.exe"
        
        try {
            if ($ServerInfo.ConnectionMethod -eq "WinRM") {
                # Verify all files are in place first
                $filesReady = Invoke-Command -ComputerName $ServerInfo.ServerName -ScriptBlock {
                    param($exePath, $licPath)
                    
                    $exeExists = Test-Path -Path $exePath
                    $licExists = Test-Path -Path $licPath
                    
                    return @{
                        ExeExists = $exeExists
                        LicExists = $licExists
                    }
                } -ArgumentList $executablePath, (Join-Path -Path $ExtractedFolderPath -ChildPath "license.lic") -ErrorAction Stop
                
                if (-not $filesReady.ExeExists) {
                    throw "Application executable not found at: $executablePath"
                }
                
                if (-not $filesReady.LicExists) {
                    throw "License file not found in extracted folder"
                }
                
                # Create scheduled task via WinRM
                Invoke-Command -ComputerName $ServerInfo.ServerName -ScriptBlock {
                    param($taskName, $exePath)
                    
                    # Create a scheduled task that runs as SYSTEM
                    $action = New-ScheduledTaskAction -Execute $exePath
                    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -AllowStartIfOnBatteries
                    
                    # Register the task
                    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force
                } -ArgumentList $taskName, $executablePath -ErrorAction Stop
            }
            elseif ($ServerInfo.ConnectionMethod -eq "SMB") {
                # Verify all files are in place first
                $remoteExePath = "\\$($ServerInfo.ServerName)\$($executablePath.Replace(':', '$'))"
                $remoteLicPath = "\\$($ServerInfo.ServerName)\$($ExtractedFolderPath.Replace(':', '$'))\license.lic"
                
                if (-not (Test-Path -Path $remoteExePath)) {
                    throw "Application executable not found at: $remoteExePath"
                }
                
                if (-not (Test-Path -Path $remoteLicPath)) {
                    throw "License file not found at: $remoteLicPath"
                }
                
                # Create scheduled task via SCHTASKS.EXE
                $schTasksCmd = "schtasks.exe /create /s $($ServerInfo.ServerName) /tn `"$taskName`" /tr `"$executablePath`" /sc ONCE /st 00:00 /ru SYSTEM /f"
                $schTasksResult = Invoke-Expression -Command $schTasksCmd -ErrorAction Stop
                
                if ($LASTEXITCODE -ne 0) {
                    throw "SCHTASKS.EXE returned error code $LASTEXITCODE : $schTasksResult"
                }
            }
            
            $result.Success = $true
            Write-Log -Message "Successfully created scheduled task '$taskName' on $($ServerInfo.ServerName)" -LogFile $LogFile
            return $result
        }
        catch {
            $result.ErrorMessage = "Failed to create scheduled task: $_"
            Write-Log -Message "Failed to create scheduled task on $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
            return $result
        }
    }
    catch {
        $result.ErrorMessage = "Unexpected error creating scheduled task: $_"
        Write-Log -Message "Unexpected error creating scheduled task on $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
        return $result
    }
}

# Execute the scheduled task
function Execute-ScheduledTask {
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$ServerInfo,
        
        [Parameter(Mandatory=$true)]
        [string]$TaskName,
        
        [Parameter(Mandatory=$true)]
        [string]$LogFile
    )
    
    try {
        Write-Log -Message "Executing scheduled task on server: $($ServerInfo.ServerName)" -LogFile $LogFile
        
        $result = [PSCustomObject]@{
            Success = $false
            ErrorMessage = $null
        }
        
        try {
            if ($ServerInfo.ConnectionMethod -eq "WinRM") {
                # Run scheduled task via WinRM
                Invoke-Command -ComputerName $ServerInfo.ServerName -ScriptBlock {
                    param($taskName)
                    Start-ScheduledTask -TaskName $taskName
                } -ArgumentList $TaskName -ErrorAction Stop
            }
            elseif ($ServerInfo.ConnectionMethod -eq "SMB") {
                # Run scheduled task via SCHTASKS.EXE
                $schTasksCmd = "schtasks.exe /run /s $($ServerInfo.ServerName) /tn `"$TaskName`""
                $schTasksResult = Invoke-Expression -Command $schTasksCmd -ErrorAction Stop
                
                if ($LASTEXITCODE -ne 0) {
                    throw "SCHTASKS.EXE returned error code $LASTEXITCODE : $schTasksResult"
                }
            }
            
            # Wait a moment for the task to start
            Start-Sleep -Seconds 5
            
            $result.Success = $true
            Write-Log -Message "Successfully executed scheduled task on $($ServerInfo.ServerName)" -LogFile $LogFile
            return $result
        }
        catch {
            $result.ErrorMessage = "Failed to execute scheduled task: $_"
            Write-Log -Message "Failed to execute scheduled task on $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
            return $result
        }
    }
    catch {
        $result.ErrorMessage = "Unexpected error executing scheduled task: $_"
        Write-Log -Message "Unexpected error executing scheduled task on $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
        return $result
    }
}

# Verify software execution by checking logs
function Verify-SoftwareExecution {
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$ServerInfo,
        
        [Parameter(Mandatory=$true)]
        [string]$ExtractedFolderPath,
        
        [Parameter(Mandatory=$true)]
        [string]$LogFile
    )
    
    try {
        Write-Log -Message "Verifying software execution on server: $($ServerInfo.ServerName)" -LogFile $LogFile
        
        $result = [PSCustomObject]@{
            Success = $false
            ErrorMessage = $null
        }
        
        # Assume log file is in a "logs" subfolder of the extracted folder
        $softwareLogPath = Join-Path -Path $ExtractedFolderPath -ChildPath "logs\application.log"
        
        # Wait for the software to create logs - with retry
        $logFound = $false
        $maxRetries = 6
        $retryDelay = 10
        
        for ($i = 1; $i -le $maxRetries; $i++) {
            Write-Log -Message "Log check attempt $i of $maxRetries" -LogFile $LogFile
            
            try {
                if ($ServerInfo.ConnectionMethod -eq "WinRM") {
                    # Check for log file via WinRM
                    $logExists = Invoke-Command -ComputerName $ServerInfo.ServerName -ScriptBlock {
                        param($logPath)
                        Test-Path -Path $logPath
                    } -ArgumentList $softwareLogPath -ErrorAction Stop
                    
                    if ($logExists) {
                        $logFound = $true
                        break
                    }
                }
                elseif ($ServerInfo.ConnectionMethod -eq "SMB") {
                    # Check for log file via SMB
                    $remoteLogPath = "\\$($ServerInfo.ServerName)\$($softwareLogPath.Replace(':', '$'))"
                    
                    if (Test-Path -Path $remoteLogPath -ErrorAction SilentlyContinue) {
                        $logFound = $true
                        break
                    }
                }
            }
            catch {
                Write-Log -Message "Error checking for log file (attempt $i): $_" -LogFile $LogFile -Level "WARNING"
            }
            
            Write-Log -Message "Waiting $retryDelay seconds for log file to appear (attempt $i of $maxRetries)..." -LogFile $LogFile
            Start-Sleep -Seconds $retryDelay
        }
        
        if (-not $logFound) {
            $result.ErrorMessage = "Software log file not found after $maxRetries attempts"
            Write-Log -Message "Software log file not found on $($ServerInfo.ServerName) after $maxRetries attempts" -LogFile $LogFile -Level "ERROR"
            return $result
        }
        
        # Check log content for errors
        try {
            $logHasErrors = $false
            
            if ($ServerInfo.ConnectionMethod -eq "WinRM") {
                $logHasErrors = Invoke-Command -ComputerName $ServerInfo.ServerName -ScriptBlock {
                    param($logPath)
                    
                    $logContent = Get-Content -Path $logPath -Raw
                    return $logContent -match "error|exception|failure"
                } -ArgumentList $softwareLogPath -ErrorAction Stop
            }
            elseif ($ServerInfo.ConnectionMethod -eq "SMB") {
                $remoteLogPath = "\\$($ServerInfo.ServerName)\$($softwareLogPath.Replace(':', '$'))"
                $logContent = Get-Content -Path $remoteLogPath -Raw -ErrorAction SilentlyContinue
                $logHasErrors = $logContent -match "error|exception|failure"
            }
            
            if ($logHasErrors) {
                $result.ErrorMessage = "Software log contains errors"
                Write-Log -Message "Software log contains errors on $($ServerInfo.ServerName)" -LogFile $LogFile -Level "WARNING"
                return $result
            }
            
            $result.Success = $true
            Write-Log -Message "Successfully verified software execution on $($ServerInfo.ServerName)" -LogFile $LogFile
            return $result
        }
        catch {
            $result.ErrorMessage = "Error analyzing log content: $_"
            Write-Log -Message "Error analyzing log content on $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
            return $result
        }
    }
    catch {
        $result.ErrorMessage = "Unexpected error verifying software execution: $_"
        Write-Log -Message "Unexpected error verifying software execution on $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
        return $result
    }
}

# Remove the scheduled task
function Remove-ScheduledTaskSafely {
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$ServerInfo,
        
        [Parameter(Mandatory=$true)]
        [string]$TaskName,
        
        [Parameter(Mandatory=$true)]
        [string]$LogFile
    )
    
    try {
        Write-Log -Message "Removing scheduled task from server: $($ServerInfo.ServerName)" -LogFile $LogFile
        
        $result = [PSCustomObject]@{
            Success = $false
            ErrorMessage = $null
        }
        
        try {
            if ($ServerInfo.ConnectionMethod -eq "WinRM") {
                # Check task state first to ensure it's not running
                $taskState = Invoke-Command -ComputerName $ServerInfo.ServerName -ScriptBlock {
                    param($taskName)
                    
                    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                    if ($task) {
                        return $task.State
                    }
                    return $null
                } -ArgumentList $TaskName -ErrorAction Stop
                
                # If task is running, wait a moment
                if ($taskState -eq "Running") {
                    Write-Log -Message "Task is still running, waiting before removal..." -LogFile $LogFile
                    Start-Sleep -Seconds 10
                }
                
                # Remove scheduled task via WinRM
                Invoke-Command -ComputerName $ServerInfo.ServerName -ScriptBlock {
                    param($taskName)
                    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                } -ArgumentList $TaskName -ErrorAction Stop
            }
            elseif ($ServerInfo.ConnectionMethod -eq "SMB") {
                # Try to check task state using SCHTASKS.EXE
                $schTasksQueryCmd = "schtasks.exe /query /s $($ServerInfo.ServerName) /tn `"$TaskName`" /fo CSV"
                $taskQueryResult = Invoke-Expression -Command $schTasksQueryCmd -ErrorAction SilentlyContinue
                
                # If task exists and might be running, wait a moment
                if ($LASTEXITCODE -eq 0 -and $taskQueryResult -match "Running") {
                    Write-Log -Message "Task might be running, waiting before removal..." -LogFile $LogFile
                    Start-Sleep -Seconds 10
                }
                
                # Remove scheduled task via SCHTASKS.EXE
                $schTasksCmd = "schtasks.exe /delete /s $($ServerInfo.ServerName) /tn `"$TaskName`" /f"
                $schTasksResult = Invoke-Expression -Command $schTasksCmd -ErrorAction Stop
                
                if ($LASTEXITCODE -ne 0) {
                    throw "SCHTASKS.EXE returned error code $LASTEXITCODE : $schTasksResult"
                }
            }
            
            $result.Success = $true
            Write-Log -Message "Successfully removed scheduled task from $($ServerInfo.ServerName)" -LogFile $LogFile
            return $result
        }
        catch {
            $result.ErrorMessage = "Failed to remove scheduled task: $_"
            Write-Log -Message "Failed to remove scheduled task from $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
            return $result
        }
    }
    catch {
        $result.ErrorMessage = "Unexpected error removing scheduled task: $_"
        Write-Log -Message "Unexpected error removing scheduled task from $($ServerInfo.ServerName): $_" -LogFile $LogFile -Level "ERROR"
        return $result
    }
}

#endregion

#region Main Script

# Main function
function Start-SoftwareDeployment {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ServerListPath,
        
        [Parameter(Mandatory=$true)]
        [string]$SoftwareZipPath,
        
        [Parameter(Mandatory=$true)]
        [string]$LicenseFolderPath,
        
        [Parameter(Mandatory=$true)]
        [string]$TargetFolderPath,
        
        [Parameter(Mandatory=$true)]
        [string]$LogFile,
        
        [Parameter(Mandatory=$true)]
        [string]$ReportPath
    )
    
    try {
        Write-Log -Message "Starting software deployment process" -LogFile $LogFile
        
        # Validate input files and folders
        if (-not (Test-Path -Path $ServerListPath)) {
            Write-Log -Message "Server list file not found: $ServerListPath" -LogFile $LogFile -Level "ERROR"
            return
        }
        
        if (-not (Test-Path -Path $SoftwareZipPath)) {
            Write-Log -Message "Software zip file not found: $SoftwareZipPath" -LogFile $LogFile -Level "ERROR"
            return
        }
        
        if (-not (Test-Path -Path $LicenseFolderPath)) {
            Write-Log -Message "License folder not found: $LicenseFolderPath" -LogFile $LogFile -Level "ERROR"
            return
        }
        
        # Read server list
        $servers = Get-Content -Path $ServerListPath | Where-Object { $_ -and (-not $_.StartsWith('#')) }
        Write-Log -Message "Found $($servers.Count) servers in the list" -LogFile $LogFile
        
        # Deployment results
        $deploymentResults = @()
        
        # Test connectivity to all servers
        $accessibleServers = @()
        foreach ($server in $servers) {
            $connectivityResult = Test-ServerConnectivity -ServerName $server -LogFile $LogFile
            
            $deploymentResult = [PSCustomObject]@{
                ServerName = $server
                IsAccessible = $connectivityResult.IsAccessible
                IsWindows = $connectivityResult.IsWindows
                ConnectionMethod = $connectivityResult.ConnectionMethod
                CopyStatus = "Not Started"
                ExtractStatus = "Not Started"
                LicenseStatus = "Not Started"
                TaskCreationStatus = "Not Started"
                ExecutionStatus = "Not Started"
                VerificationStatus = "Not Started"
                TaskRemovalStatus = "Not Started"
                ErrorDetails = $connectivityResult.ErrorMessage
            }
            
            if ($connectivityResult.IsAccessible -and $connectivityResult.IsWindows) {
                $accessibleServers += $connectivityResult
            }
            
            $deploymentResults += $deploymentResult
        }
        
        Write-Log -Message "Found $($accessibleServers.Count) accessible Windows servers" -LogFile $LogFile
        
        # Deploy software to each accessible server
        foreach ($serverInfo in $accessibleServers) {
            $serverName = $serverInfo.ServerName
            Write-Log -Message "Starting deployment to server: $serverName" -LogFile $LogFile
            
            $deploymentResult = $deploymentResults | Where-Object { $_.ServerName -eq $serverName }
            
            # Copy software package
            $copyResult = Copy-SoftwarePackage -ServerInfo $serverInfo -SoftwareZipPath $SoftwareZipPath -TargetFolderPath $TargetFolderPath -LogFile $LogFile
            
            if ($copyResult.Success) {
                $deploymentResult.CopyStatus = "Success"
                
                # Extract software package
                $extractResult = Extract-SoftwarePackage -ServerInfo $serverInfo -SoftwareZipPath $SoftwareZipPath -TargetFolderPath $TargetFolderPath -LogFile $LogFile
                
                if ($extractResult.Success) {
                    $deploymentResult.ExtractStatus = "Success"
                    $extractedFolderPath = $extractResult.ExtractedFolderPath
                    
                    # Copy license file
                    $licenseResult = Copy-LicenseFile -ServerInfo $serverInfo -LicenseFolderPath $LicenseFolderPath -ExtractedFolderPath $extractedFolderPath -LogFile $LogFile
                    
                    if ($licenseResult.Success) {
                        $deploymentResult.LicenseStatus = "Success"
                        
                        # Create scheduled task
                        $taskResult = Create-ScheduledTask -ServerInfo $serverInfo -ExtractedFolderPath $extractedFolderPath -LogFile $LogFile
                        
                        if ($taskResult.Success) {
                            $deploymentResult.TaskCreationStatus = "Success"
                            $taskName = $taskResult.TaskName
                            
                            # Execute scheduled task
                            $executeResult = Execute-ScheduledTask -ServerInfo $serverInfo -TaskName $taskName -LogFile $LogFile
                            
                            if ($executeResult.Success) {
                                $deploymentResult.ExecutionStatus = "Success"
                                
                                # Verify software execution
                                $verifyResult = Verify-SoftwareExecution -ServerInfo $serverInfo -ExtractedFolderPath $extractedFolderPath -LogFile $LogFile
                                
                                if ($verifyResult.Success) {
                                    $deploymentResult.VerificationStatus = "Success"
                                }
                                else {
                                    $deploymentResult.VerificationStatus = "Failed"
                                    $deploymentResult.ErrorDetails = $verifyResult.ErrorMessage
                                }
                                
                                # Remove scheduled task
                                $removeResult = Remove-ScheduledTaskSafely -ServerInfo $serverInfo -TaskName $taskName -LogFile $LogFile
                                
                                if ($removeResult.Success) {
                                    $deploymentResult.TaskRemovalStatus = "Success"
                                }
                                else {
                                    $deploymentResult.TaskRemovalStatus = "Failed"
                                    $deploymentResult.ErrorDetails = $removeResult.ErrorMessage
                                }
                            }
                            else {
                                $deploymentResult.ExecutionStatus = "Failed"
                                $deploymentResult.ErrorDetails = $executeResult.ErrorMessage
                            }
                        }
                        else {
                            $deploymentResult.TaskCreationStatus = "Failed"
                            $deploymentResult.ErrorDetails = $taskResult.ErrorMessage
                        }
                    }
                    else {
                        $deploymentResult.LicenseStatus = "Failed"
                        $deploymentResult.ErrorDetails = $licenseResult.ErrorMessage
                    }
                }
                else {
                    $deploymentResult.ExtractStatus = "Failed"
                    $deploymentResult.ErrorDetails = $extractResult.ErrorMessage
                }
            }
            else {
                $deploymentResult.CopyStatus = "Failed"
                $deploymentResult.ErrorDetails = $copyResult.ErrorMessage
            }
        }
        
        # Export results to CSV
        $deploymentResults | Export-Csv -Path $ReportPath -NoTypeInformation
        Write-Log -Message "Deployment results exported to: $ReportPath" -LogFile $LogFile
        
        Write-Log -Message "Software deployment process completed" -LogFile $LogFile
    }
    catch {
        Write-Log -Message "Error in deployment process: $_" -LogFile $LogFile -Level "ERROR"
    }
}

# Main script execution
try {
    $logFile = Initialize-Logging
    
    Write-Log -Message "Starting Remote Software Deployment Script" -LogFile $logFile
    
    # Start the deployment process
    Start-SoftwareDeployment -ServerListPath $ServerListPath -SoftwareZipPath $SoftwareZipPath -LicenseFolderPath $LicenseFolderPath -TargetFolderPath $TargetFolderPath -LogFile $logFile -ReportPath $ReportPath
    
    Write-Log -Message "Script execution completed" -LogFile $logFile
}
catch {
    if ($logFile) {
        Write-Log -Message "Critical error in script execution: $_" -LogFile $logFile -Level "ERROR"
    }
    else {
        Write-Error "Critical error in script execution: $_"
    }
}

#endregion
