

#Find if PS Module Folder is in the Path 
$moduleDirPath = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Modules"
$myDocumentsModuleFolderIsInPSModulePath = $false
$env:PSModulePath -Split ';' | % {
  if ($_.ToLower() -eq ($moduleDirPath).ToLower()){
    $myDocumentsModuleFolderIsInPSModulePath = $true
  }
}
#If Not add it to the path 
if(-not $myDocumentsModuleFolderIsInPSModulePath){
  $newPSModulePath = $env:PSModulePath + ";" + $moduleDirPath ;
  [Environment]::SetEnvironmentVariable("PSModulePath",$newPSModulePath, "Process")
  [Environment]::SetEnvironmentVariable("PSModulePath",$newPSModulePath, "User")
}

#find location where this install script is stored
$filesDirPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
#and the destimation path for the module

$modulePath = $moduleDirPath + "\AADGraph"

if (Test-Path $modulePath)
{    
    #give upgrade notice
    Write-Host "Removing existing module directory under "$moduleDirPath -ForegroundColor Green
    Remove-Item -Path $modulePath -Recurse -Force | Out-Null
}

Write-Host "Creating module directory under$moduleDirPath" -ForegroundColor Green
New-Item -Path $modulePath -Type "Directory" -Force | Out-Null
New-Item -Path $modulePath"\Nugets" -Type "Directory" -Force | Out-Null
New-Item -Path $modulePath"\Cmdlets" -Type "Directory" -Force | Out-Null

If ($Host.Version.Major -ge 5) {
    #Make use of Nuget in Powershell 5
    import-Module PackageManagement 
    #UnInstall-Package -name Microsoft.IdentityModel.Clients.ActiveDirectory  -Destination "$modulePath\Nugets"  -Force 
    Install-Package -name Microsoft.IdentityModel.Clients.ActiveDirectory  -Destination "$modulePath\Nugets"  -Force 

} else { 
    #Old Style download 
    Write-Host "Installing Active Directory Authentication Library Nuget in " $modulePath"\Nugets" -ForegroundColor Green
    Write-Host "Downloading nuget.exe from http://www.nuget.org/nuget.exe" -ForegroundColor Green
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile("http://www.nuget.org/nuget.exe",$modulePath + "\Nugets\nuget.exe");

    $nugetDownloadExpression = $modulePath + "\Nugets\nuget.exe install Microsoft.IdentityModel.Clients.ActiveDirectory -OutputDirectory " + $modulePath + "\Nugets | out-null"
    Invoke-Expression $nugetDownloadExpression
}
Write-Host "Copying module files to the module directory" -ForegroundColor Green
Copy-Item $filesDirPath"\AADGraph.psd1" -Destination $modulePath -Force 
Copy-Item $filesDirPath"\AADGraph.psm1" -Destination $modulePath -Force 
Copy-Item $filesDirPath"\Cmdlets\*.psm1" -Destination $modulePath"\Cmdlets" -Force 

Import-Module AADGraph -DisableNameChecking -Force

Get-Command -Module AADGraph