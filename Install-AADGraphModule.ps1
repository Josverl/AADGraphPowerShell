
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

<#  Removed due to issues in WRM 5.0 
If ($Host.Version.Major -ge 5) {
#>
if ($false){
    #Make use of Nuget in Powershell 5
    import-Module PackageManagement 
    if (-not $(get-PackageProvider -Name nuget)) {
        install-PackageProvider -Name nuget
    }

    Install-Package -Name Microsoft.IdentityModel.Clients.ActiveDirectory -ProviderName NuGet -Destination "$modulePath\Nugets" 
    Microsoft.IdentityModel.Clients.ActiveDirectory 
    #UnInstall-Package -name Microsoft.IdentityModel.Clients.ActiveDirectory  -Destination "$modulePath\Nugets"  -Force 


} else { 

    #Old Style download 
    Write-Host "Installing Active Directory Authentication Library Nuget in " $modulePath"\Nugets" -ForegroundColor Green
    Write-Host "Downloading nuget.exe from http://www.nuget.org/nuget.exe" -ForegroundColor Green
    $wc = New-Object System.Net.WebClient
    $nuget_exe = $modulePath + "\Nugets\nuget.exe"
    $nuget_mod = $modulePath + "\Nugets" 

    $wc.DownloadFile("http://www.nuget.org/nuget.exe",$nuget_exe);
    # Path may contains spaces 
    
    $args = 'install Microsoft.IdentityModel.Clients.ActiveDirectory -OutputDirectory "' +  $nuget_mod  + '"'
    Start-Process -FilePath $nuget_exe -ArgumentList $args -Wait -WindowStyle Minimized


    Invoke-Expression ( $DQuote + $modulePath + "\Nugets\nuget.exe" + " install Microsoft.IdentityModel.Clients.ActiveDirectory -OutputDirectory " + $modulePath + "\Nugets" + " " + $DQuote )

    #$nugetDownloadExpression = $DQuote + $modulePath + "\Nugets\nuget.exe" + $DQuote + " install Microsoft.IdentityModel.Clients.ActiveDirectory -OutputDirectory " + $DQuote + $modulePath + "\Nugets" + $DQuote + " | out-null"
    #Invoke-Expression $nugetDownloadExpression
}
Write-Host "Copying module files to the module directory" -ForegroundColor Green
Copy-Item $filesDirPath"\AADGraph.psd1" -Destination $modulePath -Force 
Copy-Item $filesDirPath"\AADGraph.psm1" -Destination $modulePath -Force 
Copy-Item $filesDirPath"\Cmdlets\*.psm1" -Destination $modulePath"\Cmdlets" -Force 

Import-Module AADGraph -DisableNameChecking -Force

Get-Command -Module AADGraph
