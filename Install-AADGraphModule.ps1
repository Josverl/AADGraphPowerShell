#find location where this install script is stored
#and the destimation path for the module
$filesDirPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$moduleDirPath = ($ENV:PSModulePath -split ';')[0]
$modulePath = $moduleDirPath + "\AADGraph"

if (Test-Path $modulePath)
{
    #give upgrade notice
    Write-Verbose -Message "Removing existing module directory under $moduleDirPath";
    Remove-Item -Path $modulePath -Recurse -Force | Out-Null
}

Write-Verbose -Message "Creating module directory under $moduleDirPath";
New-Item -Path $modulePath -Type "Directory" -Force | Out-Null
New-Item -Path $modulePath"\Nugets" -Type Directory -Force | Out-Null
New-Item -Path $modulePath"\Cmdlets" -Type Directory -Force | Out-Null

<#  Removed due to issues in WRM 5.0 
If ($Host.Version.Major -ge 5) {
#>
if ($false){
    Write-Verbose -Message ('Installing Active Directory Authentication Library Nuget using packagemanagement' -f $modulePath);

    #Make use of Nuget in Powershell 5
    import-Module PackageManagement 
    if (-not $(get-PackageProvider -Name nuget)) {
        install-PackageProvider -Name nuget
    }
    #UnInstall-Package -name Microsoft.IdentityModel.Clients.ActiveDirectory  -Destination "$modulePath\Nugets"  -Force 
    Install-Package -Name Microsoft.IdentityModel.Clients.ActiveDirectory -ProviderName NuGet -Destination "$modulePath\Nugets" 
    Microsoft.IdentityModel.Clients.ActiveDirectory 
} else { 
    #Old Style download
    Write-Verbose -Message ('Installing Active Directory Authentication Library Nuget in {0}\Nugets' -f $modulePath);
    Write-Verbose -Message "Downloading nuget.exe from http://www.nuget.org/nuget.exe";
    $WebClient = New-Object -TypeName System.Net.WebClient;
    $WebClient.DownloadFile("http://www.nuget.org/nuget.exe",$modulePath + "\Nugets\nuget.exe");
    $nugetDownloadExpression = $modulePath + "\Nugets\nuget.exe install Microsoft.IdentityModel.Clients.ActiveDirectory -OutputDirectory " + $modulePath + "\Nugets | out-null"
    Invoke-Expression -Command $nugetDownloadExpression;
}

Write-Verbose -Message 'Copying module files to the module directory';
Copy-Item $filesDirPath"\AADGraph.psd1" -Destination $modulePath -Force 
Copy-Item $filesDirPath"\AADGraph.psm1" -Destination $modulePath -Force 
Copy-Item $filesDirPath"\Cmdlets\*.psm1" -Destination $modulePath"\Cmdlets" -Force 
