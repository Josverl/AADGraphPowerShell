$filesDirPath = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$moduleDirPath = ($ENV:PSModulePath -split ';')[0]
$modulePath = $moduleDirPath + "\AADGraph"

if (Test-Path $modulePath)
{
    Write-Verbose -Message "Removing existing module directory under $moduleDirPath";
    Remove-Item -Path $modulePath -Recurse -Force | Out-Null
}

Write-Verbose -Message "Creating module directory under $moduleDirPath";
New-Item -Path $modulePath -Type "Directory" -Force | Out-Null
New-Item -Path $modulePath"\Nugets" -Type Directory -Force | Out-Null
New-Item -Path $modulePath"\Cmdlets" -Type Directory -Force | Out-Null

Write-Verbose -Message ('Installing Active Directory Authentication Library Nuget in {0}\Nugets' -f $modulePath);
Write-Verbose -Message "Downloading nuget.exe from http://www.nuget.org/nuget.exe";
$WebClient = New-Object -TypeName System.Net.WebClient;
$WebClient.DownloadFile("http://www.nuget.org/nuget.exe",$modulePath + "\Nugets\nuget.exe");
$nugetDownloadExpression = $modulePath + "\Nugets\nuget.exe install Microsoft.IdentityModel.Clients.ActiveDirectory -OutputDirectory " + $modulePath + "\Nugets | out-null"
Invoke-Expression -Command $nugetDownloadExpression;

Write-Verbose -Message 'Copying module files to the module directory';
Copy-Item $filesDirPath"\AADGraph.psd1" -Destination $modulePath -Force 
Copy-Item $filesDirPath"\AADGraph.psm1" -Destination $modulePath -Force 
Copy-Item $filesDirPath"\Cmdlets\*.psm1" -Destination $modulePath"\Cmdlets" -Force 
