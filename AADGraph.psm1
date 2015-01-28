function Load-ActiveDirectoryAuthenticationLibrary {
    [CmdletBinding()]
    param (
    )

  $moduleDirPath = ($ENV:PSModulePath -split ';')[0]
  $modulePath = $moduleDirPath + "\AADGraph"
  $NuGetDestination = $modulePath + "\Nugets\nuget.exe";

    if(-not (Test-Path ($modulePath+"\Nugets"))) {
        Write-Verbose -Message 'NuGet path doesn''t exist. Creating ...';
        New-Item -Path ($modulePath+"\Nugets") -ItemType "Directory" | out-null
    }

  $adalPackageDirectories = (Get-ChildItem -Path ($modulePath+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)

  if($adalPackageDirectories.Length -eq 0){
    Write-Verbose -Message "Active Directory Authentication Library Nuget doesn't exist. Downloading now ...";
    if(-not(Test-Path $NuGetDestination))
    {
      Write-Verbose -Message "nuget.exe not found. Downloading from http://www.nuget.org/nuget.exe ...";
      $NuGetSource = "http://www.nuget.org/nuget.exe";

      $WebClient = New-Object -TypeName System.Net.WebClient;
      $WebClient.DownloadFile($NuGetSource, $NuGetDestination);
    }
    $nugetDownloadExpression = $modulePath + "\Nugets\nuget.exe install Microsoft.IdentityModel.Clients.ActiveDirectory -OutputDirectory " + $modulePath + "\Nugets | out-null"
    Invoke-Expression -Command $nugetDownloadExpression;
  }

  $adalPackageDirectories = Get-ChildItem -Path ($modulePath+"\Nugets") -Filter Microsoft.IdentityModel.Clients.ActiveDirectory* -Directory;
  $ADAL_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)
  $ADAL_WindowsForms_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)
  if($ADAL_Assembly.Length -gt 0 -and $ADAL_WindowsForms_Assembly.Length -gt 0){
    Write-Host "Loading ADAL Assemblies ..." -ForegroundColor Green
    Add-Type -Path $ADAL_Assembly.FullName | Out-Null;
    Add-Type -Path $ADAL_WindowsForms_Assembly.FullName | Out-Null;
    return $true
  }
  else{
    Write-Verbose -Message "Fixing Active Directory Authentication Library (ADAL) package directories ...";
    $adalPackageDirectories | Remove-Item -Recurse -Force | Out-Null;
    Write-Error -Message "Not able to load ADAL assembly. Delete the Nugets folder under $modulePath." -RecommendedAction 'Restart PowerShell session and try again ...';
    return $false;
  }
}

function Get-AuthenticationResult {
    [CmdletBinding()]
    param (
    )
    $clientId = "1950a258-227b-4e31-a9cf-717495945fc2";
    [uri]$redirectUri = [uri]"urn:ietf:wg:oauth:2.0:oob";
    $resourceClientId = "00000002-0000-0000-c000-000000000000";
    $resourceAppIdURI = "https://graph.windows.net";
    $authority = "https://login.windows.net/common";
  
    $authContext = New-Object -TypeName Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext -ArgumentList $authority, $false;
    $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, $redirectUri);
    return $authResult;
}

function Connect-AAD {
    [CmdletBinding()]
    param ()

    process {
        $global:authenticationResult = $null
        $global:authenticationResult = Get-AuthenticationResult
    }
}

Load-ActiveDirectoryAuthenticationLibrary