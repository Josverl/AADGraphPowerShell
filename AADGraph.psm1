<#
.Synopsis
   Load Adal Libraries 
.DESCRIPTION
   Load the ADFAL libraries for use with the AAD Graph API.
   requires that the ADAL libraries are present , and will download the ADAL libraries using PowershellGet/NUGET if not avaialble
.EXAMPLE
   Load-ActiveDirectoryAuthenticationLibrary
#>
function Load-ActiveDirectoryAuthenticationLibrary(){ 
    [CmdletBinding()]
    [OutputType([boolean])]
    param ()
    
    $moduleDirPath = ($ENV:PSModulePath -split ';' | ?{ $_ -inotlike '*\Users\*'})[0]
    $modulePath = $moduleDirPath + "\AADGraph"
    
    #Store Nuget in a location where we can write to 
    $NuGetFolder = $env:LOCALAPPDATA + "\Nuget";
    $NuGetExe = Join-Path $NuGetFolder "nuget.exe";

    #check for nugets folder
    if(-not (Test-Path ($NuGetFolder))) {
        Write-Verbose -Message 'NuGet path doesn''t exist. Creating ...';
        New-Item -Path ($NuGetFolder) -ItemType "Directory" | out-null
    }

    $adalPackageDirectories = (Get-ChildItem -Path  $NuGetFolder -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)
    #go get ADAL if its not downloaded yet
    if($adalPackageDirectories.Length -eq 0){
        Write-Verbose -Message 'ADAL Libraries are not yet installed';
<#        If ($Host.Version.Major -ge 5) {
            #Make use of Nuget in Powershell 5
            import-Module PackageManagement 
            #UnInstall-Package -name Microsoft.IdentityModel.Clients.ActiveDirectory  -Destination "$modulePath\Nugets"  -Force 
            Find-Package -ProviderName NuGet -Name Microsoft.IdentityModel.Clients.ActiveDirectory  
            -Destination "$modulePath\Nugets"  -Force 
            Install-Package -name Microsoft.IdentityModel.Clients.ActiveDirectory  -Destination "$modulePath\Nugets"  -Force 
        } else { 
#>
            #Nuget.exe v3 
            Write-Verbose -Message "Active Directory Authentication Library Nuget doesn't exist. Downloading now ...";
            if(-not(Test-Path  $NuGetExe))
            {
                Write-Verbose -Message "nuget.exe not found. Downloading from http://dist.nuget.org/..."
                $NuGetSource = "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe"
                $WebClient = New-Object -TypeName System.Net.WebClient
                $WebClient.DownloadFile($NuGetSource,  $NuGetExe)
            }
            $nugetDownloadExpression = $NuGetExe + " install Microsoft.IdentityModel.Clients.ActiveDirectory -OutputDirectory " + $NuGetFolder 
            Write-Verbose $nugetDownloadExpression 
            Invoke-Expression -Command $nugetDownloadExpression;
#        }
        #load ADAL libs from downloaded package 
        $adalPackageDirectories = Get-ChildItem -Path ($modulePath+"\Nugets") -Filter Microsoft.IdentityModel.Clients.ActiveDirectory* -Directory;
        #Load the libraries from the last downloaded package
        $ADAL_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)
        $ADAL_WindowsForms_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)
        if($ADAL_Assembly.Length -gt 0 -and $ADAL_WindowsForms_Assembly.Length -gt 0){
            Write-Host "Loading ADAL Assemblies ..." -ForegroundColor Green
            Add-Type -Path $ADAL_Assembly.FullName | Out-Null;
            Add-Type -Path $ADAL_WindowsForms_Assembly.FullName | Out-Null;
            return $true
        } else {
            Write-Verbose -Message "Fixing Active Directory Authentication Library (ADAL) package directories ...";
            $adalPackageDirectories | Remove-Item -Recurse -Force | Out-Null;
            Write-Error "Not able to load ADAL assembly. Delete the Nuget folder : $NuGetFolder" -RecommendedAction 'Restart PowerShell session and try again'
            return $false;
        }
    }
}

function Get-AuthenticationResult {
[CmdletBinding()]
#[OutputType([int])]
Param(
    #Tenant directory
    [Parameter(Mandatory=$true,Position=0,HelpMessage="Tenant directory or registered domain")][string]
    $tenant = "contoso.onmicrosoft.com", 
    #environment or production tier 
    [Parameter(Position=1)][string]
    $env="prod",
    #credentials to authenticate
    [Parameter(Position=2)][System.Management.Automation.PSCredential]
    $Credentials = $null
    )
    $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
    [uri]$redirectUri = [uri]"urn:ietf:wg:oauth:2.0:oob"
    $resourceClientId = "00000002-0000-0000-c000-000000000000"
    $resourceAppIdURI = "https://graph.windows.net";
    $authority = "https://login.windows.net/common";
    #Use the appropriate endpoints
    switch ($env.ToLower())
    {
        'ppe'   { $resourceAppIdURI = "https://graph.ppe.windows.net/"; 
                  $authority = "https://login.windows-ppe.net/" + $tenant}
        'china' { $resourceAppIdURI = "https://graph.chinacloudapi.cn/";
                  $authority = "https://login.chinacloudapi.cn/" + $tenant}
        Default { $resourceAppIdURI = "https://graph.windows.net/"; 
                  $authority = "https://login.windows.net/" + $tenant}
    }
  
    $authContext = New-Object -TypeName Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext -ArgumentList $authority, $false;
    #Aquires security token from the authority
    if ( -Not $credentials ) {
        # If Always, asks service to show user the authentication page which gives them chance to authenticate as a different user.
        $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, $redirectUri, [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always)
        
    } else {           
<#      
        #Assumed Name , required to prompt
        $UserIdentifyer = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier"  -ArgumentList  "josverl2@microsoft.com",  "OptionalDisplayableId"
        $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, $redirectUri, [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always, $UserIdentifyer)

        #Known Name , required to prompt
        $UserIdentifyer = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier"  -ArgumentList  "josverl@microsoft.com",  "RequiredDisplayableId"
        $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, $redirectUri, [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always, $UserIdentifyer)

        #Known Name , Auto prompt
        $UserIdentifyer = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier"  -ArgumentList  "josverl@microsoft.com",  "RequiredDisplayableId"
        $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, $redirectUri, [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto, $UserIdentifyer)

        #Known Name , Never Prompt
        $UserIdentifyer = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier"  -ArgumentList  "josverl@microsoft.com",  "RequiredDisplayableId"
        $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, $redirectUri, [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Never, $UserIdentifyer)
#>
        # transform credential into the required type
        $cred2 = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential" -ArgumentList @( $Credentials.UserName , $Credentials.Password )

        #Call the silent overload     
        $authResult = $authContext.AcquireToken($resourceAppIdURI, $clientId, $Cred2) 
    }

    return $authResult
}

<#
.Synopsis
   Connect and authenticate to AAD via Graph
.Notes 
    #Added $credential parameter 
#>
function Connect-AAD {
    [CmdletBinding()]
Param ( 
    #Tenant directory
    [Parameter(Mandatory=$true,Position=0,HelpMessage="Tenant directory or registered domain")][string]
    $tenant = "contoso.onmicrosoft.com", 
    #environment or production tier 
    [Parameter(Position=1)][string]
    $env="prod",
    #Version of graph API to use ( 1.5,1.6,beta)  
    [Parameter(Position=2)][string]
    $graphVer="1.6", 
    #credentials to authenticate
    [Parameter(Position=3)][System.Management.Automation.PSCredential]
    $Credentials = $null
) 
    PROCESS {
        $global:AuthenticationResult = $null
        $global:aadGPoShEnv = $env
        $global:GraphAPIVersion = $graphVer
        #Use the appropriate endpoints
        switch ($env.ToLower())
        {
            'ppe'   {$global:aadGraphUrl = "https://graph.ppe.windows.net/"}
            'china' {$global:aadGraphUrl = "https://graph.chinacloudapi.cn/"}
            Default {$global:aadGraphUrl = "https://graph.windows.net/"}
        }
        $global:AuthenticationResult = Get-AuthenticationResult -Tenant $tenant -Env $env -Credentials $Credentials
    }
}

function Execute-AADQuery ($Base, $HTTPVerb, $Query, $Data, [switch] $Silent) {
  $return = $null
  if($global:AuthenticationResult -ne $null) {
    $header = $global:AuthenticationResult.CreateAuthorizationHeader()
    $headers = @{"Authorization"=$header;"Content-Type"="application/json"}
    $uri = [string]::Format("{0}{1}/{2}?api-version={3}{4}",$global:aadGraphUrl,$global:AuthenticationResult.TenantId, $base, $global:GraphAPIVersion, $query)
    if($data -ne $null){
      $enc = New-Object "System.Text.ASCIIEncoding"
      $body = ConvertTo-Json -InputObject $Data -Depth 10
      $byteArray = $enc.GetBytes($body)
      $contentLength = $byteArray.Length
      $headers.Add("Content-Length",$contentLength)
    }
    if(-not $Silent){
      Write-Host HTTP $HTTPVerb $uri -ForegroundColor Cyan
      Write-Host
    }
    
    $headers.GetEnumerator() | % {
      if(-not $Silent){
        Write-Host $_.Key: $_.Value -ForegroundColor Cyan
        }
      }
    if($data -ne $null){
      if(-not $Silent){
        Write-Host
        Write-Host $body -ForegroundColor Cyan
      }
    }
    $result = Invoke-WebRequest -Method $HTTPVerb -Uri $uri -Headers $headers -Body $body
    if($result.StatusCode -ge 200 -and $result.StatusCode -le 399){
      if(-not $Silent){
        Write-Host
        Write-Host "Query successfully executed." -ForegroundColor Cyan
      }
      if($result.Content -ne $null){
        $json = (ConvertFrom-Json $result.Content)
        if($json -ne $null){
          $return = $json
          if($json.value -ne $null){$return = $json.value}
        }
      }
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD." -ForegroundColor Yellow
  }
  return $return
}


Load-ActiveDirectoryAuthenticationLibrary
