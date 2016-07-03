<#
.Synopsis
   Load Adal Libraries 
.DESCRIPTION
   Load the ADFAL libraries for use with the AAD Graph API.
   requires that the ADAL libraries are present , and will download the ADAL libvraries using PowershellGet/NUGET if not avaialble
.EXAMPLE
   Load-ActiveDirectoryAuthenticationLibrary
#>
function Load-ActiveDirectoryAuthenticationLibrary(){
[CmdletBinding()]
[OutputType([boolean])]

    $moduleDirPath = [Environment]::GetFolderPath("MyDocuments") + "\WindowsPowerShell\Modules"
    $modulePath = $moduleDirPath + "\AADGraph"
    #check for nugets folder
    if(-not (Test-Path ($modulePath+"\Nugets"))) {New-Item -Path ($modulePath+"\Nugets") -ItemType "Directory" | out-null}

    $adalPackageDirectories = (Get-ChildItem -Path ($modulePath+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)
    #go get ADAL if its not downloaded yet
    if($adalPackageDirectories.Length -eq 0){
        If ($Host.Version.Major -ge 5) {
            #Make use of Nuget in Powershell 5
            import-Module PackageManagement 
            #UnInstall-Package -name Microsoft.IdentityModel.Clients.ActiveDirectory  -Destination "$modulePath\Nugets"  -Force 
            Install-Package -name Microsoft.IdentityModel.Clients.ActiveDirectory  -Destination "$modulePath\Nugets"  -Force 

        } else { 
            #Old Style download 
            Write-verbose "Active Directory Authentication Library Nuget doesn't exist. Downloading now ..." 
            if(-not(Test-Path ($modulePath + "\Nugets\nuget.exe")))
            {   #wget nuget 
                Write-verbose "nuget.exe not found. Downloading from http://www.nuget.org/nuget.exe ..." 
                $wc = New-Object System.Net.WebClient
                $wc.DownloadFile("http://www.nuget.org/nuget.exe",$modulePath + "\Nugets\nuget.exe");
            }
            $nugetDownloadExpression = $modulePath + "\Nugets\nuget.exe install Microsoft.IdentityModel.Clients.ActiveDirectory -Version 2.14.201151115 -OutputDirectory " + $modulePath + "\Nugets | out-null"
            Invoke-Expression $nugetDownloadExpression
        }
    }
    #load ADAL libs from downloaded package 
    $adalPackageDirectories = (Get-ChildItem -Path ($modulePath+"\Nugets") -Filter "Microsoft.IdentityModel.Clients.ActiveDirectory*" -Directory)
    #Load the libraries from the last downloaded package 
    $ADAL_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)
    $ADAL_WindowsForms_Assembly = (Get-ChildItem "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll" -Path $adalPackageDirectories[$adalPackageDirectories.length-1].FullName -Recurse)
    #
    if($ADAL_Assembly.Length -gt 0 -and $ADAL_WindowsForms_Assembly.Length -gt 0){
        Write-verbose "Loading ADAL Assemblies ..." 
        [System.Reflection.Assembly]::LoadFrom($ADAL_Assembly[0].FullName) | out-null
        [System.Reflection.Assembly]::LoadFrom($ADAL_WindowsForms_Assembly.FullName) | out-null
        return $true
    }
    else{
        Write-Verbose "Fixing Active Directory Authentication Library package directories ..." 
        $adalPackageDirectories | Remove-Item -Recurse -Force | Out-Null
        Write-Warning "Not able to load ADAL assembly. Delete the Nugets folder under" $modulePath ", restart PowerShell session and try again ..."
        return $false
    }
}

function Get-AuthenticationResult{
[CmdletBinding()]
#    [OutputType([int])]
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
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $resourceClientId = "00000002-0000-0000-c000-000000000000"
    
    #Use the appropriate endpoints
    switch ($env.ToLower())
    {
        'ppe'   {$resourceAppIdURI = "https://graph.ppe.windows.net/"; $authority = "https://login.windows-ppe.net/" + $tenant}
        'china' {$resourceAppIdURI = "https://graph.chinacloudapi.cn/"; $authority = "https://login.chinacloudapi.cn/" + $tenant}
        Default {$resourceAppIdURI = "https://graph.windows.net/"; $authority = "https://login.windows.net/" + $tenant}
    }
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority,$false
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
   Connect and authenticate to AAD via Grap
.Notes 
    #Added $credential parameter 
#>
function Connect-AAD{
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
        $global:aadGPoShAuthResult = $null
        $global:aadGPoShEnv = $env
        $global:aadGPoShGraphVer = $graphVer
        #Use the appropriate endpoints
        switch ($env.ToLower())
        {
            'ppe'   {$global:aadGPoShGraphUrl = "https://graph.ppe.windows.net/"}
            'china' {$global:aadGPoShGraphUrl = "https://graph.chinacloudapi.cn/"}
            Default {$global:aadGPoShGraphUrl = "https://graph.windows.net/"}
        }
        $global:aadGPoShAuthResult = Get-AuthenticationResult -Tenant $tenant -Env $env -Credentials $Credentials
    }
}

function Execute-AADQuery ($Base, $HTTPVerb, $Query, $Data, [switch] $Silent) {
  $return = $null
  if($global:aadGPoShAuthResult -ne $null) {
    $header = $global:aadGPoShAuthResult.CreateAuthorizationHeader()
    $headers = @{"Authorization"=$header;"Content-Type"="application/json"}
    $uri = [string]::Format("{0}{1}/{2}?api-version={3}{4}",$global:aadGPoShGraphUrl,$global:aadGPoShAuthResult.TenantId, $base, $global:aadGPoShGraphVer, $query)
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
