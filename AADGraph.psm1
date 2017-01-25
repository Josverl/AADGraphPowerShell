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
    switch ($env.ToLower()) {
        'ppe'   {
            $resourceAppIdURI = "https://graph.ppe.windows.net/"; 
            $authority = "https://login.windows-ppe.net/" + $tenant
        }
        'china' {
            $resourceAppIdURI = "https://graph.chinacloudapi.cn/";
            $authority = "https://login.chinacloudapi.cn/" + $tenant
        }
        Default {
            $resourceAppIdURI = "https://graph.windows.net/"; 
            $authority = "https://login.windows.net/" + $tenant
        }
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
function Connect-AADGraph {
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
        switch ($env.ToLower()) {
            'ppe'   {
                $global:aadGraphUrl = "https://graph.ppe.windows.net/"
            }
            'china' {
                $global:aadGraphUrl = "https://graph.chinacloudapi.cn/"
            }
            Default {
                $global:aadGraphUrl = "https://graph.windows.net/"
            }
        }
        $global:AuthenticationResult = Get-AuthenticationResult -Tenant $tenant -Env $env -Credentials $Credentials
    }
}

function Execute-AADGraphQuery ($Base, $HTTPVerb, $Query, $Data, [switch] $Silent) {
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
                    if($json.value -ne $null){
                        $return = $json.value
                    }
                }
            }
        }
    }
    else{
        Write-Host "Not connected to an AAD tenant. First run Connect-AADGraph." -ForegroundColor Yellow
    }
    return $return
}
