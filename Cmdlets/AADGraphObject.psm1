﻿function Get-AADObject {
    <#
    .Synopsis
    Retrieves an entity from Microsoft Azure Active Directory (AAD).

    .Parameter Type
    The type of entity to retrieve from Microsoft Azure Active Directory. A list of valid entities can be found
    in the AAD documentation. See the LINKS section.

    .Links
    Microsoft Azure Active Directory Entity Reference: https://msdn.microsoft.com/en-us/library/azure/dn151470.aspx
    #>
    [CmdletBinding()]
    param (
        [ValidateSet('Applications', 'Contacts', 'Devices', 'DirectoryObjects', 'DirectoryRoles', 'DirectoryRoleTemplates',
        'Groups', 'OAuth2PermissionGrants', 'ServicePrincipals', 'SubscribedSkus', 'TenantDetails', 'Users')]
        [string] $Type
    )
    $CmdletName = $MyInvocation.MyCommand.Name;

    $objects = $null

    if (!$authenticationResult) {
        Write-Error -Message 'Not connected to an Azure Active Directory tenant.' -RecommendedAction 'First run Connect-AAD.';
    }

    $AuthorizationHeader = $authenticationResult.CreateAuthorizationHeader()
    $uri = [string]::Format("https://graph.windows.net/{0}/{1}?api-version=2013-04-05",$authenticationResult.TenantId, $type)

    Write-Verbose -Message ('HTTP GET {0}' -f $uri);

    $HttpHeaders = @{
        Authorization = $AuthorizationHeader;
        "Content-Type" = "application/json";
        }

    $result = Invoke-WebRequest -Method Get -Uri $uri -Headers $HttpHeaders;
    if($result.StatusCode -eq 200)
    {
      Write-Verbose -Message ('{0}: Get succeeded.' -f $CmdletName);
      $json = ConvertFrom-Json $result.Content;
    }

    return $json.value;
}

function Get-AADObjectById {
    [CmdletBinding()]
    param (
          [ValidateSet('Applications', 'Contacts', 'Devices', 'DirectoryObjects', 'DirectoryRoles', 'DirectoryRoleTemplates',
          'Groups', 'OAuth2PermissionGrants', 'ServicePrincipals', 'SubscribedSkus', 'TenantDetails', 'Users')]
          [Parameter(Mandatory = $true)]
          [string] $Type
        , [Parameter(Mandatory = $true)]
          [string] $Id
    )
 
    $object = $null;

    if (!$global:authenticationResult) {
        Write-Error -Message 'Not connected to an Azure Active Directory tenant.' -RecommendedAction 'First run Connect-AAD.';
    }

    $AuthorizationHeader = $authenticationResult.CreateAuthorizationHeader();
    $uri = [string]::Format("https://graph.windows.net/{0}/{1}/{2}?api-version=2013-04-05",$authenticationResult.TenantId, $type.Trim(), $id.Trim())
    Write-Verbose -Message ('HTTP GET {0}' -f $uri);

    $HttpHeaders = @{
        Authorization = $AuthorizationHeader;
        "Content-Type" = "application/json";
        }

    $result = Invoke-WebRequest -Method Get -Uri $uri -Headers $HttpHeaders;

    if($result.StatusCode -eq 200)
    {
        Write-Verbose -Message "Get succeeded.";
        $object = ConvertFrom-Json $result.Content;
    }

    return $object;
}

function New-AADObject {
    [CmdletBinding()]
    param (
          [Parameter(Mandatory = $true)]
          [ValidateSet('Applications', 'Contacts', 'Devices', 'DirectoryObjects', 'DirectoryRoles', 'DirectoryRoleTemplates',
          'Groups', 'OAuth2PermissionGrants', 'ServicePrincipals', 'SubscribedSkus', 'TenantDetails', 'Users')]
          [string] $Type
        , [Parameter(Mandatory = $true)]
          [object] $Object
        )
  $newObject = $null
    if (!$global:authenticationResult) {
        Write-Error -Message 'Not connected to an Azure Active Directory tenant.' -RecommendedAction 'First run Connect-AAD.';
    }

    $AuthorizationHeader = $authenticationResult.CreateAuthorizationHeader()
    $uri = [string]::Format("https://graph.windows.net/{0}/{1}?api-version=2013-04-05", $authenticationResult.TenantId, $type)
    Write-Verbose -Message ('HTTP POST {0}' -f $uri);

    $ASCIIEncoding = New-Object -TypeName System.Text.ASCIIEncoding;
    $body = ConvertTo-Json -InputObject $object;

    Write-Verbose -Message $body;
    $byteArray = $ASCIIEncoding.GetBytes($body);

    $HttpHeaders = @{
        Authorization = $AuthorizationHeader;
        "Content-Type" = 'application/json';
        "Content-Length"= $byteArray.Length;
        }

    $result = Invoke-WebRequest -Method Post -Uri $uri -Headers $HttpHeaders -Body $Body

    if ($result.StatusCode -eq 201)
    {
      Write-Verbose -Message 'Azure Active Directory object created successfully';
      $newObject = ConvertFrom-Json $result.Content;
    }

  return $newObject;
}

function Set-AADObject([string]$type, [string]$id, [object]$object) {
  if($global:authenticationResult -ne $null) {
    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = [string]::Format("https://graph.windows.net/{0}/{1}/{2}?api-version=2013-04-05",$authenticationResult.TenantId, $type, $id)
    Write-Host HTTP PATCH $uri -ForegroundColor Cyan
    $enc = New-Object "System.Text.ASCIIEncoding"
    $body = ConvertTo-Json -InputObject $object
    Write-Host $body -ForegroundColor Cyan
    $byteArray = $enc.GetBytes($body)
    $contentLength = $byteArray.Length
    $headers = @{"Authorization"=$header;"Content-Type"="application/json";"Content-Length"=$contentLength}
    $result = Invoke-WebRequest -Method Patch -Uri $uri -Headers $headers -Body $body
    if($result.StatusCode -eq 204)
    {
      Write-Host "Update succeeded." -ForegroundColor Cyan
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD." -ForegroundColor Yellow
  }
}

function Remove-AADObject([string]$type, [string]$id) {
  if($global:authenticationResult -ne $null) {
    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = [string]::Format("https://graph.windows.net/{0}/{1}/{2}?api-version=2013-04-05",$authenticationResult.TenantId, $type, $id)
    Write-Host HTTP DELETE $uri -ForegroundColor Cyan
    $headers = @{"Authorization"=$header;"Content-Type"="application/json"}
    $result = Invoke-WebRequest -Method Delete -Uri $uri -Headers $headers
    if($result.StatusCode -eq 204)
    {
      Write-Host "Delete succeeded." -ForegroundColor Cyan
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD." -ForegroundColor Yellow
  }
}

function Get-AADLinkedObject([string]$type, [string] $id, [string]$relationship, [bool]$getLinksOnly) {
  $objects = $null
  if($global:authenticationResult -ne $null){
    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = $null
    if($getLinksOnly) {$uri = [string]::Format("https://graph.windows.net/{0}/{1}/{2}/$links/{3}?api-version=2013-04-05",$authenticationResult.TenantId, $type, $id, $relationship)}
    else {$uri = [string]::Format("https://graph.windows.net/{0}/{1}/{2}/{3}?api-version=2013-04-05",$authenticationResult.TenantId, $type, $id, $relationship)}
    Write-Host HTTP GET $uri -ForegroundColor Cyan
    $result = Invoke-WebRequest -Method Get -Uri $uri -Headers @{"Authorization"=$header;"Content-Type"="application/json"}
    if($result.StatusCode -eq 200)
    {
      Write-Host "Get succeeded." -ForegroundColor Cyan
      $json = (ConvertFrom-Json $result.Content)
      if($json -ne $null){$objects = $json.value}
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AAD." -ForegroundColor Yellow
  }
  return $objects
}

function Set-AADObjectProperty {
    <#
    .Synopsis
    Sets the property of a Microsoft Azure Active Directory object.
    #>
    [CmdletBinding()]
    param (
        [ValidateSet('Applications', 'Contacts', 'Devices', 'DirectoryObjects', 'DirectoryRoles', 'DirectoryRoleTemplates',
        'Groups', 'OAuth2PermissionGrants', 'ServicePrincipals', 'SubscribedSkus', 'TenantDetails', 'Users')]
        [string] $Type, 
        [string] $Id, 
        [string] $Property, 
        [object] $Value, 
        [bool] $IsLinked,
        [string] $ContentType
    )

    if (!$global:authenticationResult) {
        throw 'You are not authenticated to Microsoft Azure Active Directory. Use Connect-AAD to authenticate, and then retry your command.';
        return;
    }

    $header = $authenticationResult.CreateAuthorizationHeader()
    $uri = $null
    if($isLinked) {
        $uri = [string]::Format('https://graph.windows.net/{0}/{1}/{2}/$links/{3}?api-version=2013-04-05',$authenticationResult.TenantId, $type, $id, $property)
        }
    else {
        $uri = [string]::Format('https://graph.windows.net/{0}/{1}/{2}/{3}?api-version=2013-04-05',$authenticationResult.TenantId, $type, $id, $property)
        }
    Write-Host HTTP PUT $uri -ForegroundColor Cyan

    $HttpBody = $null;
    $byteArray = $null
    
    if($contentType.Trim() -eq "" -or $contentType -eq $null -or $contentType.ToLower() -eq "application/json") {
      $contentType = "application/json"
      $enc = New-Object "System.Text.ASCIIEncoding"
      $body = ConvertTo-Json -InputObject $value
      $byteArray = $enc.GetBytes($HttpBody)
      Write-Host $body -ForegroundColor Cyan
    }
    elseif ($contentType.ToLower() -eq "image/jpeg" -or $contentType.ToLower() -eq "image/png" -or $contentType.ToLower() -eq "image/gif") {
      $contentType = $contentType.ToLower()
      $HttpBody = $value;
      $byteArray = $value;
      Write-Host "Body of the request is binary data." -ForegroundColor Cyan
    }
    $contentLength = $byteArray.Length
    $headers = @{
        Authorization = $header;
        'Content-Type' = $contentType;
        'Content-Length' = $contentLength;
        }
    $result = Invoke-WebRequest -Method Put -Uri $uri -Headers $headers -Body $HttpBody -ErrorVariable PutError;

    if ($result.StatusCode -eq 204) {
        Write-Verbose -Message 'Entity update succeeded.';
    }
    else {
        Write-Error -Message 'Entity update was not successful. Examine the result for more information.' -TargetObject $PutError;
    }

    return $Result;
}
