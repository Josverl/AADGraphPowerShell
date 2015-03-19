function Get-AADPolicy {
  [CmdletBinding()]
  param (
    [parameter(Mandatory=$false,
    ValueFromPipeline=$true,
    HelpMessage="The ObjectId of the Policy.")]
    [string]
    $ObjectId,
    
    [parameter(Mandatory=$false,
    HelpMessage="Suppress console output.")]
    [switch]
    $Silent
  )
  PROCESS {
    if($ObjectId -ne $null -and $ObjectId -ne "") {
      if($Silent){Get-AADObjectById -Type "policies" -Id $ObjectId -Silent}
      else{Get-AADObjectById -Type "policies" -Id $ObjectId}
    }
    else {
      if($Silent){Get-AADObject -Type "policies" -Silent}
      else{Get-AADObject -Type "policies"}
    }
  }
}

function Set-TenantDefaultPolicy {
    # TODO
}

function Get-TenantDefaultPolicy {
    [CmdletBinding()]
    param (   
    [parameter(Mandatory=$false,
    HelpMessage="Suppress console output.")]
    [switch]
    $Silent
    )
    PROCESS {
        $existingPolicies = New-Object System.Object
        if($Silent) {$existingPolicies = Get-AADPolicy -Silent}
        else {$existingPolicies = Get-AADPolicy}

        foreach($policy in $existingPolicies) {
            if($policy.tenantDefaultPolicy -eq '1') {return $policy}
        }
        return $null
  }
}

function Assign-Policy {
    # TODO
}

function New-AADAdminPermissionGrantIfNeeded {
    [CmdletBinding()]
    param (   
    [parameter(Mandatory=$false,
    HelpMessage="Suppress console output.")]
    [switch]
    $Silent,

    [parameter(Mandatory=$true,
    HelpMessage="The Object Id of the service principal for which tenant-wide consent will be recorded.")]
    [string]
    $ServicePrincipalObjectId

    )
    PROCESS {
        $grants = New-Object System.Object
        if($Silent) {$grants = Get-AADObject -Type 'oAuth2PermissionGrants' -Silent}
        else {$grants = Get-AADObject -Type 'oAuth2PermissionGrants'}

        foreach($grant in $grants) {
            if($grant.clientId -eq $ServicePrincipalObjectId -and $grant.consentType -eq 'AllPrincipals') {
                if(!$Silent) {
                    Write-Host "Admin consent to application already exists." -ForegroundColor Green
                }
                return 
            }
        }

        $grant = New-Object System.Object
        Add-Member -InputObject $grant -MemberType NoteProperty -Name 'clientId' -Value $ServicePrincipalObjectId
        Add-Member -InputObject $grant -MemberType NoteProperty -Name 'clientId' -Value $ServicePrincipalObjectId

        if ($Silent) {New-AADObject -Type 'oAuth2PermissionGrants' -Object $grant -Silent}
        else {New-AADObject -Type 'oAuth2PermissionGrants' -Object $grant}
  }
}

function New-AADIdp {
  [CmdletBinding()]
  param (
    [parameter(Mandatory=$true,
    ValueFromPipeline=$true,
    HelpMessage="Choose from: Facebook, Google, Weibo, QQ, RenRen")]
    [string]
    $Idp,

    [parameter(Mandatory=$true,
    ValueFromPipeline=$true,
    HelpMessage="The client_id of the app you registered with the IDP.")]
    [string]
    $ClientId,

    [parameter(Mandatory=$true,
    ValueFromPipeline=$true,
    HelpMessage="The client_secret of the app you registered with the IDP.")]
    [string]
    $ClientSecret,

    [parameter(Mandatory=$false,
    ValueFromPipeline=$true,
    HelpMessage="The Display Name of the IDP Policy that will be updated or created")]
    [string]
    $DisplayName,

    [parameter(Mandatory=$false,
    ValueFromPipeline=$true,
    HelpMessage="Set to true to create a new IDP Policy rather than update the existing tenant default policy.")]
    [switch]
    $AddToNewPolicy,

    [parameter(Mandatory=$false,
    ValueFromPipeline=$true,
    HelpMessage="The Object Id of the IDP Policy to update with new IDP.")]
    [string]
    $PolicyId,

    [parameter(Mandatory=$false,
    HelpMessage="The Object Id of the service principal that will use the IDP for sign in.")]
    [string]
    $ServicePrincipal,

    [parameter(Mandatory=$false,
    HelpMessage="Suppress console output.")]
    [switch]
    $Silent
  )
  PROCESS {
    # Create Necessary Objects
    $newPolicy = New-Object System.Object
    $existingPolicy = New-Object System.Object
    $clientSecretBytes = [System.Text.Encoding]::UTF8.GetBytes($ClientSecret)
    $encodedClientSecret = [System.Convert]::ToBase64String($clientSecretBytes)
    $clientSecretStorageKey = [guid]::NewGuid()
    $issuerUri = Map-IdpToIssuerUri($Idp)
    $idpType = Map-IdpToIdpType($Idp)
    
    # Check Command Validity
    if($PolicyId -and $AddToNewPolicy) {
        Write-Host "Cannot use -PolicyId and -AddToNewPolicy in the same command" -ForegroundColor Yellow
        return
    }

    if(!$idpType -or !$issuerUri) {
        Write-Host "Idp not supported, see help for the existing Idp's supported." -ForegroundColor Yellow
        return
    }

    if($ClientId -eq '') {
        Write-Host "Client Id must be longer than zero characters." -ForegroundColor Yellow
        return
    }

    if($ClientSecret -eq '') {
        Write-Host "Client Secret must be longer than zero characters." -ForegroundColor Yellow
        return
    }


    # If PolicyId was specified, get that Policy
    if($PolicyId) {
        if($Silent) {$existingPolicy = Get-AADPolicy -ObjectId $PolicyId -Silent}
        else {$existingPolicy = Get-AADPolicy -ObjectId $PolicyId}
        if ($existingPolicy -eq $null) {
            Write-Host "Could not find Policy with given Object Id." -ForegroundColor Yellow
            return
        }
    }
    # If no PolicyId was specified, check for an existing tenantDefaultPolicy
    else {
        if($Silent) {$existingPolicy = Get-TenantDefaultPolicy}
        else {$existingPolicy = Get-TenantDefaultPolicy}
    }

    # PolicyType is always 1, for now
    Add-Member -InputObject $newPolicy -MemberType NoteProperty -Name 'policyType' -Value '1'

    # TenantDefaultPolicy
    if($existingPolicy -eq $null) {
        Add-Member -InputObject $newPolicy -MemberType NoteProperty -Name 'tenantDefaultPolicy' -Value '1'
    }
    elseif($AddToNewPolicy) {
        Add-Member -InputObject $newPolicy -MemberType NoteProperty -Name 'tenantDefaultPolicy' -Value '0'
    }
    else {
        Add-Member -InputObject $newPolicy -MemberType NoteProperty -Name 'tenantDefaultPolicy' -Value $existingPolicy.tenantDefaultPolicy
    }

    # DisplayName
    if($DisplayName) {
        Add-Member -InputObject $newPolicy -MemberType NoteProperty -Name 'displayName' -Value $DisplayName
    }
    elseif($existingPolicy -eq $null) {
        Add-Member -InputObject $newPolicy -MemberType NoteProperty -Name 'displayName' -Value 'Default_Social_Idp_Policy'
    }
    else {
        Add-Member -InputObject $newPolicy -MemberType NoteProperty -Name 'displayName' -Value $existingPolicy.displayName
    }

    # PolicyDetail
    $policyDetailFormat = "{`"ClaimIssuancePolicy`":{`"Version`":1, `"AllowPassThruUsers`":`"true`"}, `"IdentityProviderPolicy`": [{policyChunks}]}"
    $policyChunkFormat = "{{`"Version`":1, `"IssuerURI`": `"{0}`", `"Protocol`": `"OAuth2`", `"Metadata`": [{{Key: `"IdpType`", Value: `"{1}`"}}, {{Key: `"client_id`", Value: `"{2}`"}}], `"CryptographicKeys`": [{{Id:`"client_secret`", StorageReferenceId:`"{3}`"}}], `"OutputClaims`": []}}, "
    
    $policyChunks = ''
    if($existingPolicy -and !($AddToNewPolicy)) {
        $chunksKey = "`"IdentityProviderPolicy`": ["
        $chunksStartToEnd = $existingPolicy.policyDetail.Substring($existingPolicy.policyDetail.IndexOf($chunksKey) + $chunksKey.Length)
        $policyChunks = $chunksStartToEnd.Substring(0, $chunksStartToEnd.Length-2) 
    }

        # TODO: Prevent the same IDP/Client_Id Tuple from being added twice.

    Write-Host $policyChunkFormat -ForegroundColor Yellow
    $policyChunks += [string]::Format($policyChunkFormat, $issuerUri, $idpType, $ClientId, $clientSecretStorageKey)
    $policyDetail = $policyDetailFormat.Replace("{policyChunks}", $policyChunks)
    Add-Member -InputObject $newPolicy -MemberType NoteProperty -Name 'policyDetail' -Value @($policyDetail)


    # KeyCredentials
    $keyCredentials = @()
    if($existingPolicy -and !($AddToNewPolicy)) {
        $keyCredentials = $existingPolicy.keyCredentials
    }

    $newKeyCredential = New-Object System.Object
    $endDate = (Get-Date).AddYears(1).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $startDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    Add-Member -InputObject $newKeyCredential -MemberType NoteProperty -Name 'customKeyIdentifier' -Value $null
    Add-Member -InputObject $newKeyCredential -MemberType NoteProperty -Name 'endDate' -Value $endDate
    Add-Member -InputObject $newKeyCredential -MemberType NoteProperty -Name 'keyId' -Value $clientSecretStorageKey
    Add-Member -InputObject $newKeyCredential -MemberType NoteProperty -Name 'startDate' -Value $startDate
    Add-Member -InputObject $newKeyCredential -MemberType NoteProperty -Name 'type' -Value 'Symmetric'
    Add-Member -InputObject $newKeyCredential -MemberType NoteProperty -Name 'usage' -Value 'Sign'
    Add-Member -InputObject $newKeyCredential -MemberType NoteProperty -Name 'value' -Value $encodedClientSecret
    
    $keyCredentials += $newKeyCredential
    Add-Member -InputObject $newPolicy -MemberType NoteProperty -Name 'keyCredentials' -Value $keyCredentials

    # Create or Update Policy
    if($existingPolicy -and !$AddToNewPolicy) {
        if($Silent) {Set-AADObject -Type 'policies' -Id $existingPolicy.ObjectId -Object $newPolicy -Silent}
        else {Set-AADObject -Type 'policies' -Id $existingPolicy.ObjectId -Object $newPolicy}
    }
    else {
        if($Silent) {New-AADObject -Type 'policies' -Object $newPolicy -Silent}
        else {New-AADObject -Type 'policies' -Object $newPolicy}
    }

    # Create Admin Delegation
    if($ServicePrincipal) {
        if($Silent) {Create-AdminPermissionGrantIfNeeded -ServicePrincipalObjectId $ServicePrincipal -Silent}
        else {Create-AdminPermissionGrantIfNeeded -ServicePrincipalObjectId $ServicePrincipal}
    }
  }
}

function Remove-AADIdp {
    [CmdletBinding()]
  param (
    [parameter(Mandatory=$true,
    ValueFromPipeline=$true,
    HelpMessage="Choose from: Facebook, Google, Weibo, QQ, RenRen")]
    [string]
    $Idp,

    [parameter(Mandatory=$true,
    ValueFromPipeline=$true,
    HelpMessage="The client_id of the app you registered with the IDP.")]
    [string]
    $ClientId,

    [parameter(Mandatory=$false,
    ValueFromPipeline=$true,
    HelpMessage="The Object Id of the IDP Policy to update with new IDP.")]
    [string]
    $PolicyId,

    [parameter(Mandatory=$false,
    HelpMessage="Suppress console output.")]
    [switch]
    $Silent
  )
  PROCESS {
    $idpType = Map-IdpToIdpType($Idp)

    # Get specified policy or tenant default policy
    $policy = New-Object System.Object
    if ($PolicyId) {
        if($PolicyId = '') {
            Write-Host "Policy Id must be longer than zero characters." -ForegroundColor Yellow
            return
        }
        if ($Silent) {$policy = Get-AADPolicy -ObjectId $PolicyId -Silent}
        else {$policy = Get-AADPolicy -ObjectId $PolicyId}
    }
    else {
        if($Silent) {$policy = Get-TenantDefaultPolicy -Silent}
        else {$policy = Get-TenantDefaultPolicy}
    }
    if ($policy -eq $null) {
        Write-Host "No tenant default policy found and no policy specified." -ForegroundColor Yellow
        return
    }

    # Remove the correct Policy Chunk
    $policyDetailFormat = "{`"ClaimIssuancePolicy`":{`"Version`":1, `"AllowPassThruUsers`":`"true`"}, `"IdentityProviderPolicy`": [{policyChunks}]}"
    $storageRefId = ''
    $chunksKey = "`"IdentityProviderPolicy`": ["
    $policyChunks = $policy.policyDetail.Substring($policy.policyDetail.IndexOf($chunksKey) + $chunksKey.Length)
    $policyChunks = $policyChunks.Substring(0, $policyChunks.Length-2)
    $chunkKey = "{`"Version"
    $separator = @($chunkKey)
    $options = [System.StringSplitOptions]::RemoveEmptyEntries
    $policyChunks = $policyChunks.Split($separator, $options)
    $reconstructedChunks = ''
    $found = $false
    foreach($chunk in $policyChunks) {
        if ($chunk.Contains("Key: `"client_id`", Value: `"" + $ClientId + "`"") -and $chunk.Contains("Key: `"IdpType`", Value: `"" + $idpType + "`"")) {
            $found = $true
            $storageRefKey = "StorageReferenceId:`""
            $storageRefId = $chunk.Substring($chunk.IndexOf($storageRefKey) + $storageRefKey.Length, 36)
            continue
        }
        $reconstructedChunks += ($chunkKey + $chunk)
    }
    if($found) {
        $policy.policyDetail = $policyDetailFormat.Replace("{policyChunks}", $reconstructedChunks)
    }
    else {
        Write-Host "Client Id not found in default policy or specified policy." -ForegroundColor Yellow
        return
    }

    # Remove the associated Key
    Write-Host $policy.keyCredentials.GetType().FullName 
    Write-Host 'STOP'
    Write-Host $policy.KeyCredentials -ForegroundColor Yellow
 
    
    
    $resconstructedKeys = @()
    foreach($keyCred in $policy.keyCredentials) {
        Write-Host 'STOP'
        Write-Host $keyCred.keyId -ForegroundColor Yellow
 
        if($keyCred.keyId -eq $storageRefId) {
            Write-Host 'STOP'
            Write-Host 'Equal!' -ForegroundColor Yellow
            continue
        }
        $reconstructedKeys += $keyCred
    }
    $policy.KeyCredentials = $resconstructedKeys

    Write-Host $reconstructedKeys -ForegroundColor Yellow
    Write-Host 'STOP' -ForegroundColor Yellow
    Write-Host $policy.keyCredentials -ForegroundColor Yellow

    # Update the Policy, or Delete if all IDPs are removed
    if($policy.keyCredentials.Length -eq 0) {
        if($Silent) {Remove-AADObject -Type 'policies' -Id $policy.ObjectId -Silent}
        else {Remove-AADObject -Type 'policies' -Id $policy.ObjectId}
    }
    else {
        if($Silent) {Set-AADObject -Type 'policies' -Id $policy.ObjectId -Object $policy -Silent}
        else {Set-AADObject -Type 'policies' -Id $policy.ObjectId -Object $policy}
    }
  }
}

# TODO: What should the IssuerUri Actually Be?
function Map-IdpToIssuerUri([string]$Idp) {
    switch($Idp.ToLower()) {
        'google' {return 'https://google.mytenant.com'}
        'facebook' {return 'https://facebook.mytenant.com'}
        'qq' {return 'https://qq.mytenant.com'}
        'weibo' {return 'https://weibo.mytenant.com'}
        'renren' {return 'https://renren.mytenant.com'}
        default {return $null}
    }
}

function Map-IdpToIdpType([string]$Idp) {
    switch($Idp.ToLower()) {
        'google' {return '50'}
        'facebook' {return '51'}
        'qq' {return '52'}
        'weibo' {return '53'}
        'renren' {return '54'}
        default {return $null}
    }
}

# TODO: Put in own file w/full Creation & Update

function Get-AADoAuth2PermissionGrant {
    [CmdletBinding()]
    param (   
    [parameter(Mandatory=$false,
    HelpMessage="Suppress console output.")]
    [switch]
    $Silent,

    [parameter(Mandatory=$false,
    HelpMessage="The Object Id of the oAuth2PermissionGrant.")]
    [string]
    $ObjectId

    )
    PROCESS {
        if($ObjectId -ne $null -and $ObjectId -ne "") {
        if($Silent){Get-AADObjectById -Type "oAuth2PermissionGrants" -Id $ObjectId -Silent}
        else{Get-AADObjectById -Type "oAuth2PermissionGrants" -Id $ObjectId}
        }
        else {
            if($Silent){Get-AADObject -Type "oAuth2PermissionGrants" -Silent}
            else{Get-AADObject -Type "oAuth2PermissionGrants"}
        }
  }
}

function Remove-AADoAuth2PermissionGrant {
    [CmdletBinding()]
    param (
    [parameter(Mandatory=$true,
    ValueFromPipeline=$true,
    HelpMessage="The ObjectId of the oAuth2PermissionGrant")]
    [string]
    $Id,
    
    [parameter(Mandatory=$false,
    HelpMessage="Suppress console output.")]
    [switch]
    $Silent
  )
  PROCESS {
    if($Silent){Remove-AADObject -Type "oAuth2PermissionGrants" -Id $id -Silent}
    else{Remove-AADObject -Type "oAuth2PermissionGrants" -Id $id}
  }
}