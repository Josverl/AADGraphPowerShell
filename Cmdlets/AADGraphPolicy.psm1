function Get-AADGraphGraphPolicy {
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
      if($Silent){Get-AADGraphGraphObjectById -Type "policies" -Id $ObjectId -Silent}
      else{Get-AADGraphGraphObjectById -Type "policies" -Id $ObjectId}
    }
    else {
      if($Silent){Get-AADGraphGraphObject -Type "policies" -Silent}
      else{Get-AADGraphGraphObject -Type "policies"}
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
        if($Silent) {$existingPolicies = Get-AADGraphGraphPolicy -Silent}
        else {$existingPolicies = Get-AADGraphGraphPolicy}

        foreach($policy in $existingPolicies) {
            if($policy.tenantDefaultPolicy -eq '1') {return $policy}
        }
        return $null
  }
}

function Enable-SocialIdp {
    # TODO
}

function New-AADGraphGraphIdp {
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
        if($Silent) {$existingPolicy = Get-AADGraphGraphPolicy -ObjectId $PolicyId -Silent}
        else {$existingPolicy = Get-AADGraphGraphPolicy -ObjectId $PolicyId}
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
        # Dont add a tenantDefaultPolicy Flag
    }
    elseif($existingPolicy.tenantDefaultPolicy) {
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
    $policyDetail = New-Object System.Object
    $claimIssuancePolicy = New-Object System.Object
    Add-Member -InputObject $claimIssuancePolicy -MemberType NoteProperty -Name 'Version' -Value 1
    Add-Member -InputObject $claimIssuancePolicy -MemberType NoteProperty -Name 'AllowPassThruUsers' -Value $true
    Add-Member -InputObject $policyDetail -MemberType NoteProperty -Name 'ClaimIssuancePolicy' -Value $claimIssuancePolicy

    $idpPolicy = @()
    if ($existingPolicy -and !($AddToNewPolicy)) {
        $existingPolicyDetail = ConvertFrom-Json -InputObject $existingPolicy.policyDetail[0]
        $idpPolicy = $existingPolicyDetail.IdentityProviderPolicy
    }
    
        # TODO: Prevent the same IDP/Client_id tuple from being used twice.

    $newIdpType = New-Object System.Object
    Add-Member -InputObject $newIdpType -MemberType NoteProperty -Name 'Key' -Value 'IdpType'
    Add-Member -InputObject $newIdpType -MemberType NoteProperty -Name 'Value' -Value $idpType
    $newClientId = New-Object System.Object
    Add-Member -InputObject $newClientId -MemberType NoteProperty -Name 'Key' -Value 'client_id'
    Add-Member -InputObject $newClientId -MemberType NoteProperty -Name 'Value' -Value $ClientId
    $newCryptoKey = New-Object System.Object
    Add-Member -InputObject $newCryptoKey -MemberType NoteProperty -Name 'Id' -Value 'client_secret'
    Add-Member -InputObject $newCryptoKey -MemberType NoteProperty -Name 'StorageReferenceId' -Value $clientSecretStorageKey
    $newPolicyChunk = New-Object System.Object
    Add-Member -InputObject $newPolicyChunk -MemberType NoteProperty -Name 'Version' -Value 1
    Add-Member -InputObject $newPolicyChunk -MemberType NoteProperty -Name 'IssuerURI' -Value $issuerUri
    Add-Member -InputObject $newPolicyChunk -MemberType NoteProperty -Name 'Protocol' -Value 'OAuth2'
    Add-Member -InputObject $newPolicyChunk -MemberType NoteProperty -Name 'Metadata' -Value @($newIdpType, $newClientId)
    Add-Member -InputObject $newPolicyChunk -MemberType NoteProperty -Name 'CryptographicKeys' -Value @($newCryptoKey)
    Add-Member -InputObject $newPolicyChunk -MemberType NoteProperty -Name 'OutputClaims' -Value @()

    $idpPolicy += $newPolicyChunk
    Add-Member -InputObject $policyDetail -MemberType NoteProperty -Name 'IdentityProviderPolicy' -Value $idpPolicy
    $serializedPolicyDetail = ConvertTo-Json -InputObject $policyDetail -Depth 10 -Compress
    Add-Member -InputObject $newPolicy -MemberType NoteProperty -Name 'policyDetail' -Value @($serializedPolicyDetail)

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
        if($Silent) {Set-AADGraphGraphObject -Type 'policies' -Id $existingPolicy.ObjectId -Object $newPolicy -Silent}
        else {Set-AADGraphGraphObject -Type 'policies' -Id $existingPolicy.ObjectId -Object $newPolicy}
    }
    else {
        if($Silent) {New-AADGraphGraphObject -Type 'policies' -Object $newPolicy -Silent}
        else {New-AADGraphGraphObject -Type 'policies' -Object $newPolicy}
    }

    # Create Admin Delegation
    if($ServicePrincipal) {
        if($Silent) {New-AADGraphGraphAdminPermissionGrantIfNeeded -ServicePrincipalObjectId $ServicePrincipal -Silent}
        else {New-AADGraphGraphAdminPermissionGrantIfNeeded -ServicePrincipalObjectId $ServicePrincipal}
    }
  }
}

function Remove-AADGraphGraphIdp {
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
        if ($Silent) {$policy = Get-AADGraphGraphPolicy -ObjectId $PolicyId -Silent}
        else {$policy = Get-AADGraphGraphPolicy -ObjectId $PolicyId}
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
    $policyDetail = ConvertFrom-Json -InputObject $policy.policyDetail[0]
    $storageRefId = ''
    $reconstructedIdpPolicy = @()
    $found = $false
    foreach($chunk in $policyDetail.IdentityProviderPolicy) {
        $isIdp = $false
        $isClientId = $false
        foreach ($kvp in $chunk.Metadata) {
            if($kvp.Key -eq 'IdpType' -and $kvp.Value -eq $idpType) {
                $isIdp = $true
            }
            elseif($kvp.Key -eq 'client_id' -and $kvp.Value -eq $ClientId) {
                $isClientId = $true
            }
        }
        if($isIdp -and $isClientId) {
            $found = $true
            $storageRefId = $chunk.CryptographicKeys[0].StorageReferenceId
            continue
        }
        $reconstructedIdpPolicy += $chunk
    }
    if($found) {
        $policyDetail.IdentityProviderPolicy = $reconstructedIdpPolicy
        $serializedPolicyDetail = ConvertTo-Json -InputObject $policyDetail -Depth 10 -Compress
        $policy.policyDetail = @($serializedPolicyDetail)
    }
    else {
        Write-Host "Client Id not found in default policy or specified policy." -ForegroundColor Yellow
        return
    }

    # Remove the associated Key
    $existingCredentials = $policy.keyCredentials
    $policy.keyCredentials = @()
    foreach($keyCred in $existingCredentials) {
        if($keyCred.keyId -eq $storageRefId) {
            continue
        }
        $policy.keyCredentials += $keyCred
    }

    # Update the Policy, or Delete if all IDPs are removed
    if($policy.keyCredentials.Length -eq 0) {
        if($Silent) {Remove-AADGraphGraphObject -Type 'policies' -Id $policy.ObjectId -Silent}
        else {Remove-AADGraphGraphObject -Type 'policies' -Id $policy.ObjectId}
    }
    else {
        if($Silent) {Set-AADGraphGraphObject -Type 'policies' -Id $policy.ObjectId -Object $policy -Silent}
        else {Set-AADGraphGraphObject -Type 'policies' -Id $policy.ObjectId -Object $policy}
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

function New-AADGraphGraphAdminPermissionGrantIfNeeded {
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
        if($Silent) {$grants = Get-AADGraphGraphObject -Type 'oauth2PermissionGrants' -Silent}
        else {$grants = Get-AADGraphGraphObject -Type 'oauth2PermissionGrants'}

        $graphResourceId = Get-GraphResourceId

        foreach($grant in $grants) {
            if($grant.clientId -eq $ServicePrincipalObjectId -and $grant.consentType -eq 'AllPrincipals' -and $grant.resourceId -eq $graphResourceId) {
                $scope = ''
                if ($grant.scope) {$scope = $grant.scope}
                if (!$scope.Contains('user_impersonation')) {$scope += ' user_impersonation'}
                if(!$Silent) {Set-AADGraphGraphoAuth2PermissionGrant -PermissionGrantObjectId $grant.objectId -Scope $scope -Silent}
                else {Set-AADGraphGraphoAuth2PermissionGrant -PermissionGrantObjectId $grant.objectId -Scope $scope}
                return 
            }
        }

        if ($Silent) {New-AADGraphGraphoAuth2PermissionGrant -ServicePrincipalObjectId $ServicePrincipalObjectId -ResourceObjectId $graphResourceId -Scope 'user_impersonation' -ConsentType 'AllPrincipals' -Silent}
        else {New-AADGraphGraphoAuth2PermissionGrant -ServicePrincipalObjectId $ServicePrincipalObjectId -ResourceObjectId $graphResourceId -Scope 'user_impersonation' -ConsentType 'AllPrincipals'}
  }
}

function Get-GraphResourceId() {
    switch($global:aadGPoShEnv.ToLower()) {
        'ppe' {return '97ceba2e-60aa-4b82-968f-d0a1c17570c1'}
        # TODO: Other environments
        default {return $null}
    }
}

