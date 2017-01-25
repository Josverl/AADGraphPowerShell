function Get-AADGraphGraphoAuth2PermissionGrant {
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
        if($Silent){Get-AADGraphGraphObjectById -Type "oauth2PermissionGrants" -Id $ObjectId -Silent}
        else{Get-AADGraphGraphObjectById -Type "oauth2PermissionGrants" -Id $ObjectId}
        }
        else {
            if($Silent){Get-AADGraphGraphObject -Type "oauth2PermissionGrants" -Silent}
            else{Get-AADGraphGraphObject -Type "oauth2PermissionGrants"}
        }
  }
}

function Remove-AADGraphGraphoAuth2PermissionGrant {
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
    if($Silent){Remove-AADGraphGraphObject -Type "oauth2PermissionGrants" -Id $id -Silent}
    else{Remove-AADGraphGraphObject -Type "oauth2PermissionGrants" -Id $id}
  }
}

function New-AADGraphGraphoAuth2PermissionGrant {
    [CmdletBinding()]
    param (   
    [parameter(Mandatory=$false,
    HelpMessage="Suppress console output.")]
    [switch]
    $Silent,

    [parameter(Mandatory=$true,
    HelpMessage="The Object Id of the service principal for which consent will be recorded.")]
    [string]
    $ServicePrincipalObjectId,

    [parameter(Mandatory=$true,
    HelpMessage="The Object Id of the resource for which consent will be recorded.")]
    [string]
    $ResourceObjectId,

    [parameter(Mandatory=$true,
    HelpMessage="A string of space-separted scopes for which consent will be recorded")]
    [string]
    $Scope,

    [parameter(Mandatory=$false,
    HelpMessage="The object Id of the princpal for which consent will be recorded. Not necessary if consentType == AllPrincipals")]
    [string]
    $PrincipalId,

    [parameter(Mandatory=$true,
    HelpMessage="'AllPrincipals' or 'Principal'.")]
    [string]
    $ConsentType

    )
    PROCESS {
        $endDate = (Get-Date).AddYears(1).ToString("yyyy-MM-ddTHH:mm:ss")
        $startDate = "0001-01-01T00:00:00"
        $grant = New-Object System.Object
        Add-Member -InputObject $grant -MemberType NoteProperty -Name 'clientId' -Value $ServicePrincipalObjectId
        Add-Member -InputObject $grant -MemberType NoteProperty -Name 'consentType' -Value $ConsentType
        Add-Member -InputObject $grant -MemberType NoteProperty -Name 'scope' -Value $Scope
        Add-Member -InputObject $grant -MemberType NoteProperty -Name 'resourceId' -Value $ResourceObjectId
        Add-Member -InputObject $grant -MemberType NoteProperty -Name 'expiryTime' -Value $endDate
        Add-Member -InputObject $grant -MemberType NoteProperty -Name 'startTime' -Value $startDate
        if($PrincipalId) {
            Add-Member -InputObject $grant -MemberType NoteProperty -Name 'principalId' -Value $PrincipalId
        }

        if ($Silent) {New-AADGraphGraphObject -Type 'oauth2PermissionGrants' -Object $grant -Silent}
        else {New-AADGraphGraphObject -Type 'oauth2PermissionGrants' -Object $grant}
  }
}

function Set-AADGraphGraphoAuth2PermissionGrant {
    [CmdletBinding()]
    param (   
    [parameter(Mandatory=$false,
    HelpMessage="Suppress console output.")]
    [switch]
    $Silent,

    [parameter(Mandatory=$true,
    HelpMessage="The Object Id of the service principal for which consent will be recorded.")]
    [string]
    $PermissionGrantObjectId,

    [parameter(Mandatory=$true,
    HelpMessage="The Object Id of the resource for which consent will be recorded.")]
    [string]
    $Scope
    )
    PROCESS {
        $grant = New-Object System.Object
        Add-Member -InputObject $grant -MemberType NoteProperty -Name 'scope' -Value $Scope

        if ($Silent) {Set-AADGraphGraphObject -Type 'oauth2PermissionGrants' -Id $PermissionGrantObjectId -Object $grant -Silent}
        else {Set-AADGraphGraphObject -Type 'oauth2PermissionGrants' -Id $PermissionGrantObjectId -Object $grant}
  }
}