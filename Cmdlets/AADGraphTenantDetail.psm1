function Get-AADTenantDetail {
  PROCESS {
    Get-AADObject -Type tenantDetails;
  }
}

function Set-AADTenantDetail {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $false,
    HelpMessage = "A list of additional email addresses for the user.")]
    [string[]] $MarketingNotificationMails,
    [parameter(Mandatory = $false,
    HelpMessage = "A list of additional email addresses for the user.")]
    [string[]] $TechnicalNotificationMails
  )
  PROCESS {
    $updatedTenantDetail = New-Object System.Object
               
    foreach($psbp in $PSBoundParameters.GetEnumerator()){
      $key = $psbp.Key
      $value = $psbp.Value
      if($key -eq "marketingNotificationMails" -or $key -eq "technicalNotificationMails") {
        Add-Member -InputObject $updatedTenantDetail -MemberType NoteProperty -Name $key -Value $value
      }
    }
    Set-AADObject -Type tenantDetails -Object $updatedUser
  }
}