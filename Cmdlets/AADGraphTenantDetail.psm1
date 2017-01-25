function Get-AADGraphTenantDetail {
  [CmdletBinding()]
  param (
    [parameter(Mandatory=$false,
    HelpMessage="Suppress console output.")]
    [switch]$Silent
  )
  PROCESS {
    Get-AADGraphObject -Type "tenantDetails" -Silent:$Silent
  }
}

function Set-AADGraphTenantDetail {
  [CmdletBinding()]
  param (
    [parameter(Mandatory=$false,
    HelpMessage="A list of additional email addresses for the user.")]
    [string[]]
    $marketingNotificationMails,

    [parameter(Mandatory=$false,
    HelpMessage="A list of additional email addresses for the user.")]
    [string[]]
    $technicalNotificationMails,
    
    [parameter(Mandatory=$false,
    HelpMessage="Suppress console output.")]
    [switch]
    $Silent
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
    Set-AADGraphObject -Type tenantDetails -Object $updatedTenantDetail -Silent:Silent
  }
}
