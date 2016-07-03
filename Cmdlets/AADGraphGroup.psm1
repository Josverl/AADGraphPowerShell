
<#
.Synopsis
   Check if a user is a member of a group
   
.EXAMPLE
    $Grp = Get-AADObject -Type "groups" -Query "Generation-y"
    $result = Test-AADisMemberof -groupId $grp.objectId -memberId $li.objectId
    If ($result.value) { "{0} is a member of {1}" -f $li.displayName , $g2.displayName}

#>
function Test-AADisMemberOf{
[CmdletBinding()]
Param (
    ## Param1 help description    
    [string][Parameter(Mandatory=$true,Position=0)]
    $groupId, 
    [string]$memberId, 
    [switch] $Silent
)
    ## POST https://graph.windows.net/myorganization/isMemberOf?api-version 
    $newObject = $null
    if($global:AuthenticationResult -ne $null) {
        $header = $global:AuthenticationResult.CreateAuthorizationHeader()
        $uri = [string]::Format("{0}{1}/{2}?api-version={3}",
                    $global:aadGraphUrl,$global:AuthenticationResult.TenantId,
                    "isMemberOf",
                    $global:GraphAPIVersion)

        Write-verbose "HTTP POST - isMemberOf " 
        $enc = New-Object "System.Text.ASCIIEncoding"
        ## Put the parameters into an hastable and convert to json object 
        $object = @{ groupId = $groupId ; memberId = $memberId}
        $body = ConvertTo-Json -InputObject $Object -Depth 10
        Write-verbose $body 
        #convert to bytearray
        $byteArray = $enc.GetBytes($body)
        #add the headers
        $contentLength = $byteArray.Length
        $headers = @{"Authorization"=$header;"Content-Type"="application/json";"Content-Length"=$contentLength}
        #post the request 
        $result = Invoke-WebRequest -Method Post -Uri $uri -Headers $headers -Body $body
        #return 200 = OK 
        if($result.StatusCode -eq 200){
            Write-verbose "IsMemberof query succeeded."
            $newObject = (ConvertFrom-Json $result.Content)
        } else {
            Write-warning "IsMemberof query failed and returned $($result.StatusCode)"
            #will return $null 
        }
    }else{
        Write-Host "Not connected to an AAD tenant. First run Connect-AAD."
    }
    return $newObject
}
