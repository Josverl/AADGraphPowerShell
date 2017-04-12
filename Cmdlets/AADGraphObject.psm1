#JV - Add Progress indicator 
#JV - add page size
#JV - use verbosepreferences 

$Script:SkipToken = "";

function Test-AADGraphNextObject {
    #If there is a skiptoken, then there is a next object 
    return ([string]::IsNullOrEmpty($Script:SkipToken) -eq $false)
}


function Get-AADGraphObject{
[CmdletBinding()]
param ([string]$Type, 
    [string]$Query="", 
    [switch] $All, 
    [switch] $Silent, 
    $PageSize = 100 ,
    [Switch]$Next      #get the next Page, continue on from the last page(s) read.
    
     ) 
    $objects = $null
    $Page= 0 #Page Counter
    #variable page size between 1 - 999 
    #Suppress top=100 as that is the default
    $TopString = if($PageSize -eq 100 -or $PageSize -lt 1 -or $PageSize -ge 999) {""} else {"&$"+"top=$PageSize"}
    
    #used for progress reporting
    $activity = "Get {0}" -f $Type

    #Check if we are yet authenticated 
    if($global:AuthenticationResult -eq $null){
        Write-warning "Not connected to an AAD tenant. First run Connect-AADGraph." 
        return $null
    }
    #and build the authentication
    $header = $global:AuthenticationResult.CreateAuthorizationHeader()

    #Create the Base URI 
    $BaseUri = [string]::Format("{0}{1}/{2}?api-version={3}{4}{5}",$global:aadGraphUrl,$global:AuthenticationResult.TenantId,$Type.Trim(),$global:GraphAPIVersion,$Query,$TopString)
    
    #Next page is possible , if a prior page had more results  
    if ($Next -and $Script:SkipToken -eQ $null) {
        Write-Error '-Next page requested withouth a prior saved skiptoken'
        Throw 'Paging error' 
    } 
    if ($Next -and $Script:SkipToken -ne $null) {
        Write-Verbose 'Starting using remembered skiptoken'
        $PageUri = $BaseUri + "&" + $Script:SkipToken.Split('?')[1] 
    } else {
        #the default ; start at the beginning
        $PageUri = $BaseUri
    }
    Write-Verbose "FIRST HTTP GET $PageUri" 
    $result = Invoke-Webrequest -UseBasicParsing -Method Get -Uri $PageUri -Headers @{"Authorization"=$header;"Content-Type"="application/json"}
    if($result.StatusCode -eq 200){
        $page++;
        $oDataSet= (ConvertFrom-Json $result.Content)
        if($oDataSet-ne $null){
            #objects were retrieved , so deserialze them from json 
            $objects = $oDataSet.value
            #Save the odata skiptoken for the next page if there is one 
            $Script:SkipToken = $oDataSet."odata.nextLink"
            if($Script:SkipToken -ne $null){
                Write-Verbose "More data..."
                $MoreData = $true
                if($all ){
                    #There is more data , and we need to get all data, so also get the next page 
                    do{
                        $page++
                        Write-Progress -Activity $activity -Status "Getting page : $Page" 
                        Write-Verbose "Getting the next page of results." 
                        $PageUri = $BaseUri + "&" + $Script:SkipToken.Split('?')[1] 

                        Write-Verbose "HTTP GET $PageUri"
                        # subsequent pages are the same size as the first one
                        $result = Invoke-Webrequest -UseBasicParsing -Method Get -Uri $PageUri -Headers @{"Authorization"=$header;"Content-Type"="application/json"} 
                        if($result.StatusCode -eq 200){
                            $oDataSet= (ConvertFrom-Json $result.Content)
                            if($oDataSet-ne $null){
                                $objects += $oDataSet.value
                                $Script:SkipToken = $oDataSet."odata.nextLink"
                    
                                if($Script:SkipToken -ne $null){
                                    Write-Verbose "More data..."
                                    $MoreData = $true}
                                else{
                                    $MoreData = $false
                                }
                            }
                        }
                    } until(-not $MoreData)

                    Write-Progress -Activity $activity -Completed
                }
            }
        }
    }
    return $objects
}

# get a single AAD Object 
function Get-AADGraphObjectById  {
param([string]$Type, [string]$Id, [switch] $Silent)

  $object = $null
  if($global:AuthenticationResult -ne $null){
    $header = $global:AuthenticationResult.CreateAuthorizationHeader()
    $BaseUri = [string]::Format("{0}{1}/{2}/{3}?api-version={4}",$global:aadGraphUrl,$global:AuthenticationResult.TenantId,$Type.Trim(), $Id.Trim(),$global:GraphAPIVersion)
    if(-not $Silent){
      Write-Host HTTP GET $BaseUri -ForegroundColor Cyan
    }
    $result = Invoke-Webrequest -UseBasicParsing -Method Get -Uri $BaseUri -Headers @{"Authorization"=$header;"Content-Type"="application/json"}
    if($result.StatusCode -eq 200)
    {
      if(-not $Silent){
        Write-Host "Get succeeded." -ForegroundColor Cyan
      }
      $object = (ConvertFrom-Json $result.Content)
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AADGraph." -ForegroundColor Yellow
  }
  return $object
}

#create a new object in AAD 
function New-AADGraphObject([string]$Type, [object]$Object, [switch] $Silent) {
  $newObject = $null
  if($global:AuthenticationResult -ne $null) {
    $header = $global:AuthenticationResult.CreateAuthorizationHeader()
    $BaseUri = [string]::Format("{0}{1}/{2}?api-version={3}",$global:aadGraphUrl,$global:AuthenticationResult.TenantId,$Type.Trim(),$global:GraphAPIVersion)
    if(-not $Silent){
      Write-Host HTTP POST $BaseUri -ForegroundColor Cyan
    }
    $enc = New-Object "System.Text.ASCIIEncoding"
    $body = ConvertTo-Json -InputObject $Object -Depth 10
    if(-not $Silent){
      Write-Host $body -ForegroundColor Cyan
    }
    $byteArray = $enc.GetBytes($body)
    $contentLength = $byteArray.Length
    $headers = @{"Authorization"=$header;"Content-Type"="application/json";"Content-Length"=$contentLength}
    $result = Invoke-Webrequest -UseBasicParsing -Method Post -Uri $BaseUri -Headers $headers -Body $body
    if($result.StatusCode -eq 201){
      if(-not $Silent){
        Write-Host "Create succeeded." -ForegroundColor Cyan
      }
      $newObject = (ConvertFrom-Json $result.Content)
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AADGraph."
  }
  return $newObject
}

#Update / chnage an existing AAD object
function Set-AADGraphObject([string]$Type, [string]$Id, [object]$Object, [switch] $Silent) {
  if($global:AuthenticationResult -ne $null) {
    $header = $global:AuthenticationResult.CreateAuthorizationHeader()
    $BaseUri = [string]::Format("{0}{1}/{2}/{3}?api-version={4}",$global:aadGraphUrl,$global:AuthenticationResult.TenantId,$Type.Trim(), $Id.Trim(),$global:GraphAPIVersion)
    if(-not $Silent){
      Write-Host HTTP PATCH $BaseUri -ForegroundColor Cyan
    }
    $enc = New-Object "System.Text.ASCIIEncoding"
    $body = ConvertTo-Json -InputObject $Object -Depth 10
    if(-not $Silent){
      Write-Host $body -ForegroundColor Cyan
    }
    $byteArray = $enc.GetBytes($body)
    $contentLength = $byteArray.Length
    $headers = @{"Authorization"=$header;"Content-Type"="application/json";"Content-Length"=$contentLength}
    $result = Invoke-Webrequest -UseBasicParsing -Method Patch -Uri $BaseUri -Headers $headers -Body $body
    if($result.StatusCode -eq 204){
      if(-not $Silent){
        Write-Host "Update succeeded." -ForegroundColor Cyan
      }
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AADGraph." -ForegroundColor Yellow
  }
}

#Remove / delete an object from the directory 
function Remove-AADGraphObject([string]$Type, [string]$Id, [switch] $Silent) {
  if($global:AuthenticationResult -ne $null) {
    $header = $global:AuthenticationResult.CreateAuthorizationHeader()
    $BaseUri = [string]::Format("{0}{1}/{2}/{3}?api-version={4}",$global:aadGraphUrl,$global:AuthenticationResult.TenantId,$Type.Trim(), $Id.Trim(),$global:GraphAPIVersion)
    if(-not $Silent){
      Write-Host HTTP DELETE $BaseUri -ForegroundColor Cyan
    }
    $headers = @{"Authorization"=$header;"Content-Type"="application/json"}
    $result = Invoke-Webrequest -UseBasicParsing -Method Delete -Uri $BaseUri -Headers $headers
    if($result.StatusCode -eq 204){
      if(-not $Silent){
        Write-Host "Delete succeeded." -ForegroundColor Cyan
      }
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AADGraph." -ForegroundColor Yellow
  }
}

function Get-AADGraphLinkedObject([string]$Type, [string] $Id, [string]$Relationship, [switch]$GetLinksOnly, [switch]$Binary, [switch]$All, [switch]$Silent) {
  $objects = $null
  if($global:AuthenticationResult -ne $null){
    $header = $global:AuthenticationResult.CreateAuthorizationHeader()
    $BaseUri = $null
    if($GetLinksOnly) {
      $BaseUri = [string]::Format("{0}{1}/{2}/{3}/`$links/{4}?api-version={5}",$global:aadGraphUrl,$global:AuthenticationResult.TenantId, $Type, $Id, $Relationship,$global:GraphAPIVersion)
    }
    else {
      $BaseUri = [string]::Format("{0}{1}/{2}/{3}/{4}?api-version={5}",$global:aadGraphUrl,$global:AuthenticationResult.TenantId, $Type, $Id, $Relationship,$global:GraphAPIVersion)
    }
    if(-not $Silent) {
      Write-Host HTTP GET $BaseUri -ForegroundColor Cyan
    }
    $result = Invoke-Webrequest -UseBasicParsing -Method Get -Uri $BaseUri -Headers @{"Authorization"=$header;"Content-Type"="application/json"}
    if($result.StatusCode -eq 200){
      if(-not $Silent) {
        Write-Host "Get succeeded." -ForegroundColor Cyan
      }
      if(-not $Binary) {
        $oDataSet= (ConvertFrom-Json $result.Content)
        if($oDataSet-ne $null){
          $objects = $oDataSet.value
          $Script:SkipToken = $oDataSet."odata.nextLink"
          if($Script:SkipToken -ne $null){
            if($all){
              $MoreData = $true
              do{
                if(-not $Silent){
                  Write-Host "Getting the next page of results." -ForegroundColor Cyan
                  Write-Host HTTP GET ($BaseUri + "&" + $Script:SkipToken.Split('?')[1]) -ForegroundColor Cyan
                }
                $result = Invoke-Webrequest -UseBasicParsing -Method Get -Uri ($BaseUri + "&" + $Script:SkipToken.Split('?')[1]) -Headers @{"Authorization"=$header;"Content-Type"="application/json"}
                if($result.StatusCode -eq 200){
                  $oDataSet= (ConvertFrom-Json $result.Content)
                  if($oDataSet-ne $null){
                    $objects += $oDataSet.value
                    $Script:SkipToken = $oDataSet."odata.nextLink"
                    if($Script:SkipToken -ne $null){$MoreData = $true}
                    else{$MoreData = $false}
                  }
                }
              }
              until(-not $MoreData)
            }
          }
        }
      }
      else {
        $objects = $result.Content
      }
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AADGraph." -ForegroundColor Yellow
  }
  return $objects
}

function Set-AADGraphObjectProperty([string]$Type, [string] $Id, [string]$Property, [object]$Value, [bool]$IsLinked, [string]$ContentType, [ValidateSet("PUT", "POST", ignorecase=$true)][string]$HTTPMethod = "PUT", [switch] $Silent) {
  if($global:AuthenticationResult -ne $null) {
    $header = $global:AuthenticationResult.CreateAuthorizationHeader()
    $BaseUri = $null
    if($IsLinked) {
      $BaseUri = [string]::Format('{0}{1}/{2}/{3}/$links/{4}?api-version={5}',$global:aadGraphUrl,$global:AuthenticationResult.TenantId,$Type, $Id, $Property,$global:GraphAPIVersion)
    }
    else {
      $BaseUri = [string]::Format('{0}{1}/{2}/{3}/{4}?api-version={5}',$global:aadGraphUrl,$global:AuthenticationResult.TenantId,$Type, $Id, $Property,$global:GraphAPIVersion)
    }
    
    if(-not $Silent){
      Write-Host HTTP $HTTPMethod.ToUpper() $BaseUri -ForegroundColor Cyan
    }
    $body = $null
    $byteArray = $null
    
    if($contentType.Trim() -eq "" -or $contentType -eq $null -or $contentType.ToLower() -eq "application/json") {
      $contentType = "application/json"
      $enc = New-Object "System.Text.ASCIIEncoding"
      $body = ConvertTo-Json -InputObject $Value -Depth 10
      $byteArray = $enc.GetBytes($body)
      if(-not $Silent){
        Write-Host $body -ForegroundColor Cyan
      }
    }
    elseif ($contentType.ToLower() -eq "image/jpeg" -or $contentType.ToLower() -eq "image/png" -or $contentType.ToLower() -eq "image/gif") {
      $contentType = $contentType.ToLower()
      $body = $Value
      $byteArray = $Value
      if(-not $Silent){
        Write-Host "Body of the request is binary data." -ForegroundColor Cyan
      }
    }
    $contentLength = $byteArray.Length
    $headers = @{"Authorization"=$header;"Content-Type"=$contentType;"Content-Length"=$contentLength}
    $result = Invoke-Webrequest -UseBasicParsing -Method $HTTPMethod -Uri $BaseUri -Headers $headers -Body $body
    if($result.StatusCode -eq 204){
      if(-not $Silent){
        Write-Host "Update succeeded." -ForegroundColor Cyan
      }
    }
  }
  else{
    Write-Host "Not connected to an AAD tenant. First run Connect-AADGraph." -ForegroundColor Yellow
  }
}
