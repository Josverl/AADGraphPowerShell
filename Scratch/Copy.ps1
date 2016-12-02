$Source = 'C:\Users\Jos\OneDrive\PowerShell\Dev\AADGraph'
$Dest = 'C:\Users\Jos\OneDrive\PowerShell\Dev\AADGraph\Release' 

$exclude = @('*.pdb','*.config','.git')
$Excludedir = @('Release','.git','Scratch','test')
#Get-ChildItem $source -Recurse -Exclude $exclude | Copy-Item -Destination {Join-Path $dest $_.FullName.Substring($source.length)} -Verbose

Get-ChildItem $source -Recurse -Exclude $exclude | where {$Excludedir -notcontains $_.DirectoryName }| %{

    Write-Verbose $_.Basename -Verbose
#    $_ | Copy-Item -Destination {Join-Path $dest $_.FullName.Substring($source.length)}
}

