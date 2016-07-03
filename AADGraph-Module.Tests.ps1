$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'

#Handle Module Testing Module 
$sut = $sut -replace '-Module', ''
$sut = $sut -replace '.ps1', ''

$VerbosePreference = 2
Import-Module -FullyQualifiedName "$here\$sut"

Describe "AADGraph-Module" {
    It "does something useful" {
        $true | Should Be $false
    }
}
