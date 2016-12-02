$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'

#Handle Module Testing Module 
$sut = $sut -replace '-Module', ''
$sut = $sut -replace '.ps1', '.psd1'

Write-Host "Test Module : $here\$sut" 
$VerbosePreference = 0

Import-Module -FullyQualifiedName "$here\$sut"

Describe "AADGraph-Module" {

    it "has a valid Module Manifest" {
        {$Mod = Test-ModuleManifest "$here\$sut" } | Should Not Throw 
        $mod.Name | Should be "AADGraph"

        $mod.ExportedCmdlets.Count | Should be 0
    }
    it "has Exported Function" {
        $mod.ExportedFunctions.Count | Should be 15 
    }
    it "has nested modules" {
 
        $mod.NestedModules.Count  | Should  be 0
    }

    it "Can Load the ADAL Libraries" -Pending {
    }



}


