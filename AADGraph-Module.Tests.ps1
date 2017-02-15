$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'

#Handle Module Testing Module 
$sut = $sut -replace '-Module', ''
$sut = $sut -replace '.ps1', '.psd1'

$ModuleUnderTest = Join-path $here $sut
Write-Verbose "Test Module : $ModuleUnderTest " -Verbose
#$VerbosePreference = 'Stop'

Import-Module -FullyQualifiedName $ModuleUnderTest 

Describe "AADGraph-Module" {
    
    $Mod = Test-ModuleManifest $ModuleUnderTest  -ErrorAction SilentlyContinue

    it "has a valid Module Manifest" {
               
        $Mod | Should Not be $null
        If ($mod) { 
            $mod.Name | Should be "AADGraph"
            $mod.ExportedCmdlets.Count | Should be 0
        }
    }

    it "has Exported Function" -Pending {
        $mod.ExportedFunctions.Count | Should be 15 
    }
    it "has nested modules"  {
        #Check if the ADAL Dlls are referenced 
        $mod.NestedModules.Count  -ge 1 | Should  be $true
    }

        it "has two nested modules" -Skip  {
        #Check if the ADAL Dlls are referenced 
        $mod.NestedModules.Count | Should  be 2
    }
}


