﻿# Module manifest for module 'AADGraph'
@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'AADGraph.psm1'
    # Version number of this module.
    ModuleVersion = '1.2'
    # ID used to uniquely identify this module
    GUID = 'f166fdf6-859a-4649-ab4e-b4e3dc47c39e'
    # Author of this module
    Author = @( 'Dushyant.Gill', 'Jos.Verlinde' )
    # Company or vendor of this module
    CompanyName = 'dushyantgill.com'
    # Copyright statement for this module
    Copyright = '(c) 2014 Dushyant Gill. All rights reserved.'
    # Description of the functionality provided by this module
    Description = 'A PowerShell Client for Windows Azure AD Graph APIs'
    # Minimum version of the Windows PowerShell engine required by this module
    # PowerShellVersion = ''
    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''
    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''
    # Minimum version of Microsoft .NET Framework required by this module
    # DotNetFrameworkVersion = ''
    # Minimum version of the common language runtime (CLR) required by this module
    # CLRVersion = ''
    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''
    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()
    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()
    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()
    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()
    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()
    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        '.\Microsoft.IdentityModel.Clients.ActiveDirectory.2.28.2\lib\net45\Microsoft.IdentityModel.Clients.ActiveDirectory.dll',
        '.\Microsoft.IdentityModel.Clients.ActiveDirectory.2.28.2\lib\net45\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll',
        '.\Cmdlets\AADGraphObject.psm1', 
        '.\Cmdlets\AADGraphUser.psm1',
        '.\Cmdlets\AADGraphGroup.psm1',
        '.\Cmdlets\AADGraphPermission.psm1', 
        '.\Cmdlets\AADGraphPolicy.psm1',
        '.\Cmdlets\AADGraphTenantDetail.psm1'
    )
    # Functions to export from this module
    FunctionsToExport = @(
        'Connect-AADGraphGraph', 
        'Get-AADGraphGraphObject', 
        'Get-AADGraphGraphObjectById', 
        'New-AADGraphGraphObject', 
        'Set-AADGraphGraphObject', 
        'Remove-AADGraphGraphObject',`
        'Get-AADGraphGraphLinkedObject', 
        'Set-AADGraphGraphObjectProperty', 
        'Get-AADGraphGraphUser', 
        'New-AADGraphGraphUser', 
        'Set-AADGraphGraphUser', 
        'Remove-AADGraphGraphUser', 
        'Set-AADGraphGraphUserThumbnailPhoto',`
        'Get-AADGraphGraphTenantDetail',
        'Set-AADGraphGraphTenantDetail')
    # Cmdlets to export from this module
    CmdletsToExport = '*'
    # Variables to export from this module
    VariablesToExport = '*'
    # Aliases to export from this module
    AliasesToExport = '*'
    # List of all modules packaged with this module
    # ModuleList = @()
    # List of all files packaged with this module
    # FileList = @()
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    # PrivateData = ''
    # HelpInfo URI of this module
    # HelpInfoURI = ''
    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
}
