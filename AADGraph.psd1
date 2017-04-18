# Module manifest for module 'AADGraph'
@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'AADGraph.psm1'
    # Version number of this module.
    ModuleVersion = '1.5'
    # ID used to uniquely identify this module
    GUID = 'f166fdf6-859a-4649-ab4e-b4e3dc47c39e'
    # Author of this module
    Author = @( 'Dushyant.Gill', 'Jos.Verlinde' )
    # Company or vendor of this module
    CompanyName = 'dushyantgill.com'
    # Copyright statement for this module
    Copyright = '(c) 2014 Dushyant Gill, Jos Verlinde. All rights reserved.'
    # Description of the functionality provided by this module
    Description = 'A PowerShell Client for Windows Azure AD Graph APIs'
    # Minimum version of the Windows PowerShell engine required by this module
    # PowerShellVersion = ''
    # Minimum version of Microsoft .NET Framework required by this module
    DotNetFrameworkVersion = '4.5'

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    NestedModules = @(
        '.\Microsoft.IdentityModel.Clients.ActiveDirectory.2.28.2\lib\net45\Microsoft.IdentityModel.Clients.ActiveDirectory.dll',
 #      '.\Microsoft.IdentityModel.Clients.ActiveDirectory.2.28.2\lib\net45\Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll',
        '.\Cmdlets\AADGraphObject.psm1', 
        '.\Cmdlets\AADGraphUser.psm1',
        '.\Cmdlets\AADGraphGroup.psm1',
        '.\Cmdlets\AADGraphPermission.psm1', 
        '.\Cmdlets\AADGraphPolicy.psm1',
        '.\Cmdlets\AADGraphTenantDetail.psm1'
    )
    # Functions to export from this module
    FunctionsToExport = @(
        'Connect-AADGraph', 
        'Get-AADGraphObject', 
        'Get-AADGraphObjectById', 
        'New-AADGraphObject', 
        'Set-AADGraphObject',
        'Test-AADGraphNextObject',
        'Remove-AADGraphObject',`
        'Get-AADGraphLinkedObject', 
        'Set-AADGraphObjectProperty', 
        'Get-AADGraphUser', 
        'New-AADGraphUser', 
        'Set-AADGraphUser', 
        'Remove-AADGraphUser', 
        'Set-AADGraphUserThumbnailPhoto',`
        'Get-AADGraphTenantDetail',
        'Set-AADGraphTenantDetail')
    # Cmdlets to export from this module
    CmdletsToExport = '*'
    # Variables to export from this module
    VariablesToExport = '*'
    # Aliases to export from this module
    AliasesToExport = '*'
}
