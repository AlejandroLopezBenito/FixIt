<#
    .SYNOPSIS
    Creates a database server and uses it to create an application database
    and a member database.
            
    .DESCRIPTION
    The New-AzureSql.ps1 script automates the process of creating databases
    for a web site. The New-AzureWebSiteEnv.ps1 script calls this script.

    New-AzureSql.ps1 creates a database server in the subscription,
    (New-AzureSqlDatabaseServer), adds firewall rules for the database 
    server (New-AzureSqlDatabaseServerFirewallRule), creates a new connection
    context to the specified SQL database server 
    (New-AzureSqlDatabaseServerContext), and then creates an application 
    database and a member database (New-AzureSqlDatabase).
    
    The script creates two firewall rules. One, named for the app, allows 
    computers in the specified IP address range to access the database 
    server. You can define the range by entering the starting and ending IP 
    addresses. If you don't, the script gets the public IP address of the 
    local machine and replaces the final parts with 0 (start) and 255 (end).

    It also creates an "AllowAllAzureIP" filewall rule that allows Windows Azure
    machines to access the database server.

    New-AzureSql.ps1 requires that Windows Azure PowerShell
    be installed and configured to work with your Windows Azure
    subscription. For details, see "How to install and configure 
    Windows Azure PowerShell" at 
    http://go.microsoft.com/fwlink/?LinkID=320552.

    .PARAMETER ResourceGroup
    Specifies a resource group where the resources will be added to.
	
    .PARAMETER DatabaseServerName
    Specifies a name for the application database server. The default value is 
    "server".
            
    .PARAMETER AppDatabaseName
    Specifies a name for the application database. The default value is 
    "appdb".

    .PARAMETER MemberDatabaseName
    Specifies a name for the member database. The default value is 
    "memberdb".

    .PARAMETER UserName
    Specifies a user name. The default value is "dbuser".
    The user name is used as the administrator account on 
    the database server and in the credentials for the 
    application and member databases. 
    
    .PARAMETER Password
    Specifies a pasword for the administrator account.
    This parameter is required. The password is used for
    the administrator account on the database server and 
    in the credentials for the application and member 
    databases. 

    .PARAMETER FirewallRuleName
    Specifies a name for the firewall rule that allow
    a range of IP addresses to access the website. The
    default value is "WebsiteRule".

    When the New-AzureWebsiteEnv.ps1 script calls this
    script, it specifies a value of <Website_Name>Rule 
    for this parameter.

    .PARAMETER Location
    Specifies the location of the Windows Azure subscription. The
    default is "West US"

    Valid values:
    -- East Asia
    -- East US
    -- North Central US
    -- North Europe
    -- West Europe
    -- West US
    
    .PARAMETER StartIPAddress
    The starting address of the range of IP addresses in the SQL 
    Azure firewall rule. If you omit this parameter, the script 
    creates an IP address range from the public IP address of the 
    local machine.

    .PARAMETER EndIPAddress
    The last address of the range of IP addresses in the SQL 
    Azure firewall rule. If you omit this parameter, the script 
    creates an IP address range from the public IP address of the 
    local machine.
    

    .INPUTS
    System.String

    .OUTPUTS
    System.Collections.Hashtable
    Returns a hashtable of values for the database server, 
    the application database, and the member database.

    .NOTES
    This script sets the $VerbosePreference variable to "Continue", so all 
    Verbose messages are displayed without using the Verbose common parameter. 
    It also sets the $ErrorActionPreference variable to "Stop" which stops the
    script when it generates non-terminating errors.

    .EXAMPLE
    PS C:\> $hash = .\New-AzureSql.ps1 -Password P@ssw0rd

    PS C:\> $hash

    Name                           Value                                                                                                                                                           
    ----                           -----                                                                                                                                                           
    ConnectionString               BlobEndpoint=http://ContosoStorage.blob.core.windows.net/;QueueEndpoint=http://ContosoStorage.queue.core.windows.net/;TableEndpoint=http://ContosoStorage.tab...
    AccessKey                      XrmGWqu9qpgKX5G3lf+V5Bc0nFIGjGWiWhHTdMxkA5Mb4WjJ0rDV+3USWW/6fAWCrszrkr2+JUb1c5mxQdq4nw==                                                                        
    AccountName                    ContosoStorage

    PS C:\> $hash.ConnectionString
    BlobEndpoint=http://ContosoStorage.blob.core.windows.net/;QueueEndpoint=http://ContosoStorage.queue.core.windows.net/;TableEndpoint=http://ContosoStorage.table.core.windows.net/;AccountName='
        ContosoStorage';AccountKey='XrmGWqu9qpgKX5G3lf+V5Bc0nFIGjGWiWhHTdMxkA5Mb4WjJ0rDV+3USWW/6fAWCrszrkr2+JUb1c5mxQdq4nw=='

    .EXAMPLE
    .\New-AzureSql.ps1 -AppDatabaseName TestApp -MemberDatabaseName -TestMembers `
        -UserName Admin01 -Password P@ssw0rd -FirewallRuleName TestAppRule `
        -StartIpAddress 216.142.28.0 -EndIPAddress 216.142.28.255 `
        -Location "West Europe"
 
    .LINK
    New-AzureWebsiteEnv.ps1

    .LINK
    New-AzureSqlDatabaseServer

    .LINK
    New-AzureSqlDatabaseServerFirewallRule

    .LINK
    New-AzureSqlDatabaseServerContext

    .LINK
    New-AzureSqlDatabase

    .LINK
    Windows Azure Management Cmdlets (http://go.microsoft.com/fwlink/?LinkID=386337)

    .LINK
    How to install and configure Windows Azure PowerShell (http://go.microsoft.com/fwlink/?LinkID=320552)
#>

[CmdletBinding(PositionalBinding=$True)]

Param
      (
	    [parameter(Mandatory=$True)]
        [String] $ResourceGroupName,
		
        [parameter(Mandatory=$False)]
        [String] $DatabaseServerName = "server",
		
        [parameter(Mandatory=$False)]
        [String] $AppDatabaseName = "appdb",

        [parameter(Mandatory=$False)]
        [String] $MemberDatabaseName = "memberdb",

        [parameter(Mandatory=$False)]
        [String] $UserName = "dbuser",

        # Required
        [parameter(Mandatory=$True)]
        [String] $Password,
        
        [parameter(Mandatory=$False)]
        [String] $FirewallRuleName = "WebsiteRule",
        
        [parameter(Mandatory=$False)]
        [String] $StartIPAddress,
        
        [parameter(Mandatory=$False)]
        [String]$EndIPAddress,
        
        [parameter(Mandatory=$False)]
        [String]$Location = "West US"		
      )


# Begin - Helper functions --------------------------------------------------------------------------------------------------------------------------

# Create a PSCrendential object from plain text password.
# The PS Credential object will be used to create a database context, which will be used to create database.
Function New-PSCredentialFromPlainText
{
    Param(
        [String]$UserName,
        [String]$Password
    )

    $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force

    Return New-Object System.Management.Automation.PSCredential($UserName, $securePassword)
}

# Generate connection string of a given SQL Azure database
Function Get-SQLAzureDatabaseConnectionString
{
    Param(
        [String]$DatabaseServerName,
        [String]$DatabaseName,
        [String]$UserName,
        [String]$Password
    )

    Return "Server=tcp:$DatabaseServerName.database.windows.net,1433;Database=$DatabaseName;User ID=$UserName@$DatabaseServerName;Password=$Password;Trusted_Connection=False;Encrypt=True;Connection Timeout=30;"
}


# End - Helper functions --------------------------------------------------------------------------------------------------------------------------

# Begin - Actual script ---------------------------------------------------------------------------------------------------------------------------

$VerbosePreference = "Continue"
$ErrorActionPreference = "Stop"

Write-Verbose "[Start] creating SQL Azure database server in $Location location with username $UserName and password $Password"
$PWord = ConvertTo-SecureString -String $Password -AsPlainText -Force
$Credential = New-PSCredentialFromPlainText -UserName $UserName -Password $Password
$databaseServer = New-AzSqlServer -ServerName $DatabaseServerName -ResourceGroupName $ResourceGroupName -Location $Location -SqlAdministratorCredentials $Credential
#-AdministratorLogin $UserName -AdministratorLoginPassword $Password
if (!$databaseServer) {throw "Did not create database server. Failure in New-AzureSqlDatabaseServer in New-AzureSql.ps1"}
#$databaseServerName = $databaseServer.ServerName
Write-Verbose "[Finish] creating SQL Azure database server $databaseServerName in location $Location with username $UserName and password $Password"

# Create firewall rules.
If ($StartIPAddress -and $EndIPAddress)
{
	$_StartIPAddress = $StartIPAddress
	$_EndIPAddress = $EndIPAddress
}
else
{
	$_StartIPAddress = (Invoke-WebRequest -uri "http://ifconfig.me/ip").Content
	$_EndIPAddress = $_StartIPAddress
}

# Create a SQL Azure database server firewall rule for the IP address of the machine in which this script will run
# This will also whitelist all the Azure IP so that the website can access the database server
Write-Verbose "[Start] creating firewall rule $FirewallRuleName in database server $databaseServerName for IP addresses $_StartIPAddress - $_EndIPAddress"
$rule1 = New-AzSqlServerFirewallRule -ServerName $databaseServer.ServerName -FirewallRuleName $FirewallRuleName -StartIpAddress $_StartIPAddress -EndIpAddress $_EndIPAddress -ResourceGroupName $ResourceGroupName -Verbose
if (!$rule1) {throw "Failed to create $FirewallRuleName. Failure in New-AzureSql.ps1"}
Write-Verbose "[Finish] creating $FirewallRuleName firewall rule in database server $databaseServerName for IP addresses $_StartIPAddress - $_EndIPAddress"

Write-Verbose "[Start] creating firewall rule AllowAllAzureIP in database server $databaseServerName for IP addresses 0.0.0.0 - 0.0.0.0"
#$rule2 = New-AzureSqlDatabaseServerFirewallRule -AllowAllAzureServices -ServerName $databaseServerName -RuleName "AllowAllAzureIP" -Verbose
$rule2 = New-AzSqlServerFirewallRule -AllowAllAzureIPs -ServerName $DatabaseServerName -ResourceGroupName $ResourceGroupName -Verbose
if (!$rule2) {throw "Failed to create AllowAllAzureIP firewall rule. Failure in New-AzureSql.ps1"}
Write-Verbose "[Finish] creating AllowAllAzureIP firewall rule in database server $databaseServerName for IP addresses 0.0.0.0 - 0.0.0.0"

# Create a database context which includes the server name and credential
# These are all local operations. No API call to Windows Azure
$credential = New-PSCredentialFromPlainText -UserName $UserName -Password $Password
if (!$credential) {throw "Failed to create secure credentials. Failure in New-PSCredentialFromPlainText function in New-AzureSql.ps1"}

# Use the database context to create app database
Write-Verbose "[Start] creating database  $AppDatabaseName in database server $databaseServerName"
$appdb = New-AzSqlDatabase -DatabaseName $AppDatabaseName -ServerName $DatabaseServerName -ResourceGroupName $ResourceGroupName -Verbose
if (!$appdb) {throw "Failed to create $AppDatabaseName application database. Failure in New-AzureSqlDatabase in New-AzureSql.ps1"}
Write-Verbose "[Finish] creating database $AppDatabaseName in database server $databaseServerName"

# Use the database context to create member database
Write-Verbose "[Start] creating database $MemberDatabaseName in database server $databaseServerName"
$memberdb = New-AzSqlDatabase -DatabaseName $MemberDatabaseName -ServerName $DatabaseServerName  -ResourceGroupName $ResourceGroupName -Verbose
if (!$memberdb) {throw "Failed to create $MemberDatabaseName member database. Failure in New-AzureSqlDatabase in New-AzureSql.ps1"}
Write-Verbose "[Finish] creating database $MemberDatabaseName in database server $databaseServerName"

Write-Verbose "Creating database connection string for $appDatabaseName in database server $databaseServerName"
$appDatabaseConnectionString = Get-SQLAzureDatabaseConnectionString -DatabaseServerName $DatabaseServerName -DatabaseName $AppDatabaseName -UserName $UserName -Password $Password
if (!$appDatabaseConnectionString) {throw "Failed to create application database connection string for $AppDatabaseName. Failure in Get-SQLAzureDatabaseConnectionString function in New-AzureSql.ps1"}

Write-Verbose "Creating database connection string for $memberDatabaseName in database server $databaseServerName"
$memberDatabaseConnectionString = Get-SQLAzureDatabaseConnectionString -DatabaseServerName $DatabaseServerName -DatabaseName $MemberDatabaseName -UserName $UserName -Password $Password
if (!$memberDatabaseConnectionString) {throw "Failed to create member database connection string for $MemberDatabaseName. Failure in Get-SQLAzureDatabaseConnectionString function in New-AzureSql.ps1"}

Write-Verbose "Creating hash table to return..."
Return @{ `
    Server = $databaseServerName; UserName = $UserName; Password = $Password; `
    AppDatabase = @{Name = $AppDatabaseName; ConnectionString = $appDatabaseConnectionString}; `
    MemberDatabase = @{Name = $MemberDatabaseName; ConnectionString = $memberDatabaseConnectionString} `
}

# End - Actual script -----------------------------------------------------------------------------------------------------------------------------