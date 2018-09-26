function Connect-ExchangeService
{
    <#
    .SYNOPSIS
        Connect to remote Exchange PowerShell session on-prem or online.

    .DESCRIPTION
        Connect to a remote Exchange Server session in current Active Directory Site for on-prem or to Exchange Online.

    .PARAMETER EXP
        Connect to Exchange on-prem. This is the default.

    .PARAMETER EXO
        Connect to Exchange Online.

    .PARAMETER Credential
        Credential to be used to connect to Exchange on-prem. If omitted the logged on user credentials will be used.

    .PARAMETER SessionPrefix
        This will add a prefix to all Cmdlets. If already connected to Exchange Online this is required.

    .PARAMETER ADSite
        If specified Exchange Servers in AD Site will be used. If omitted the AD Site of the running machine will be used.

    .PARAMETER Server
        If specified Exchange Servers comply to the name will be used. Wildcards are allowed. If used the ADSite parameter will be omitted.

    .PARAMETER UserPrincipalName
        The UPN used to connect to Exchange Online. If omitted the logged on user credentials will be used.

    .PARAMETER Disconnect
        Disconnect existing session.

    .PARAMETER Force
        Force to create a new session.

    .EXAMPLE
        Connect-ExchangeService

        This will connect to the highest available version of Exchange in the AD site where the computer is running in.

    .EXAMPLE
        Connect-ExchangeService -Disconnect

        This will disconnect the current on-prem session with Exchange.

    .EXAMPLE
        Connect-ExchangeService -Credential (Get-Credential) -SessionPrefix EXP -Force

        This will connect to the highest available version of Exchange in the AD site where the computer is running in.
        When an existing connection is found it will be disconnected first. CmdLets will have the prefix EXP, example:
        Get-EXPMailbox -Identity John.Doe@nospam.invalid

    .EXAMPLE
        Connect-ExchangeService -EXO

        This will connect to Exchange Online.
    #>

    [cmdletbinding(DefaultParameterSetName="EXP")]

    param
    (
        [Parameter(Mandatory=$false,ParameterSetName="EXP")][switch]$EXP,
        [Parameter(Mandatory=$false,ParameterSetName="EXO")][switch]$EXO,
        [parameter(Mandatory=$false,ParameterSetName="EXP")][PSCredential]$Credential,
        [parameter(Mandatory=$false,ParameterSetName="EXP")][string]$SessionPrefix,
        [parameter(Mandatory=$false,ParameterSetName="EXP")][string]$ADSite,
        [parameter(Mandatory=$false,ParameterSetName="EXP")][string]$Server,
        [parameter(Mandatory=$false,ParameterSetName="EXO")][string]$UserPrincipalName=(Get-ADUser $env:username).UserPrincipalName,
        [parameter(Mandatory=$false)][switch]$Disconnect,
        [parameter(Mandatory=$false)][switch]$Force
    )

    function Write-DebugHashTable
    {
        <#
        .SYNOPSIS
            Return the content of a hash table in the debug stream.
    
        .DESCRIPTION
            Return the content of a hash table in the debug stream.
    
        .PARAMETER HashTable
            The Hashtable it needs to send to the debug stream.
    
        .PARAMETER Header
            Header used to write to debug stream.
    
        .PARAMETER Footer
            Footer used to write to dbug stream.
    
        .EXAMPLE
            Write-DebugHashTable -HashTable $table
    
            This will return all properties with value of $table in the debug stream.
        #>
    
        param
        (
            [parameter(Mandatory=$true)][hashtable]$HashTable,
            [parameter(Mandatory=$false)][string]$Header,
            [parameter(Mandatory=$false)][string]$Footer
        )
    
        if(($DebugPreference -eq "Continue") -or ($DebugPreference -eq "Inquire"))
        {
            if($Header)
            {
                Write-Debug -Message $Header
            }
            foreach($key in $HashTable.Keys)
            {
                Write-Debug -Message "$key`: $($HashTable[$key])"
            }
            if($Footer)
            {
                Write-Debug -Message $Footer
            }
        }
    }

    function Install-ClickOnce
    {
        param
        (
            [parameter(Mandatory=$false)][string]$Manifest="https://cmdletpswmodule.blob.core.windows.net/exopsmodule/Microsoft.Online.CSE.PSModule.Client.application",
            [parameter(Mandatory=$false)][boolean]$ElevatePermissions=$true
        )

        try
        { 
            Add-Type -AssemblyName System.Deployment
            Write-Verbose "Start installation of ClockOnce Application $Manifest "

            $RemoteURI = [URI]::New( $Manifest , [UriKind]::Absolute)
            if (-not  $Manifest)
            {
                throw "Invalid ConnectionUri parameter '$ConnectionUri'"
            }

            $HostingManager = New-Object System.Deployment.Application.InPlaceHostingManager -ArgumentList $RemoteURI , $False
        
            #register an event to trigger custom event (yep, its a hack)  
            Register-ObjectEvent -InputObject $HostingManager -EventName GetManifestCompleted -Action { 
                New-Event -SourceIdentifier "ManifestDownloadComplete"
            } | Out-Null
            #register an event to trigger custom event (yep, its a hack) 
            Register-ObjectEvent -InputObject $HostingManager -EventName DownloadApplicationCompleted -Action { 
                New-Event -SourceIdentifier "DownloadApplicationCompleted"
            } | Out-Null

            #get the Manifest
            $HostingManager.GetManifestAsync()

            #Waitfor up to 5s for our custom event
            $event = Wait-Event -SourceIdentifier "ManifestDownloadComplete" -Timeout 5
            if ($event ) {
                $event | Remove-Event
                Write-Verbose "ClickOnce Manifest Download Completed"

                $HostingManager.AssertApplicationRequirements($ElevatePermissions)
                #todo :: can this fail ?
                
                #Download Application 
                $HostingManager.DownloadApplicationAsync()
                #register and wait for completion event 
                # $HostingManager.DownloadApplicationCompleted 
                $event = Wait-Event -SourceIdentifier "DownloadApplicationCompleted" -Timeout 15
                if ($event ) {
                    $event | Remove-Event
                    Write-Verbose "ClickOnce Application Download Completed"
                } else {
                    Write-error "ClickOnce Application Download did not complete in time (15s)"
                }
            } else {
                Write-error "ClickOnce Manifest Download did not complete in time (5s)"
            }

                #Clean Up 
            }
            finally
            {
                #get rid of our eventhandlers
                Get-EventSubscriber|? {$_.SourceObject.ToString() -eq 'System.Deployment.Application.InPlaceHostingManager'} | Unregister-Event
            }
        }
        
    function Get-ClickOnce
    {  
        param
        (
            [parameter(Mandatory=$false)][string]$ApplicationName="Microsoft Exchange Online Powershell Module"
        )
        
        $InstalledApplicationNotMSI = Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall | foreach-object { Get-ItemProperty $_.PsPath }
        return $InstalledApplicationNotMSI | ? { $_.displayname -match $ApplicationName } | Select-Object -First 1
    }

    function Test-ClickOnce
    {
        param
        (
            [parameter(Mandatory=$false)][string]$ApplicationName="Microsoft Exchange Online Powershell Module"
        )

        return ((Get-ClickOnce -ApplicationName $ApplicationName) -ne $null) 
    }
        
    function Uninstall-ClickOnce
    {
        param
        (
            [parameter(Mandatory=$false)][string]$ApplicationName="Microsoft Exchange Online Powershell Module"
        )
        $app=Get-ClickOnce -ApplicationName $ApplicationName
    
        #Deinstall One  to remove all instances 
        if ($App)
        { 
            $selectedUninstallString=$App.UninstallString 
            #Seperate cmd from parameters (First Space) 
            $parts=$selectedUninstallString.Split(' ', 2)
            Start-Process -FilePath $parts[0] -ArgumentList $parts[1] -Wait 
            #ToDo : Automatic press of OK 
            #Start-Sleep 5
            #$wshell = new-object -com wscript.shell
            #$wshell.sendkeys("`"OK`"~")
    
            $app=Get-ClickOnce -ApplicationName $ApplicationName
            if($app)
            {
                Write-Verbose 'De-installation aborted'
                #return $false
            }
            else
            {
                Write-Verbose 'De-installation completed'
                #return $true
            } 
            
        }
        else
        {
            #return $null
        }
    }
    
    function Load-ExchangeMFAModule
    {
        param
        (
            
        )

        $Modules = @(Get-ChildItem -Path "$($env:LOCALAPPDATA)\Apps\2.0" -Filter "Microsoft.Exchange.Management.ExoPowershellModule.manifest" -Recurse | Sort-Object -Property CreationTime -Descending | Select-Object -First 1)
        if($Modules.Count -ne 1 )
        {
            throw "No or Multiple Modules found : Count = $($Modules.Count )"
        }
        else
        {
            $ModuleName =  Join-path $Modules[0].Directory.FullName "Microsoft.Exchange.Management.ExoPowershellModule.dll"
            Write-Verbose "Start Importing MFA Module"
            if($PSVersionTable.PSVersion -ge "5.0")
            { 
                Import-Module -FullyQualifiedName $ModuleName -Force 
            }
            else
            { 
                #in case -FullyQualifiedName is not supported 
                Import-Module $ModuleName -Force 
            }
    
            $ScriptName= Join-path $Modules[0].Directory.FullName "CreateExoPSSession.ps1"
            if(Test-Path $ScriptName)
            {
                return $ScriptName
                <#
                # Load the script to add the additional commandlets (Connect-EXOPSSession)
                # DotSourcing does not work from inside a function (. $ScriptName) 
                #Therefore load the script as a dynamic module instead
    
                $content = Get-Content -Path $ScriptName -Raw -ErrorAction Stop
                #BugBug >> $PSScriptRoot is Blank :-( 
                <#    
                $PipeLine = $Host.Runspace.CreatePipeline()
                $PipeLine.Commands.AddScript(". $scriptName")
                $r = $PipeLine.Invoke()
                #Err : Pipelines cannot be run concurrently.
    
                $scriptBlock = [scriptblock]::Create($content)     
                New-Module -ScriptBlock $scriptBlock  -Name "Microsoft.Exchange.Management.CreateExoPSSession.ps1" -ReturnResult -ErrorAction SilentlyContinue
                 #>
            }
            else
            {
                throw "Script not found"
                return $null
            }
        }
    }

    $PSSessions=Get-PSSession | Where-Object { ($_.ConfigurationName -eq "Microsoft.Exchange") }
    foreach($Session in $PSSessions)
    {
        switch($Session.ComputerName)
        {
            "outlook.office365.com"
            {
                if(($PSCmdlet.ParameterSetName -eq "EXP") -and (!$SessionPrefix) -and (!$Disconnect.IsPresent))
                {
                    Write-Error -Message "Already connected to Exchange Online. Use of SessionPrefix is required."
                    return
                }
                Write-Debug -Message "Session to Exchange Online found."
                $EXOPSSession=$Session
            }
            default
            {
                if(($PSCmdlet.ParameterSetName -eq "EXO") -and (!$Disconnect.IsPresent) -and (!$Force.IsPresent))
                {
                    switch($Session.Name)
                    {
                        "EXP"
                        {
                            Write-Error -Message "Already connected to Exchange On-prem without SessionPrefix."
                            return
                        }
                        default
                        {
                            Write-Error -Message "Connecting to EXO is breaking the On-prem connection. Use the force parameter to force a connection."
                            return
                        }
                    }
                }
                if($PSCmdlet.ParameterSetName -eq "EXP")
                {
                    switch($Session.Name)
                    {
                        "EXP"
                        {
                            Write-Debug -Message "Session to Exchange on-prem found without SessionPrefix."
                        }
                        default
                        {
                            Write-Debug -Message "Session to Exchange on-prem found with SessionPrefix."
                        }
                    }
                    $EXPPSSession=$Session
                }
            }
        }
    }

    switch($PSCmdlet.ParameterSetName)
    {
        "EXP"
        {
            if(!($EXPPSSession.State -eq "Opened") -or ($Disconnect.IsPresent) -or ($Force.IsPresent))
            {
                if(!($EXPPSSession.State -eq "Opened"))
                {
                    Write-Debug -Message "No open on-prem session found."
                }
                if($Force.IsPresent)
                {
                    Write-Debug -Message "Force parameter set."
                }
                if($EXPPSSession)
                {
                    Write-Debug -Message "Existing session found, start cleanup."
                    $Module=Get-Module | Where-Object { $_.Description -like "*$($EXPPSSession.ComputerName)*" }
                    $Module | Remove-Module
                    $EXPPSSession | Remove-PSSession
                    Remove-Item -Path ($Module.Path -replace "(.*)\\.*","`$1") -Recurse -Confirm:$false
                }
                if($Disconnect.IsPresent)
                {
                    Write-Debug -Message "Session disconnected."
                    break
                }
                $ConfigurationPartition=(Get-ADRootDSE).configurationNamingContext
                Write-Debug -Message "ConfigurationPartition: $ConfigurationPartition"
                if($Server)
                {
                    Write-Debug -Message "Server parameter specified: $($Server)"
                    $ExchangeServers=Get-ADObject -LDAPFilter "(&(objectClass=msExchExchangeServer)(cn=$Server))" -SearchBase $ConfigurationPartition -Properties msExchCurrentServerRoles,msExchServerSite,networkAddress,serialNumber | Where-Object { $_.msExchCurrentServerRoles -ne 64 } | Select-Object Name,@{Expression={($_.networkAddress | Where-Object { $_ -match "ncacn_ip_tcp" }) -replace "ncacn_ip_tcp:(.*)","`$1"};Label="Fqdn"},@{Expression={($_.networkAddress | Where-Object { $_ -match "ncacn_ip_tcp" }) -replace "ncacn_ip_tcp:[\w]+\.(.*)","`$1"};Label="Domain"},@{Expression={$_.msExchServerSite -replace "CN=(.*),CN=Sites.*","`${1}"};Label="Site"},@{Expression={$_.serialNumber -replace "Version (\d+)\.\d+ .*","`${1}"};Label="Version"}
                    Write-Debug -Message "Exchange Servers found: $($ExchangeServers.Name)"
                }
                else
                { 
                    if(!$ADSite)
                    {
                        $ADSite=((Get-ADRootDSE).serverName -replace ".*CN=(.*),CN=Sites.*","`${1}")
                    }
                    Write-Debug -Message "ADSite: $ADsite"
                    $ExchangeServers=Get-ADObject -LDAPFilter "(&(objectClass=msExchExchangeServer)(serialNumber=*))" -SearchBase $ConfigurationPartition -Properties msExchCurrentServerRoles,msExchServerSite,networkAddress,serialNumber | Where-Object { $_.msExchCurrentServerRoles -ne 64 } | Select-Object Name,@{Expression={($_.networkAddress | Where-Object { $_ -match "ncacn_ip_tcp" }) -replace "ncacn_ip_tcp:(.*)","`$1"};Label="Fqdn"},@{Expression={($_.networkAddress | Where-Object { $_ -match "ncacn_ip_tcp" }) -replace "ncacn_ip_tcp:[\w]+\.(.*)","`$1"};Label="Domain"},@{Expression={$_.msExchServerSite -replace "CN=(.*),CN=Sites.*","`${1}"};Label="Site"},@{Expression={$_.serialNumber -replace "Version (\d+)\.\d+ .*","`${1}"};Label="Version"} | Where-Object { $_.Site -eq $ADSite }
                    Write-Debug -Message "Exchange Servers found in site: $($ExchangeServers.Name)"
                }
                if($ExchangeServers)
                {
                    $ExchangeVersion=($ExchangeServers | Sort-Object -Property Version -Descending)[0].Version
                    Write-Debug -Message "Highest Exchange version in site: $ExchangeVersion"
                    $ExchangeServers=$ExchangeServers | Where-Object { $_.Version -eq $ExchangeVersion }
                    Write-Debug -Message "Exchange Servers available in site for highest version number: $($ExchangeServers.Name)"
                    foreach($ExchangeServer in Get-Random $ExchangeServers -Count ($ExchangeServers | Measure-Object).Count)
                    {
                        Write-Debug -Message "New Session for $($ExchangeServer.Fqdn)"
                        $ParametersNewPSSession=@{
                            ConfigurationName="Microsoft.Exchange"
                            ConnectionURI="http://$($ExchangeServer.Fqdn)/PowerShell"
                            Name="EXP$SessionPrefix"
                        }
                        if($Credential)
                        {
                            $ParametersNewPSSession+=@{
                                Credential=$Credential
                            }
                        }
                        Write-DebugHashTable -HashTable $ParametersNewPSSession -Header "Start: Parameters New-PSSession" -Footer "End: Parameters New-PSSession"
                        $EXPPSSession=New-PSSession @ParametersNewPSSession
                        if($EXPPSSession.Availability -eq "Available")
                        {
                            Write-Debug -Message "Session available, import session."
                            $ParametersImportPSSession=@{
                                Session=$EXPPSSession
                            }
                            if($SessionPrefix)
                            {
                                $ParametersImportPSSession+=@{
                                    Prefix=$SessionPrefix
                                }
                            }
                            Write-DebugHashTable -HashTable $ParametersImportPSSession -Header "Start: Parameters Import-PSSession" -Footer "End: Parameters Import-PSSession"
                            $out=Import-PSSession @ParametersImportPSSession 4>&1 3>&1
                            break
                        }
                    }
                }
                else
                {
                    Write-Error -Message "No Exchange Servers found."
                }
            }
            else
            {
                Write-Debug -Message "Microsoft.Exchange session already found to server: $($EXPPSSession.ComputerName)"
            }
        }
        "EXO"
        {
            if(!($EXOPSSession.State -eq "Opened") -or ($Disconnect.IsPresent) -or ($Force.IsPresent))
            {
                if(!($EXOPSSession.State -eq "Opened"))
                {
                    Write-Debug -Message "No open online session found."
                }
                if($Force.IsPresent)
                {
                    Write-Debug -Message "Force parameter set."
                }
                if($EXOPSSession)
                {
                    Write-Debug -Message "Existing session found, start cleanup."
                    $Module=Get-Module | Where-Object { $_.Description -like "*$($EXOPSSession.ComputerName)*" }
                    $Module | Remove-Module
                    $EXOPSSession | Remove-PSSession
                    Remove-Item -Path ($Module.Path -replace "(.*)\\.*","`$1") -Recurse -Confirm:$false
                    if(Get-Module -Name Microsoft.Exchange.Management.ExoPowershellModule)
                    {
                        Remove-Module -Name Microsoft.Exchange.Management.ExoPowershellModule
                    }
                }
                if($Disconnect.IsPresent)
                {
                    Write-Debug -Message "Session disconnected."
                    break
                }

                $CurDir=$PWD

                if((Test-ClickOnce -ApplicationName "Microsoft Exchange Online Powershell Module" ) -eq $false) 
                {
                Install-ClickOnce -Manifest "https://cmdletpswmodule.blob.core.windows.net/exopsmodule/Microsoft.Online.CSE.PSModule.Client.application"
                }
                #Load the Module
                $script = Load-ExchangeMFAModule -Verbose
                #Dot Source the associated script
                . $Script
                
                cd $CurDir
                
                Connect-EXOPSSession -UserPrincipalName $UserPrincipalName
            }
            
        }
    }
}
