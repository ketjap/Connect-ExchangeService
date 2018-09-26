# Connect-ExchangeService
PowerShell function to connect to Exchange on-prem and Exchange Online with or without MFA.

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
