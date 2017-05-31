function Get-LoggedOnUsers {
<#
.SYNOPSIS
    Returns a list of accounts currently logged into a device. The -CurrentUser flag will return the active logged on user

.DESCRIPTION
    Will return a list of all logged in accounts. This will include your username as you have to log in to the computer to run the getwmi command. Just because someone is listed as "loggedin" doesn't mean they have "switched user" ... but its an indication

    With the -Verbose flag, the computername selected will be displayed

.PARAMETER ComputerName
    The name of the computer

.PARAMETER CurrentUser
    Returns the current active user instead of all accounts

.PARAMETER Laps
    Queries and uses LAPS connection stored in AD

.PARAMETER LocalUsername LocalPassword
 Used to connect to a device using local credentials
    

.INPUTS
    String

.OUTPUTS
    String


.EXAMPLE
    Get-LoggedOnUsers -ComputerName MyPC 
    This will return all of the logged on users - including system accounts and switched users
 
.EXAMPLE
    Get-LoggedOnUsers -ComputerName MyPC -CurrentUser
    Returns the currently active user

.LINK
    http://www.peetersonline.nl/2008/11/oneliner-get-logged-on-users-with-powershell
 
.LINK
    The URL jumps to a page  explaining extracting the user from win32_loggedonuser.antecedant
    Get-WmiObject -class win32_computersystem
    Get-WmiObject Win32_LoggedOnUser 

.NOTES
 Author: Dave Bremer
 Updates:
  
#>
 
[cmdletBinding()]
Param ( [Parameter (
            Mandatory = $TRUE,
            Position = 1,
            HelpMessage = 'Computer Name',
            ValueFromPipeLine = $TRUE,
            ValueFromPipelineByPropertyName = $TRUE
            )]
        [Parameter(ParameterSetName='Laps')]        
        [Parameter(ParameterSetName='Basic')]
        [Parameter(ParameterSetName='LocalCreds')]
        [String[]] $ComputerName,
        
        [Parameter(Mandatory = $TRUE,ParameterSetName='Laps')]
        [switch] $Laps,

        [Parameter(Mandatory = $TRUE,ParameterSetName='LocalCreds')]
        [string] $LocalUsername,
        [Parameter(Mandatory = $TRUE,ParameterSetName='LocalCreds')]
        [string] $LocalPassword,
        
        [Switch] $CurrentUser
        )
    
    BEGIN{
        write-verbose ("Parameter-Set: {0}" -f $PSCmdlet.ParameterSetName)

        $pset = $PSCmdlet.ParameterSetName
    
    }

    PROCESS{
        foreach ($comp in $ComputerName ) {
            switch ($pset) {
                    "Laps" {$cred = get-LAPSCred $comp }
                    "LocalCreds" {
                            $Luser = ("{0}\{1}" -f $Comp,$LocalUsername)
                            $LocalPass = ConvertTo-SecureString "$LocalPassword" -AsPlainText -Force
                            $Cred = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList $Luser, $LocalPass
                        }
                }
            if ($cred){
                if ($CurrentUser) {
                    $CS = Get-WmiObject -class win32_computersystem -ComputerName $Comp -Credential $cred
                    Write-Verbose "Computer - $comp"                    
                    $CS.UserName

                } else {
                    Write-Verbose "Computer - $comp"                    
                    Get-WmiObject Win32_LoggedOnUser -ComputerName $Comp -Credential $cred |
                        Select __server,Antecedent -Unique | 
                        % {"{0}\{1}" -f $_.Antecedent.ToString().Split('"')[1], $_.Antecedent.ToString().Split('"')[3]}
                
                
                } #else current user
            } else {
                if ($CurrentUser) {
                    $CS = Get-WmiObject -class win32_computersystem -ComputerName $Comp
                    Write-Verbose "Computer - $comp"                    
                    $CS.UserName

                } else {
                    Write-Verbose "Computer - $comp"                    
                    Get-WmiObject Win32_LoggedOnUser -ComputerName $Comp |
                        Select __server,Antecedent -Unique | 
                        % {"{0}\{1}" -f $_.Antecedent.ToString().Split('"')[1], $_.Antecedent.ToString().Split('"')[3]}
                
                
                } #else current user
            } # else creds
        } #foreach in computername
    }

    END {}


}
