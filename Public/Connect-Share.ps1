function Connect-Share {
<#
.SYNOPSIS
    Maps a share to a local drive letter using LAPS or supplied Credential

.DESCRIPTION
    Primarily written to easily map a remote share on a computer running LAPS. Basically builds a "net use" statement using the supplied parameters.
    You can also provide your own credentials

.PARAMETER ComputerName
    Name of the computer being connected to. Validation checks that its online.

.PARAMETER DriveLetter
    A single letter used as the drive letter. Validation checks for a single alphabetic character

.PARAMETER Sharename
    Name of the share on the remote computer

.PARAMETER Credential
    Uses supplied credential instead of Laps

.PARAMETER Laps
    Instructs to obtain the laps credential of the computer



.EXAMPLE
    Connect-Share -ComputerName thatpc -DriveLetter Q -ShareName C$ -laps

    This will attempt to map \\thatpc\C$ to Q: locally using LAPS credentials

.EXAMPLE
    $mycreds = get-credential
     Connect-Share -ComputerName thatpc -DriveLetter Q -ShareName C$ -Credential $mycreds

     This will use the credentials entered via the get-credential command to map the admin share of C$



.NOTES
 Author: Dave Bremer
 Updates:
#>


    [cmdletBinding()]
        Param ( 
        [Parameter (
            Mandatory = $TRUE,
            Position = 0,
            HelpMessage = 'Computer Name',
            ValueFromPipeLine = $TRUE,
            ValueFromPipelineByPropertyName = $TRUE
            )]
        [ValidateScript({  test-connection -Computername $_ -Count 1  })]
        [String] $ComputerName,
        
        [Parameter (
            Mandatory = $TRUE,
            Position = 1,
            HelpMessage = 'Drive Letter',
            ValueFromPipeLine = $TRUE,
            ValueFromPipelineByPropertyName = $TRUE
            )]
        [ValidatePattern('^[a-zA-Z]$')]
        [String] $DriveLetter,
        
        [Parameter (
            Mandatory = $TRUE,
            Position = 2,
            HelpMessage = 'Name of the share on the remote computer',
            ValueFromPipeLine = $TRUE,
            ValueFromPipelineByPropertyName = $TRUE
            )]  
        [String] $ShareName,
        
        
        [Parameter(Mandatory = $TRUE,ParameterSetName='Laps')]
        [switch] $Laps,

        [Parameter(Mandatory = $TRUE,ParameterSetName='Creds')]
        [System.Management.Automation.PSCredential] $Credential #check http://duffney.io/AddCredentialsToPowerShellFunctions

        )
    
    BEGIN{
    }

    PROCESS {
    if ($laps) {$Cred = Get-LAPSCred $ComputerName}

    $netcommand = ("net use {0}: \\{1}\{2} /user:{3}\{4} {5}" -f $driveletter,
                                                             $computername,
                                                             $sharename,
                                                             $cred.GetNetworkCredential().domain,
                                                             $cred.GetNetworkCredential().UserName,
                                                             $cred.GetNetworkCredential().Password)
    Write-Verbose $netcommand
    Invoke-Expression $netcommand
    }

    END {
    }


}