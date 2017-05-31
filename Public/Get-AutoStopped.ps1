function Get-AutoStopped {
<#
.SYNOPSIS
    Finds the services which are set to start automatically which are not running

.DESCRIPTION
    Finds the services which are set to start automatically which are not running.

    Uses CimSession but with DCOM protocol

.PARAMETER ComputerName
    The name of the computer(s)

.PARAMETER Laps
    Queries and uses LAPS connection stored in AD

.PARAMETER LocalUsername LocalPassword
 Used to connect to a device using local credentials

.INPUTS
    String: An object with a single STRING field will have that field treated as ComputerName due to ValueFromPipeLine
    -- OR --
    Object with property named "ComputerName" - due to ValueFromPipelineByPropertyName

.OUTPUTS


   TypeName: daveb.systools.process

Name         MemberType   Definition
----         ----------   ----------
Equals       Method       bool Equals(System.Object obj)
GetHashCode  Method       int GetHashCode()
GetType      Method       type GetType()
ToString     Method       string ToString()
ComputerName NoteProperty System.String 
ExitCode     NoteProperty System.UInt32 
ProcessName  NoteProperty System.String 
StartMode    NoteProperty System.String 
State        NoteProperty System.String 
Status       NoteProperty System.String 




.EXAMPLE
 Get-AutoStopped localhost
 Returns the details of the services which should start automatically but aren't running



.EXAMPLE
 Get-AutoStopped WebSrvr02 | format-table -autosize
 PS C:\> Get-AutoStopped WebSrvr02 | Format-Table -auto

ProcessName                    ExitCode StartMode ComputerName State   Status
-----------                    -------- --------- ------------ -----   ------
ccmsetup                           1068 Auto      WebSrvr02    Stopped OK
clr_optimization_v4.0.30319_32        0 Auto      WebSrvr02    Stopped OK
Dhcp                                  5 Auto      WebSrvr02    Stopped OK
SysmonLog                             0 Auto      WebSrvr02    Stopped OK
swi_update                         1077 Auto      WebSrvr02    Stopped OK

.LINK
 Get-CimInstance Win32_Service

 .NOTES
 Author: Dave Bremer
 Updates:
    2017-05-19 added local authentication and LAPS auth. Refactored the use of objects
    
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
        [string] $LocalPassword
            )

    BEGIN{
        write-verbose ("Parameter-Set: {0}" -f $PSCmdlet.ParameterSetName)

        $pset = $PSCmdlet.ParameterSetName

        $obj = New-Object PSObject -Property @{
            ComputerName = $null
            ProcessName = $null
            StartMode = $null
            State = $null
            Status = $null
            ExitCode = $null
        }
    }

    PROCESS {
        Foreach ($comp in $ComputerName ) {
            $obj.ComputerName = $null
            $obj.ProcessName = $null
            $obj.StartMode = $null
            $obj.State = $null
            $obj.Status = $null
            $obj.ExitCode = $null
            
            write-verbose "Looking up: $comp"
            if (test-connection -computername $comp -count 1 -quiet){
                switch ($pset) {
                    "Laps" {$cred = get-LAPSCred $comp }
                    "LocalCreds" {
                            $Luser = ("{0}\{1}" -f $Comp,$LocalUsername)
                            $LocalPass = ConvertTo-SecureString "$LocalPassword" -AsPlainText -Force
                            $Cred = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList $Luser, $LocalPass
                        }
                    }
                

                
                if ($cred) {
                    $CS = New-CimSession -ComputerName $comp -SessionOption (New-CimSessionOption -Protocol dcom) -Credential $cred
                        
                } else {
                    $CS = New-CimSession -ComputerName $comp -SessionOption (New-CimSessionOption -Protocol dcom)
                        
                }
            
                $CI = Get-CimInstance -Query "SELECT * FROM Win32_Service WHERE StartMode = 'auto' AND state <> 'Running'" -CimSession $CS 
                foreach ($proc in $CI) {
            
                    $obj.ComputerName = $proc.SystemName
                    $obj.ProcessName = $proc.Name
                    $obj.StartMode = $proc.StartMode
                    $obj.State = $proc.State
                    $obj.Status = $proc.Status
                    $obj.ExitCode = $proc.ExitCode  
                
                    $obj.psobject.typenames.insert(0, 'daveb.systools.process')
                    Write-Output $obj
                } # foreach $Proc
                remove-cimsession $CS
            } # if test-connect
        } #foreach comp
    } #process

    END{}
}