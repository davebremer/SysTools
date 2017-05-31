function Get-SystemDetails {
<#
.SYNOPSIS
    Returns the system details of a computer or set of computers

.DESCRIPTION
    Returns a custom object containing details of the system details from one or multiple computers. 
    Details include 
        * ComputerName
        * InstallDate, 
        * LocalUsername,
        * QueryStatus,
        * Architechture,
        * RAM,
        * OSVersion,
        * Description,
        * Model,
        * Processors,
        * OSBuild,
        * Caption,
        * SPVersion,
        * Manufacturer,
        * LastBoot

.PARAMETER ComputerName
    The name of the Computer, or comma seperated list of computers

.PARAMETER Laps
    Queries and uses LAPS connection stored in AD

.PARAMETER LocalUsername LocalPassword
 Used to connect to a device using local credentials
    

.EXAMPLE
 Get-SystemDetails localhost
 Returns the details of the current computer

.EXAMPLE
 Get-SystemDetails comp2.copmany.local, comp3, comp4.company2.local
 Returns the details of three computers

.EXAMPLE
 Get-SystemDetails localhost | select *
 Shows a few more fields - including Last Boot time

.EXAMPLE
 Get-SystemDetails abc-1234 -Laps
 Performs a Laps query and uses that for the credentials to get the details

.Example
 Get-SystemDetails abc-1234 -LocalUsername wibble -LocalPassword foo
 Uses local credentials to get information

.Example
 Get-AdComputer -filter {name -like "ABC*"} | select -expand name | get-SystemDetails -Laps

 Gets the system details from all online computers in AD that have a name starting with "ABC" and use LAPS for credentials.

.LINK
 Get-WmiObject –Class Win32_ComputerSystem
 Get-WmiObject –Class Win32_OperatingSystem

.LINK
    https://technet.microsoft.com/en-us/library/hh849824.aspx

.NOTES
 Author: Dave Bremer
 Updates:
    2015/04/05 added manifest to display RAM in GB. Allowing the script to keep the raw data for further processing down the pipeline while displaying human readible values
    2017/5/16 split into seperate files. 
    2017/5/18 Added ability to use a LAPS and local credentials

#>

#Requires -modules ADTools
[cmdletBinding()]
Param (
        [Parameter (
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
            OSVersion = $null
            OSBuild = $null
            Caption = $null
            SPVersion = $null
            InstallDate= $null
            Architechture = $null
            LastBoot = $null
            LocalUsername = $null
            Manufacturer = $null
            Model = $null
            #BiosSerial = $null
            RAM = $Null
            Processors = $null
            QueryStatus = $null
            Description = $null
            
            }
    }

PROCESS{
        foreach ($comp in $ComputerName ) {
            #reset values
            $obj.ComputerName = $null
            $obj.OSVersion = $null
            $obj.OSBuild = $null
            $obj.Caption = $null
            $obj.SPVersion = $null
            $obj.InstallDate= $null
            $obj.Architechture = $null
            $obj.LastBoot = $null
            $obj.LocalUsername = $null
            $obj.Manufacturer = $null
            $obj.Model = $null
            $obj.RAM = $Null
            $obj.Processors = $null
            $obj.QueryStatus = $null
            $obj.Description = $null

            

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

                try { 
                    if ($cred) {
                    
                        $OS = Get-WmiObject -Class Win32_OperatingSystem -Namespace "root\cimv2" –ComputerName $comp -credential $Cred -ErrorAction Stop 
                        $CompSys = Get-WmiObject –Class Win32_ComputerSystem -Namespace "root\cimv2" –ComputerName $comp -credential $Cred -ErrorAction Stop
                    } else {
                    
                          $OS = Get-WmiObject –Class Win32_OperatingSystem –ComputerName $comp -ErrorAction Stop 
                          $CompSys = Get-WmiObject –Class Win32_ComputerSystem –ComputerName $comp -ErrorAction Stop
                          
                        
                } 
                
                $obj.Computername = $OS.__SERVER
                $obj.OSVersion = $OS.Version
                $obj.OSBuild = $OS.version
                $obj.Caption = $OS.Caption
                $obj.SPVersion = $OS.ServicePackMajorVersion
                $obj.InstallDate= $os.ConvertToDateTime($OS.installdate)
                $obj.Architechture = $OS.OSArchitecture
                $obj.Description = $OS.description
                $obj.LastBoot = $os.ConvertToDateTime($OS.LastBootUpTime)
                $obj.LocalUsername = $CompSys.LocalUsername
                $obj.Manufacturer = $CompSys.Manufacturer
                $obj.Model = $CompSys.Model
                #$obj.BiosSerial = $Bios.SerialNumber
                $obj.RAM = $CompSys.TotalPhysicalMemory
                $obj.Processors = $CompSys.NumberofProcessors
                $obj.QueryStatus = "Success"
                        
                } catch {
                    $error = $_.Exception.Message
                    Write-Warning ("Error: {0} on {1}" -f $error,$comp)
                    $obj.QueryStatus = "Error getting WMI data.";
                    $obj.Description = $error
                    
                }
                
             } else {
                write-verbose "Cannot ping"
                
               $obj.QueryStatus = "Cannot Connect";
                            
            } # if test connect else

        $obj.psobject.typenames.insert(0, 'daveb.systools.SystemDetails')
        Write-Output $obj
        } # foreach in ComputerName
    } #process
    END{}
}