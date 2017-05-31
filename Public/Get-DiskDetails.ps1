Function Get-DiskDetails {
<#
.SYNOPSIS
    Returns the local drive details of a computer or set of computers

.DESCRIPTION
    Returns a custom object containing details of the local drive from one or multiple computers. Details include ComputerName, Drive ID, Free Space, Disk Size and the percentage of free space

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
    TypeName: daveb.systools.diskdetails

Name         MemberType   Definition                       
----         ----------   ----------                       
Equals       Method       bool Equals(System.Object obj)   
GetHashCode  Method       int GetHashCode()                
GetType      Method       type GetType()                   
ToString     Method       string ToString()                
ComputerName NoteProperty System.String
Drive        NoteProperty System.String
FreePercent  NoteProperty System.String
FreeSpace    NoteProperty System.String
Size         NoteProperty System.String

.EXAMPLE
 Get-DiskDetails localhost
 Returns the disk details of the current computer

.EXAMPLE
 Get-DiskDetails comp2.company.local, comp3, comp4.company2.local
 Returns the details of three computers

.LINK
 Get-WmiObject –Class Win32_LogicalDisk


.LINK
    https://msdn.microsoft.com/en-us/library/aa394173%28v=vs.85%29.aspx

.NOTES
 Author: Dave Bremer
 Updates:
    5/4/2015 added manifest to display disk size and freespace in GB. Allowing the script to keep the raw data for further processing down the pipeline while displaying human readible values
    23/5/2017 added laps and local credentials
 
#>
[cmdletBinding()]
Param ([Parameter (
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
        $DriveType = 3

        write-verbose ("Parameter-Set: {0}" -f $PSCmdlet.ParameterSetName)

        $pset = $PSCmdlet.ParameterSetName
        }

    PROCESS{
        foreach ($comp in $ComputerName ) {
             write-verbose "Looking up: $comp"
            if (test-connection -computername $comp -count 1 -quiet){

                Switch ($pset) {
                    "Laps" {$cred = get-LAPSCred $comp }
                    "LocalCreds" {
                            $Luser = ("{0}\{1}" -f $Comp,$LocalUsername)
                            $LocalPass = ConvertTo-SecureString "$LocalPassword" -AsPlainText -Force
                            $Cred = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList $Luser, $LocalPass
                        }
                }

                if ($cred) {
                    $LocalDrive = Get-WmiObject –Class Win32_LogicalDisk –ComputerName $comp -Filter "drivetype=$DriveType" -Credential $cred
                } else {
                    $LocalDrive = Get-WmiObject –Class Win32_LogicalDisk –ComputerName $comp -Filter "drivetype=$DriveType"
                }
                
                write-verbose ("found {0} drives" -f (($localdrive).count))
                foreach ($drive in $LocalDrive ){
                    
                    #There are drives with 0 bytes? Whats with that??
                    #conditional to avoid div by zero error
                    if ($Drive.Size -gt 0) {
                        $Freepc = [decimal]("{0:N2}" -f ($Drive.FreeSpace/$Drive.Size * 100))
                       } else {$Freepc = 0}
                
                    $prop = @{  "ComputerName" = $drive.__Server;
                                "Drive" = $Drive.DeviceID;                        
                                "Size" = $Drive.Size;
                                "FreeSpace" = $Drive.FreeSpace;
                                "FreePercent" = $Freepc
                              } #prop
                $obj = New-Object -TypeName PSObject -Property $prop
                $obj.psobject.typenames.insert(0, 'daveb.systools.diskdetails')
                Write-Output $obj
                } #foreach drive
            } else {
                write-verbose "Cannot ping"
                $prop = @{"ComputerName" = $comp;
                            "Drive" = "-";
                            "Size" = $null;
                            "FreeSpace" = $null;
                            "FreePercent" = $null
                
                } #prop
                $obj = New-Object -TypeName PSObject -Property $prop
                $obj.psobject.typenames.insert(0, 'daveb.systools.diskdetails')
                Write-Output $obj
            } #if test-connection
            
            
        } #foreach Computer
    } #Process

    END{}
}
