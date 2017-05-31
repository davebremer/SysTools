function Get-SoftDetails {
<#
.SYNOPSIS
Identifies if software is found by name on a PC

.DESCRIPTION
A number of fields are returned. 
   
    The software is listed in a number of multi-value fields delimited by semicolon. These fields are:
        Software: A hashtable of the software name and version of software found
        SoftwareName: A semicolon delimited list of software name
        SoftwareVersion: A semicolon delimited list of the software version - matching softwarename
    QueryStatus: Error messages found while trying to extract

.PARAMETER ComputerName
    The name of the Computer, or comma seperated list of computers

.PARAMETER Laps
    Queries and uses LAPS connection stored in AD

.PARAMETER LocalUsername LocalPassword
 Used to connect to a device using local credentials
    

.PARAMETER Software
    The name of the software being sought. This must be supplied as a single argument. 


.EXAMPLE
get-softdetails -computername a21120 -software "office"
Returns:
    SoftwareVersion     : 12.0.6425.1000;12.0.4518.1014;12.0.6425.1000;12.0.6425.1000;12.0.6425.1000
    ComputerName        : pc121212
    QueryStatus               : Success
    SoftwareName        : Microsoft Office Standard 2007;Microsoft Office Proofing (English) 2007;Microsoft Office Proof
                          (English) 2007;Microsoft Office Proof (Spanish) 2007;Microsoft Office Proof (French) 2007
    Software            : {@{ComputerName=PC121212; name=Microsoft Office Standard 2007; version=12.0.6425.1000},
                          @{ComputerName=PC121212; name=Microsoft Office Proofing (English) 2007; version=12.0.4518.1014},
                          @{ComputerName=PC121212; name=Microsoft Office Proof (English) 2007; version=12.0.6425.1000},
                          @{ComputerName=PC121212; name=Microsoft Office Proof (Spanish) 2007; version=12.0.6425.1000}...}
    

.EXAMPLE
get-softdetails -computername PC121212 -software "office" | select -expand  Software

Useful for exporting to csv 

Returns:
   ComputerName                            name                                    version
------------                            ----                                    -------
PC121212                                Microsoft Office Standard 2007          12.0.6425.1000
PC121212                                Microsoft Office Proofing (English) ... 12.0.4518.1014
PC121212                                Microsoft Office Proof (English) 2007   12.0.6425.1000
PC121212                                Microsoft Office Proof (Spanish) 2007   12.0.6425.1000
PC121212                                Microsoft Office Proof (French) 2007    12.0.6425.1000




 .NOTES
 Author: Dave Bremer
 Updates:
    2017-06-1: added laps and local creds. Removed crud that belonged in other scripts (around things like AD membership and last login)
    
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

        [Parameter (
            Mandatory = $TRUE,
            HelpMessage = 'software',
            ValueFromPipeLine = $FALSE,
            ValueFromPipelineByPropertyName = $TRUE
            )]
        [string] $software
        )
    
    BEGIN{
         write-verbose ("Parameter-Set: {0}" -f $PSCmdlet.ParameterSetName)

        $pset = $PSCmdlet.ParameterSetName

        $obj = New-Object PSObject -Property @{
            ComputerName = $null
           Software= @{"ComputerName" = $null;"Name" = $null;"Version"=$null}
           SoftwareName = $null
            QueryStatus = $null
            SoftwareVersion = $null
            
            
            }
    }
    

    PROCESS{
    
    
    foreach ($comp in $ComputerName) {
        
        $obj.ComputerName = $comp;       
        $obj.Software = @{"ComputerName" = $comp;"Name" = $null;"Version"=$null}
        $obj.SoftwareName = $null
        $obj.SoftwareVersion = $null
        $obj.QueryStatus = ""
                   


        
        if (test-connection -computername $comp -count 1 -Quiet){
            

            switch ($pset) {
                    "Laps" {$cred = get-LAPSCred $comp }
                    "LocalCreds" {
                            $Luser = ("{0}\{1}" -f $Comp,$LocalUsername)
                            $LocalPass = ConvertTo-SecureString "$LocalPassword" -AsPlainText -Force
                            $Cred = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList $Luser, $LocalPass
                        }
                }

            Try {
                Write-Verbose "Getting software called '$software'..."

                if ($cred) {
                    $obj.Software = Get-WmiObject -Class Win32_Product -computername $comp -credential $cred -ErrorAction stop| 
                    select @{n="ComputerName";e={$_.__Server}},name, version, InstallLocation,InstallSource,InstallDate | where name -match $software | 
                    where name -NotMatch "MUI"
                    $obj.querystatus = "Success"
                    
                } else {
                    $obj.Software = Get-WmiObject -Class Win32_Product -computername $comp -ErrorAction stop| 
                    select @{n="ComputerName";e={$_.__Server}},name, version, InstallLocation,InstallSource,InstallDate | where name -match $software | 
                    where name -NotMatch "MUI"
                    $obj.querystatus = "Success"
                }
            } Catch {
                Write-Warning "Failed WMI query getting software"
                $obj.QueryStatus += "Failed WMI query getting software. "
            } Finally {
                
            }
        } else {
                Write-Verbose "$comp Can't ping"
                $obj.QueryStatus += "Can't ping. " 
              
        }
        
        #ok this might not be needed any more - this whole thing needs refactored to get away from doing this and including everything in the output seamlessly
        if ($obj.Software.name) {
            $obj.SoftwareName = ([string]::join(“;”, ($obj.Software.name)))
            Write-Verbose ($obj.SoftwareName)
        }

        if ($obj.Software.version) {
            $obj.SoftwareVersion = ([string]::join(“;”, ($obj.Software.Version)))
        }

       
        $obj.psobject.typenames.insert(0, 'daveb.systools.software')
        Write-Output $obj
        }
    }
}
