function Get-OfficeVersion {
<#
.SYNOPSIS
    Returns a list of all installed software with "Office" in the name. Returns an object with the computername, Product, and Version

.DESCRIPTION
    Returns a list of all installed software with "Office" in the name. Returns an object with the computername, Product, and Version

    This uses: Get-WmiObject -Query "select * from win32_product where name like '%office%'"

.PARAMETER ComputerName
    The name of the computer(s) to query. Accepts pipeline by value and by name

.PARAMETER Laps
    Queries and uses LAPS connection stored in AD

.PARAMETER LocalUsername LocalPassword
 Used to connect to a device using local credentials

.INPUTS
    String

.OUTPUTS
   TypeName: daveb.systools.OfficeVersion

Name         MemberType   Definition
----         ----------   ----------
Equals       Method       bool Equals(System.Object obj)
GetHashCode  Method       int GetHashCode()
GetType      Method       type GetType()
ToString     Method       string ToString()
ComputerName NoteProperty System.String
InstallDate  NoteProperty System.String
Product      NoteProperty System.String
Version      NoteProperty System.String


.EXAMPLE
    Get-OfficeVersion localhost | Format-Table -AutoSize -Wrap

    ComputerName Version        InstallDate Product
    ------------ -------        ----------- -------
    MyPC       15.0.4569.1506 20141113    Microsoft Office Professional Plus 2013
    MyPC       15.0.4569.1506 20140903    Microsoft Office OSM MUI (English) 2013
    MyPC       15.0.4569.1506 20140903    Microsoft Office OSM UX MUI (English) 2013
    MyPC       15.0.4569.1506 20140903    Microsoft Office Shared Setup Metadata MUI (English) 2013
    MyPC       15.0.4569.1506 20140903    Microsoft Office Shared 64-bit Setup Metadata MUI (English) 2013
    MyPC       15.0.4569.1506 20141113    Microsoft Office 64-bit Components 2013
    MyPC       15.0.4569.1506 20141112    Microsoft Office Shared 64-bit MUI (English) 2013
    MyPC       15.0.4569.1506 20140903    Microsoft Office Proofing (English) 2013
    MyPC       15.0.4569.1506 20141112    Microsoft Office Shared MUI (English) 2013
    MyPC       15.0.4569.1506 20141113    Microsoft Office Proofing Tools 2013 - English
    MyPC       15.0.4569.1506 20141113    Microsoft Office Proofing Tools 2013 - Español
    MyPC       15.0.4569.1506 20141113    Outils de vérification linguistique 2013 de Microsoft Office - Français
    
.LINK
    Get-WmiObject win32_product

.LINK
    https://msdn.microsoft.com/en-us/library/aa394378%28v=vs.85%29.aspx

.NOTES
 Author: Dave Bremer
 Updates:
    23/5/2017 added laps and local credentials

#>
 
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
    }

    PROCESS{

        foreach ($comp in $ComputerName ) {


            write-verbose "Computer: $comp"


            switch ($pset) {
                    "Laps" {$cred = get-LAPSCred $comp }
                    "LocalCreds" {
                            $Luser = ("{0}\{1}" -f $Comp,$LocalUsername)
                            $LocalPass = ConvertTo-SecureString "$LocalPassword" -AsPlainText -Force
                            $Cred = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList $Luser, $LocalPass
                        }
                }
            if ($cred) {
                $SoftwareList = Get-WmiObject -Query "select * from win32_product where name like '%office%'" -ComputerName $Comp -Credential $cred
            } else {
                $SoftwareList = Get-WmiObject -Query "select * from win32_product where name like '%office%'" -ComputerName $Comp
            }

            foreach ($SW in $SoftwareList) {
                $prop = @{"ComputerName" = $SW.__Server;
                          "Product" = $SW.name;
                          "Version" = $SW.version;
                          "InstallDate" = $SW.InstallDate;

                          }
        
                $obj = New-Object -TypeName PSObject -Property $prop
                $obj.psobject.typenames.insert(0, 'daveb.systools.OfficeVersion')
        
                Write-Output $obj    
            } #foreach in $SoftwareList
            
        } #foreach in computername
    }

    END {}


}