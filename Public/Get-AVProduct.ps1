function Get-AVProduct { 
<# 
.SYNOPSIS 
    Get the status of Antivirus Product(s) on local and Remote Computers. 
 
.DESCRIPTION 
    Works with MS Security Center and detects the status for most AV products. If there are multiple AV installed for in a computer, 
    a seperate output object is created for each product

    Note: There are different calls for XP,Win2000 etc vs Vista, Win7, Server 2008 etc. They report slightly differently. Where possible the output has
    been converted to the modern field names. It is possible that future OS may break this.

    If there are multiple AV software installed then an object for each is returned - Win 8.1 will always have Defender, which may be disabled if another AV is installed
 
.PARAMETER ComputerName 
    The computer name(s) to retrieve the info from. 
    
.PARAMTER Laps
    This queries AD to get a LAPS password 

.PARAMETER LocalUsername LocalPassword
 Uses a local username and password
 
.EXAMPLE 
    Get-AVProduct 
    Returns the AV details of the current computer

.EXAMPLE
    gc 'c:\temp\computers.txt' | 
        Get-AVProduct | 
        select ComputerName,OS,CountProdsInstalled,AVProductName,ProductExecutable,versionNumber,DefinitionStatus,RealTimeProtectionStatus,QueryStatus,DateTime |
        Export-Csv 'f:\reports\AVreport.csv' -NoTypeInformation
    
    Tests all of the computers in the text file and outputs a csv file

.EXAMPLE
 Get-AVProduct abc-1234 -laps
 Queries LAPS password from AD to get AV details on device avc-1234

.EXAMPLE
 Get-AVProduct abc-1234 -localusername wibble -localpassword foo
 uses the supplied user/pass as local credentials

.INPUTS 
    System.String, you can pipe ComputerNames to this Function 
 
.OUTPUTS 
    psobject: daveb.av

    ComputerName:             The name of the computer being queried
    OS:                       The name of the OS
    CountProdsInstalled:      Number of AV products installed
    QueryStatus               Success / No Ping / WMI Error
    AVProductName:            The display name of the AV product. Could be an array of objects unless converted to string with -stringout
    DefinitionStatus:         Up to date/Out of date
    ProductExecutable:        Path to the executable - could be an array of objects unless converted to string with -stringout
    RealTimeProtectionStatus: Is real time protection active?
    versionNumber:            Version number if legacy OS
    DateTime:                 The Date/Time the query ran
 
.NOTES 
    WMI query to get anti-virus infor­ma­tion has been changed. 
    Pre-Vista clients used the root/SecurityCenter name­space,  
    while Post-Vista clients use the root/SecurityCenter2 name­space. 
    But not only the name­space has been changed, The properties too.  
 
 
    code drawn from:
        http://neophob.com/2010/03/wmi-query-windows-securitycenter2/ 
        http://blogs.msdn.com/b/alejacma/archive/2008/05/12/how-to-get-antivirus-information-with-wmi-vbscript.aspx 
        https://soykablog.wordpress.com/2012/08/26/get-info-about-antivirus-from-windows-security-centre-using-powershell-and-wmi/ 
        https://gallery.technet.microsoft.com/scriptcenter/Get-the-status-of-4b748f25
 
    AUTHOR: Dave Bremer (mostly copying from the above)  
    LASTEDIT:  2016-05-25
    KEYWORDS:  
 
.LINK 
 
 
 
#>

#Requires -Version 2.0 
#Requires -modules ADTools
 
[CmdletBinding()] 
[OutputType('PSobject')] 

#i had problems with these parameters. This isn't quite right but works
param (
       
        [Parameter(Mandatory = $TRUE,
            Position = 1,
            HelpMessage = 'Computer Name',
            ValueFromPipeLine = $TRUE,
            ValueFromPipelineByPropertyName = $TRUE,
            ParameterSetName='Basic')]
        [Parameter(Mandatory = $TRUE,
            Position = 1,
            HelpMessage = 'Computer Name',
            ValueFromPipeLine = $TRUE,
            ValueFromPipelineByPropertyName = $TRUE,
            ParameterSetName='Laps')]        
        [Parameter(Mandatory = $TRUE,
            Position = 1,
            HelpMessage = 'Computer Name',
            ValueFromPipeLine = $TRUE,
            ValueFromPipelineByPropertyName = $TRUE,
            ParameterSetName='LocalCreds')]
        [ValidateNotNullorEmpty()]
        [String[]] $ComputerName,
        
        [Parameter(Mandatory = $TRUE,ParameterSetName='Laps')]
        [switch] $Laps,

        [Parameter(Mandatory = $TRUE,ParameterSetName='LocalCreds')]
        [string] $LocalUsername,
        [Parameter(Mandatory = $TRUE,ParameterSetName='LocalCreds')]
        [string] $LocalPassword
        )
 
BEGIN { 
 
    Set-StrictMode -Version Latest 
 
    ${CmdletName} = $Pscmdlet.MyInvocation.MyCommand.Name 
    
    Write-Debug -Message "${CmdletName}: Starting Begin Block"

    $Pset = $PsCmdlet.ParameterSetName
    Write-Verbose ("Parameter Set: {0}" -f $Pset)
     
    $tot = ($computername | measure).count   
    Write-Verbose ("Total is {0}" -f $tot)

    $obj = New-Object PSObject -Property @{ 
                    ComputerName = $null 
                    OS = $null
                    CountProdsInstalled = $null
                    QueryStatus = $null
                    AVProductName = $null 
                    versionNumber = $null 
                    ProductExecutable = $null  
                    DefinitionStatus = $null
                    RealTimeProtectionStatus = $null
                    DateTime = $null
                 }
 
} # end BEGIN
 
PROCESS { 
    
    Write-Debug ("PROCESS:`n{0}" -f ($PSBoundParameters | Out-String)) 

    $counter=0 #for progress bar 
   
    ForEach ($Computer in $ComputerName) { 

        $obj.ComputerName = $null 
        $obj.OS = $null
        $obj.CountProdsInstalled = $null
        $obj.QueryStatus = $null
        $obj.AVProductName = $null 
        $obj.versionNumber = $null 
        $obj.ProductExecutable = $null  
        $obj.DefinitionStatus = $null
        $obj.RealTimeProtectionStatus = $null
        $obj.DateTime = $null
        
        $counter++

       if ($tot -gt 2) { #don't  bother with progress bar if there's only a couple of devices
            $prog=[system.math]::round($counter/$tot*100,2)
            write-progress -activity ("Checking {0}. {1} computers left to check" -f $computer,($tot-$counter)) -status "$prog% Complete:" -percentcomplete $prog;
       } 
        
       Write-verbose ("Computer: {0}" -f $Computer)
        
                
       If (Test-Connection -ComputerName $Computer -count 2 -quiet) {
       
            switch ($pset) {
                    "Laps" {$cred = get-LAPSCred $computer }
                    "LocalCreds" {
                            $Luser = ("{0}\{1}" -f $Computer,$LocalUsername)
                            $LocalPass = ConvertTo-SecureString "$LocalPassword" -AsPlainText -Force
                            $Cred = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList $Luser, $LocalPass
                        }
                }
                  
            Try {
                if ($cred) {
                    $OSDetails = Get-WmiObject –Class Win32_OperatingSystem –ComputerName $Computer -credential $Cred -ErrorAction Stop
                   } else {
                    $OSDetails = Get-WmiObject –Class Win32_OperatingSystem –ComputerName $Computer -ErrorAction Stop
                   }
                    
                $OSVersion = $OSDetails.version
                $OS = $OSVersion.split(".") 
                Write-Debug "`$OS[0]: $($OS[0])" 
                $OSName = $OSDetails.Caption
            } catch {
                Write-verbose "WMI Error getting OS"
                Write-verbose $_ 
                $obj.OS = "WMI Error getting OS Details"
                $obj.ComputerName = $Computer 
                $obj.QueryStatus = ("WMI Error querying OS" ) 
                
                $obj.DateTime = Get-Date
                $obj.psobject.typenames.insert(0, 'daveb.av')
                Write-Output $obj
                Continue
            } #try get-wmi for OS

            IF ($OS[0] -eq "5") { 
                Write-Verbose "Windows 2000, 2003, XP"  
                Try {
                    if($cred){ 
                    $AntiVirusProducts = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct  -ComputerName $Computer -credential $Cred -ErrorAction Stop 
                    } else {
                        $AntiVirusProducts = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct  -ComputerName $Computer -ErrorAction Stop 
                    }
                    $ProdCount = ($AntiVirusProducts | measure-object).count
                    if ($ProdCount -eq 0 ) {
                        Write-Warning "\\$computer MISSING AV!!!!!!!!!!!!!!!!!!!!!!!!!!!" 
                        $obj.ComputerName = $Computer
                        $obj.OS = $OSName
                        #CountProdsInstalled = $AntiVirusProduct.count;
                        $obj.CountProdsInstalled = $ProdCount
                        $obj.QueryStatus = "Success"
                        $obj.AVProductName = "MISSING"                  
                        $obj.DateTime = Get-Date
                        $obj.psobject.typenames.insert(0, 'daveb.av')
                        Write-Output $obj
                    } else {
                        foreach ($AVProd in $AntiVirusProducts) {
                             
                            $obj.ComputerName = $Computer 
                            $obj.OS = $OSName
                            #CountProdsInstalled = $AntiVirusProduct.count;
                            $obj.CountProdsInstalled = $ProdCount
                            $obj.QueryStatus = "Success"
                            $obj.AVProductName = $AVProd.displayName
                            $obj.versionNumber = $AVProd.versionNumber
                                          
                            $obj.DefinitionStatus = $AVProd.productUptoDate
                            $obj.RealTimeProtectionStatus = $AVProd.onAccessScanningEnabled
                            $obj.DateTime = Get-Date
                                            
                            
                            $obj = New-Object -TypeName PSObject -Property $prop
                            $obj.psobject.typenames.insert(0, 'daveb.av')
                            Write-Output $obj
                        
                        } #foreach AV
                        
                       
                     }  #if AV prod
                    } Catch { 
                        $Errordetails = $_
                        Write-Error "$Computer : WMI Error" 
                        Write-Error $_
                        
                        $obj.ComputerName = $Computer 
                        $obj.OS = $OSName
                        $obj.CountProdsInstalled = $null
                        $obj.QueryStatus = ("WMI ERROR: {0}" -f $Errordetails) 
                        $obj.DateTime = Get-Date

                        $obj.psobject.typenames.insert(0, 'daveb.av')
                        Write-Output $obj
                        Continue 
                }     

            } ElseIF ($OS[0] -eq "6" -or $OS[0] -eq "10") { 
                Write-Verbose "Windows Vista, 7, 2008, 2008R2" 
                Try { 

                    if ($cred){
                        $AntiVirusProducts = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct  -ComputerName $Computer -credential $cred -ErrorAction Stop 
                    } else {
                        $AntiVirusProducts = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct  -ComputerName $Computer -ErrorAction Stop 
                    }

                    $ProdCount = ($AntiVirusProducts | measure-object).count
                    if ($ProdCount -eq 0 ) {
                        Write-Warning "\\$computer MISSING!!!!!!!!!!!!!!!!!!!!!!!!!!!" 
                         
                                        $obj.ComputerName = $Computer 
                                        $obj.OS = $OSName
                                        #CountProdsInstalled = $AntiVirusProduct.count
                                        $obj.CountProdsInstalled = $ProdCount
                                        $obj.QueryStatus = "Success"
                                        $obj.AVProductName = "MISSING"
                                        $obj.DateTime = Get-Date
                                    
                           $obj.psobject.typenames.insert(0, 'daveb.av')
                           Write-Output $obj  
                    } else {
                        ForEach ($AVProd in $AntiVirusProducts) {
                        
                            $ProductState=$AVProd.ProductState
                    
                            #$ProductState
                            $HexProductState="{0:x6}" -f $ProductState
                            #Write-Verbose "HexProductState=$HexProductState"
 
                            #$FirstByte = Join-String -Strings "0x", $HexProductState.Substring(0,2)
                            $FirstByte = -join (“0x”, $HexProductState.Substring(0,2))
 
                            #Write-Verbose "FirstByte=$FirstByte"
                            $SecondByte = $HexProductState.Substring(2,2)
                            #Write-Verbose "SecondByte=$SecondByte"
                            $ThirdByte = $HexProductState.Substring(4,2)
                            #Write-Verbose "ThirdByte=$ThirdByte"      

                            <#
                            ## Decided not to use this
                             switch ($FirstByte) {
                                {($_ -band 1) -gt 0} {$Prop.ThirdPartyFirewallPresent=$true}
                                {($_ -band 2) -gt 0} {$Prop.AutoUpdate=$true}
                                {($_ -band 4) -gt 0} {$Prop.AntivirusPresent=$true}
                            }
                            #>

                            #this is as dodgy as hell. No documentation exists on this!!!!
                    
                            if (($SecondByte -eq "10") -or ($SecondByte -eq "11")) {
                                $rtstatus = "Enabled"
                            } else {
                                $rtstatus = "Disabled"
                            }
 
                            if ($ThirdByte -eq "00") {
                                $defstatus = "Up to Date"
                            } else {
                                $defstatus = "Out of Date"
                    
                           }
                            
                        $obj.ComputerName = $Computer; 
                        $obj.OS = $OSDetails.Caption;
                        # CountProdsInstalled = $AntiVirusProducts.count;
                        $obj.CountProdsInstalled = $ProdCount
                        $obj.QueryStatus = "Success"
                        $obj.AVProductName = $AVProd.displayName
                        $obj.versionNumber = $null
                        $obj.ProductExecutable = $AVProd.pathToSignedProductExe  
                        $obj.DefinitionStatus = $defstatus
                        $obj.RealTimeProtectionStatus = $rtstatus
                        $obj.DateTime = Get-Date
                                
                        $obj.psobject.typenames.insert(0, 'daveb.av')
                        Write-Output $obj  
                        }
                                
                     }           
                     
                              
                 } Catch { 
                    $Errordetails = $_
                    Write-Error "$Computer : WMI Error" 
                    Write-Error $Errordetails 
 
                    $obj.ComputerName = $Computer
                    $obj.OS = $OSName
                    $obj.QueryStatus = ("WMI ERROR: {0}" -f $Errordetails) 
                    $obj.DateTime = Get-Date
                        
                    $obj.psobject.typenames.insert(0, 'daveb.av')
                    Write-Output $obj         
                }  
 
            } Else { 
                Write-Error "\\$Computer : Unknown OS Version"
 
                $obj.ComputerName = $Computer; 
                $obj.QueryStatus = ("Unknown OS or Error querying OS - Query Skipped" ); 
                DateTime = Get-Date
                         
                $obj.psobject.typenames.insert(0, 'daveb.av')
                Write-Output $obj
            } # end If $OS 
             
             
        } Else { 
            Write-verbose "\\$computer No ping" 
            
                $obj.ComputerName = $Computer; 
                $obj.QueryStatus = ("No Ping"); 
                $obj.DateTime = Get-Date
                 
                $obj.psobject.typenames.insert(0, 'daveb.av')
                Write-Output $obj
                 
        } # end IF (Test-Connection -ComputerName $Computer -count 2 -quiet)      
        
    } # end ForEach ($Computer in $computerName) 
 
} # end PROCESS 
 
END { Write-Verbose "Function Get-AVProduct finished." }  
} # end function Get-AVProduct
