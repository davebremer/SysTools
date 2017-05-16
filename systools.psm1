Function Get-LastLogonToSys 
{ 
<# 
 
.SYNOPSIS 
  This function will list the last user logged on or logged in. 
 
.DESCRIPTION 
  This function will list the last user logged on or logged in.  It will detect if the user is currently logged on 
  via WMI or the Registry, depending on what version of Windows is running on the target.  There is some "guess" work 
  to determine what Domain the user truly belongs to if run against Vista NON SP1 and below, since the function 
  is using the profile name initially to detect the user name.  It then compares the profile name and the Security 
  Entries (ACE-SDDL) to see if they are equal to determine Domain and if the profile is loaded via the Registry. 
 
.PARAMETER ComputerName 
  A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME). 
 
.PARAMETER FilterSID 
  Filters a single SID from the results.  For use if there is a service account commonly used. 
   
.PARAMETER WQLFilter 
  Default WQLFilter defined for the Win32_UserProfile query, it is best to leave this alone, unless you know what 
  you are doing. 
  Default Value = "NOT SID = 'S-1-5-18' AND NOT SID = 'S-1-5-19' AND NOT SID = 'S-1-5-20'" 
   
.EXAMPLE 
  $Servers = Get-Content "C:\ServerList.txt" 
  Get-LastLogonToSys -ComputerName $Servers 
 
  This example will return the last logon information from all the servers in the C:\ServerList.txt file. 
 
  Computer          : SVR01 
  User              : WILHITE\BRIAN 
  SID               : S-1-5-21-012345678-0123456789-012345678-012345 
  Time              : 9/20/2012 1:07:58 PM 
  CurrentlyLoggedOn : False 
 
  Computer          : SVR02 
  User              : WILIHTE\BRIAN 
  SID               : S-1-5-21-012345678-0123456789-012345678-012345 
  Time              : 9/20/2012 12:46:48 PM 
  CurrentlyLoggedOn : True 
   
.EXAMPLE 
  Get-LastLogonToSys -ComputerName svr01, svr02 -FilterSID S-1-5-21-012345678-0123456789-012345678-012345 
 
  This example will return the last logon information from all the servers in the C:\ServerList.txt file. 
 
  Computer          : SVR01 
  User              : WILHITE\ADMIN 
  SID               : S-1-5-21-012345678-0123456789-012345678-543210 
  Time              : 9/20/2012 1:07:58 PM 
  CurrentlyLoggedOn : False 
 
  Computer          : SVR02 
  User              : WILIHTE\ADMIN 
  SID               : S-1-5-21-012345678-0123456789-012345678-543210 
  Time              : 9/20/2012 12:46:48 PM 
  CurrentlyLoggedOn : True 
 
.LINK 
  http://msdn.microsoft.com/en-us/library/windows/desktop/ee886409(v=vs.85).aspx 
  http://msdn.microsoft.com/en-us/library/system.security.principal.securityidentifier.aspx 
  https://gallery.technet.microsoft.com/scriptcenter/Get-LastLogonToSys-Determining-283f98ae
 
.NOTES 
  Author:   Brian C. Wilhite 
  Email:   bwilhite1@carolina.rr.com 
  Date:    "09/20/2012" 
  Updates: Added FilterSID Parameter 
           Cleaned Up Code, defined fewer variables when creating PSObjects 
  ToDo:    Clean up the UserSID Translation, to continue even if the SID is local 
  SourceURL: https://gallery.technet.microsoft.com/scriptcenter/Get-LastLogonToSys-Determining-283f98ae
#> 
 
[CmdletBinding()] 
param( 
  [Parameter(Position=0,ValueFromPipeline=$true)] 
  [Alias("CN","Computer")] 
  [String[]]$ComputerName="$env:COMPUTERNAME", 
  [String]$FilterSID, 
  [String]$WQLFilter="NOT SID = 'S-1-5-18' AND NOT SID = 'S-1-5-19' AND NOT SID = 'S-1-5-20'" 
  ) 
 
Begin 
  { 
    #Adjusting ErrorActionPreference to stop on all errors 
    $TempErrAct = $ErrorActionPreference 
    $ErrorActionPreference = "Stop" 
    #Exclude Local System, Local Service & Network Service 
  }#End Begin Script Block 
 
Process 
  { 
    Foreach ($Computer in $ComputerName) 
      { 
        $Computer = $Computer.ToUpper().Trim() 
        Try 
          { 
            #Querying Windows version to determine how to proceed. 
            $Win32OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer 
            $Build = $Win32OS.BuildNumber 
             
            #Win32_UserProfile exist on Windows Vista and above 
            If ($Build -ge 6001) 
              { 
                If ($FilterSID) 
                  { 
                    $WQLFilter = $WQLFilter + " AND NOT SID = `'$FilterSID`'" 
                  }#End If ($FilterSID) 
                $Win32User = Get-WmiObject -Class Win32_UserProfile -Filter $WQLFilter -ComputerName $Computer 
                $LastUser = $Win32User | Sort-Object -Property LastUseTime -Descending | Select-Object -First 1 
                $Loaded = $LastUser.Loaded 
                $Script:Time = ([WMI]'').ConvertToDateTime($LastUser.LastUseTime) 
                 
                #Convert SID to Account for friendly display 
                $Script:UserSID = New-Object System.Security.Principal.SecurityIdentifier($LastUser.SID) 
                $User = $Script:UserSID.Translate([System.Security.Principal.NTAccount]) 
              }#End If ($Build -ge 6001) 
               
            If ($Build -le 6000) 
              { 
                If ($Build -eq 2195) 
                  { 
                    $SysDrv = $Win32OS.SystemDirectory.ToCharArray()[0] + ":" 
                  }#End If ($Build -eq 2195) 
                Else 
                  { 
                    $SysDrv = $Win32OS.SystemDrive 
                  }#End Else 
                $SysDrv = $SysDrv.Replace(":","$") 
                $Script:ProfLoc = "\\$Computer\$SysDrv\Documents and Settings" 
                $Profiles = Get-ChildItem -Path $Script:ProfLoc 
                $Script:NTUserDatLog = $Profiles | ForEach-Object -Process {$_.GetFiles("ntuser.dat.LOG")} 
                 
                #Function to grab last profile data, used for allowing -FilterSID to function properly. 
                function GetLastProfData ($InstanceNumber) 
                  { 
                    $Script:LastProf = ($Script:NTUserDatLog | Sort-Object -Property LastWriteTime -Descending)[$InstanceNumber]               
                    $Script:UserName = $Script:LastProf.DirectoryName.Replace("$Script:ProfLoc","").Trim("\").ToUpper() 
                    $Script:Time = $Script:LastProf.LastAccessTime 
                     
                    #Getting the SID of the user from the file ACE to compare 
                    $Script:Sddl = $Script:LastProf.GetAccessControl().Sddl 
                    $Script:Sddl = $Script:Sddl.split("(") | Select-String -Pattern "[0-9]\)$" | Select-Object -First 1 
                    #Formatting SID, assuming the 6th entry will be the users SID. 
                    $Script:Sddl = $Script:Sddl.ToString().Split(";")[5].Trim(")") 
                     
                    #Convert Account to SID to detect if profile is loaded via the remote registry 
                    $Script:TranSID = New-Object System.Security.Principal.NTAccount($Script:UserName) 
                    $Script:UserSID = $Script:TranSID.Translate([System.Security.Principal.SecurityIdentifier]) 
                  }#End function GetLastProfData 
                GetLastProfData -InstanceNumber 0 
                 
                #If the FilterSID equals the UserSID, rerun GetLastProfData and select the next instance 
                If ($Script:UserSID -eq $FilterSID) 
                  { 
                    GetLastProfData -InstanceNumber 1 
                  }#End If ($Script:UserSID -eq $FilterSID) 
                 
                #If the detected SID via Sddl matches the UserSID, then connect to the registry to detect currently loggedon. 
                If ($Script:Sddl -eq $Script:UserSID) 
                  { 
                    $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]"Users",$Computer) 
                    $Loaded = $Reg.GetSubKeyNames() -contains $Script:UserSID.Value 
                    #Convert SID to Account for friendly display 
                    $Script:UserSID = New-Object System.Security.Principal.SecurityIdentifier($Script:UserSID) 
                    $User = $Script:UserSID.Translate([System.Security.Principal.NTAccount]) 
                  }#End If ($Script:Sddl -eq $Script:UserSID) 
                Else 
                  { 
                    $User = $Script:UserName 
                    $Loaded = "Unknown" 
                  }#End Else 
 
              }#End If ($Build -le 6000) 
             
            #Creating Custom PSObject For Output 
            New-Object -TypeName PSObject -Property @{ 
              Computer=$Computer 
              User=$User 
              SID=$Script:UserSID 
              Time=$Script:Time 
              CurrentlyLoggedOn=$Loaded 
              } | Select-Object Computer, User, SID, Time, CurrentlyLoggedOn 
               
          }#End Try 
           
        Catch 
          { 
            If ($_.Exception.Message -Like "*Some or all identity references could not be translated*") 
              { 
                Write-Warning "Unable to Translate $Script:UserSID, try filtering the SID `nby using the -FilterSID parameter."   
                Write-Warning "It may be that $Script:UserSID is local to $Computer, Unable to translate remote SID" 
              } 
            Else 
              { 
                Write-Warning $_ 
              } 
          }#End Catch 
           
      }#End Foreach ($Computer in $ComputerName) 
       
  }#End Process 
   
End 
  { 
    #Resetting ErrorActionPref 
    $ErrorActionPreference = $TempErrAct 
  }#End End 
 
}# End Function Get-LastLogonToSys


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

.PARAMETER Verbose
    Displays the computername being queried

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
Param ([Parameter (
            Mandatory = $TRUE,
            HelpMessage = 'Computer Name',
            ValueFromPipeLine = $TRUE,
            ValueFromPipelineByPropertyName = $TRUE
            )]
        [string[]] $ComputerName,
        
        [Switch] $CurrentUser
        )
    
    BEGIN{}

    PROCESS{
        foreach ($comp in $ComputerName ) {
            if ($CurrentUser) {
                $CS = Get-WmiObject -class win32_computersystem -ComputerName $Comp
                Write-Verbose "Computer - $comp"                    
                $CS.UserName

            } else {
                Write-Verbose "Computer - $comp"                    
                Get-WmiObject Win32_LoggedOnUser -ComputerName $Comp |
                    Select __server,Antecedent -Unique | 
                    % {"{0}\{1}" -f $_.Antecedent.ToString().Split('"')[1], $_.Antecedent.ToString().Split('"')[3]}
                
                
            } #else
        } #foreach in computername
    }

    END {}


}

function Get-OfficeVersion {
<#
.SYNOPSIS
    Returns a list of all installed software with "Office" in the name. Returns an object with the computername, Product, and Version

.DESCRIPTION
    Returns a list of all installed software with "Office" in the name. Returns an object with the computername, Product, and Version

    This uses: Get-WmiObject -Query "select * from win32_product where name like '%office%'"

.PARAMETER ComputerName
    The name of the computer(s) to query. Accepts pipeline by value and by name

.PARAMETER Verbose
    Displays the computername being queried

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

#>
 
[cmdletBinding()]
Param ([Parameter (
            Mandatory = $TRUE,
            HelpMessage = 'Computer Name',
            ValueFromPipeLine = $TRUE,
            ValueFromPipelineByPropertyName = $TRUE
            )]
        [string[]] $ComputerName
        )
    
    BEGIN{}

    PROCESS{
        foreach ($comp in $ComputerName ) {
            write-verbose "Computer: $comp"
            
            $SoftwareList = Get-WmiObject -Query "select * from win32_product where name like '%office%'" -ComputerName $Comp
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

function Get-SystemDetails {
<#
.SYNOPSIS
    Returns the system details of a computer or set of computers

.DESCRIPTION
    Returns a custom object containing details of the system details from one or multiple computers. Details include OSVersion, Service Pack Version, OS buildNumber, Manufacturer, Model, ComputerName, BIOS SerialNumber

.PARAMETER ComputerName
    The name of the copmuter, or comma seperated list of computers

.INPUTS
    String: An object with a single STRING field will have that field treated as ComputerName - due to ValueFromPipeLine
    -- OR --
    Object with property named "ComputerName" - due to ValueFromPipelineByPropertyName


.EXAMPLE
 Get-SystemDetails localhost
 Returns the details of the current computer

.EXAMPLE
 Get-SystemDetails comp2.copmany.local, comp3, comp4.company2.local
 Returns the details of three computers

.EXAMPLE
 Get-SystemDetails localhost | select *
 Shows a few more fields - including Last Boot time

.LINK
 Get-WmiObject –Class Win32_Bios
 Get-WmiObject –Class Win32_ComputerSystem
 Get-WmiObject –Class Win32_OperatingSystem

.LINK
    https://technet.microsoft.com/en-us/library/hh849824.aspx

.NOTES
 Author: Dave Bremer
 Updates:
    5/4/2015 added manifest to display RAM in GB. Allowing the script to keep the raw data for further processing down the pipeline while displaying human readible values
 
#>
[cmdletBinding()]
Param ([Parameter (
            Mandatory = $TRUE,
            HelpMessage = 'Computer Name',
            ValueFromPipeLine = $TRUE,
            ValueFromPipelineByPropertyName = $TRUE
            )]
        [string[]] $ComputerName
        )
    
    BEGIN{}

    PROCESS{
        foreach ($comp in $ComputerName ) {
            
            write-verbose "Looking up: $comp"
            if (test-connection -computername $comp -count 1 -quiet){
                

                
                    try { 
                        $OS = Get-WmiObject –Class Win32_OperatingSystem –ComputerName $comp -ErrorAction Stop 
                        $CompSys = Get-WmiObject –Class Win32_ComputerSystem –ComputerName $comp -ErrorAction Stop
                         #$Bios = (Get-WmiObject –Class Win32_Bios –ComputerName $comp)
        
                    $prop = @{"ComputerName" = $CompSys.__Server;
                              "OSVersion" = $OS.Version;
                              "OSBuild" = $OS.version;
                              "Caption" = $OS.Caption;
                              "SPVersion" = $OS.ServicePackMajorVersion;
                              "InstallDate"= $os.ConvertToDateTime($OS.installdate);
                              "Architechture" = $OS.OSArchitecture;
                              "Description" = $OS.description;
                              "LastBoot" = $os.ConvertToDateTime($OS.LastBootUpTime);
                              "UserName" = $CompSys.UserName;
                              "Manufacturer" = $CompSys.Manufacturer;
                              "Model" = $CompSys.Model;
                              #"BiosSerial" = $Bios.SerialNumber;
                              "RAM" = $CompSys.TotalPhysicalMemory;
                              "Processors" = $CompSys.NumberofProcessors
                            }
                    } catch {
                        $error = $_.Exception.Message
                        Write-Warning ("Error: {0} on {1}" -f $error,$comp)
                           $prop = @{"ComputerName" = $comp;
                          "OSVersion" = $null;
                          "OSBuild" = $null;
                          "SPVersion" = $null;
                          "InstallDate"= $null;
                          "Architechture" = $null;
                          "LastBoot" = $null;
                          "UserName" = $null;
                          "Manufacturer" = "Cannot Connect";
                          "Model" = $null;
                          #"BiosSerial" = $null;
                          "RAM" = $Null;
                          "Description" = $error;
                          "Processors" = $null
                    }
                    }
            
                   
                 
                  
        
                
             } else {
                write-verbose "Cannot ping"
                $prop = @{"ComputerName" = $comp;
                          "OSVersion" = $null;
                          "OSBuild" = $null;
                          "SPVersion" = $null;
                          "InstallDate"= $null;
                          "Architechture" = $null;
                          "LastBoot" = $null;
                          "UserName" = $null;
                          "Manufacturer" = "Cannot Connect";
                          "Model" = $null;
                          #"BiosSerial" = $null;
                          "RAM" = $Null;
                          "Processors" = $null

                        }
             }

            $obj = New-Object -TypeName PSObject -Property $prop
            $obj.psobject.typenames.insert(0, 'daveb.systools.SystemDetails')
            Write-Output $obj
        } # foreach in CopmuterName
    } #process
    END{}
}

Function Get-DiskDetails {
<#
.SYNOPSIS
    Returns the local drive details of a computer or set of computers

.DESCRIPTION
    Returns a custom object containing details of the local drive from one or multiple computers. Details include ComputerName, Drive ID, Free Space, Disk Size and the percentage of free space

.PARAMETER ComputerName
    The name of the computer(s)

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
 
#>
[cmdletBinding()]
Param ([Parameter (
            Mandatory = $TRUE,
            HelpMessage = 'Enter the name of the computer',
            ValueFromPipeLine = $TRUE,
            ValueFromPipelineByPropertyName = $TRUE
            )]
        [string[]] $ComputerName
        )

    BEGIN{$DriveType = 3}

    PROCESS{
        foreach ($comp in $ComputerName ) {
             write-verbose "Looking up: $comp"
            if (test-connection -computername $comp -count 1 -quiet){
                $LocalDrive = Get-WmiObject –Class Win32_LogicalDisk –ComputerName $comp -Filter "drivetype=$DriveType"
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

function Get-AutoStopped {
<#
.SYNOPSIS
    Finds the services which are set to start automatically which are not running

.DESCRIPTION
    Finds the services which are set to start automatically which are not running.

    Uses CimSession but with DCOM protocol

.PARAMETER ComputerName
    The name of the computer(s)

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
 Get-AutoStopped dnviweb02 | format-table -autosize
 PS C:\> Get-AutoStopped dnviweb02 | Format-Table -auto

ProcessName                    ExitCode StartMode ComputerName State   Status
-----------                    -------- --------- ------------ -----   ------
ccmsetup                           1068 Auto      DNVIWEB02    Stopped OK
clr_optimization_v4.0.30319_32        0 Auto      DNVIWEB02    Stopped OK
Dhcp                                  5 Auto      DNVIWEB02    Stopped OK
SysmonLog                             0 Auto      DNVIWEB02    Stopped OK
swi_update                         1077 Auto      DNVIWEB02    Stopped OK

.LINK
 Get-CimInstance Win32_Service

 .NOTES
 Author: Dave Bremer
 Updates:
    
#>

[cmdletBinding()]
    Param ([Parameter (
                Mandatory = $TRUE,
                HelpMessage = 'Enter the name of the computer',
                ValueFromPipeLine = $TRUE,
                ValueFromPipelineByPropertyName = $TRUE
                )]
            [string[]] $ComputerName
            )

    BEGIN{}

    PROCESS {
        Foreach ($comp in $ComputerName ) {
            $CS = New-CimSession -ComputerName $comp -SessionOption (New-CimSessionOption -Protocol dcom)
            $CI = Get-CimInstance -Query "SELECT * FROM Win32_Service WHERE StartMode = 'auto' AND state <> 'Running'" -CimSession $CS 

            foreach ($proc in $CI) {
            
            $prop = @{  "ComputerName" = $proc.SystemName;
                         "ProcessName" = $proc.Name;
                         "StartMode" = $proc.StartMode;
                         "State" = $proc.State;
                         "Status" = $proc.Status;
                          "ExitCode" = $proc.ExitCode  
                          }
        
                $obj = New-Object -TypeName PSObject -Property $prop
                $obj.psobject.typenames.insert(0, 'daveb.systools.process')
                Write-Output $obj
            } # foreach $Proc
            remove-cimsession $CS
        } #foreach comp
    } #process

    END{}
}

function Get-SoftDetails {
<#
.SYNOPSIS
Identifies if software is found by name on a PC

.DESCRIPTION
A number of fields are returned. 
    The PC is identified along with the most recently logged in user.
    The software is listed in a number of multi-value fields delimited by semicolon. These fields are:
        Software: A hashtable of the software name and version of software found
        SoftwareName: A semicolon delimited list of software name
        SoftwareVersion: A semicolon delimited list of the software version - matching softwarename
    Notes: Error messages found while trying to extract

.PARAMETER ComputerName
    The name of the computer(s). This can come from a pipeline

.PARAMETER Software
    The name of the software being sought. This must be supplied as a single argument. 


.EXAMPLE
get-softdetails -computername a21120 -software "office"
Returns:
    LastLoggedOnUser    : DNJICA0
    ADMember            : True
    SoftwareVersion     : 12.0.6425.1000;12.0.4518.1014;12.0.6425.1000;12.0.6425.1000;12.0.6425.1000
    lastlogonDate       : 31/08/2015 08:29:25
    ComputerName        : pc121212
    Notes               :
    SoftwareName        : Microsoft Office Standard 2007;Microsoft Office Proofing (English) 2007;Microsoft Office Proof
                          (English) 2007;Microsoft Office Proof (Spanish) 2007;Microsoft Office Proof (French) 2007
    Software            : {@{ComputerName=PC121212; name=Microsoft Office Standard 2007; version=12.0.6425.1000},
                          @{ComputerName=PC121212; name=Microsoft Office Proofing (English) 2007; version=12.0.4518.1014},
                          @{ComputerName=PC121212; name=Microsoft Office Proof (English) 2007; version=12.0.6425.1000},
                          @{ComputerName=PC121212; name=Microsoft Office Proof (Spanish) 2007; version=12.0.6425.1000}...}
    LastLoggedOnDisplay : Josie Miller

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
    
#>

    [cmdletBinding()]
        Param ([Parameter (
                    Mandatory = $TRUE,
                    HelpMessage = 'Computer Name',
                    ValueFromPipeLine = $TRUE,
                    ValueFromPipelineByPropertyName = $TRUE
                    )]
                [Alias("CN","Computer")] 
                [string[]] $ComputerName,

                [Parameter (
                    Mandatory = $TRUE,
                    HelpMessage = 'software',
                    ValueFromPipeLine = $FALSE,
                    ValueFromPipelineByPropertyName = $TRUE
                    )]
                [string] $software
                )
    
    BEGIN{}
    

    PROCESS{
    
    
    foreach ($pc in $ComputerName) {
        $Prop = @{"ComputerName" = $pc;
                   "lastlogonDate" = $null;
                   "LastLoggedOnUser" = $null;
                   "LastLoggedOnDisplay" = $null;
                   "ADMember" = $False;
                   "Software"=@{"ComputerName" = $PC;"Name" = $null;"Version"=$null};
                   "SoftwareName" = $null;
                   "SoftwareVersion" = $null;
                   "Notes" = ""
                   }


        Try {
                write-verbose "PC: $pc"
                $pcdata = get-adcomputer -Identity $pc -Properties lastlogondate
                $Prop.ADMember = $true;
                $Prop.LastLogonDate = $pcdata.lastlogondate

                Write-Verbose ("{0} is in AD, last login: {1}/{2}/{3}  " -f $prop.Computername,$Prop.LastLogonDate.day,$Prop.LastLogonDate.month,$Prop.LastLogonDate.year)

        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            $Prop.notes = "Not in AD. "
            Write-Verbose "$pc not in AD. "
        }

        Finally {
       # write-verbose $Error
                
        }
        if (test-connection -computername $pc -count 1 -Quiet){
        
            Try {
                Write-Verbose "Can ping so getting user..."
                $Prop.LastLoggedOnUser = (Get-LastLogonToSys $pc | select User).user.ToString().split("\")[1]
                $Prop.LastLoggedOnDisplay = (get-aduser -Identity $Prop.LastLoggedonUser | select name).name
                Write-Verbose ("Last Logon {0}: {1}" -f $Prop.lastLoggedonUser,$Prop.LastLoggedOnDisplay)
            } catch {
                write-warning "Failed getting last logged in user"
                $Prop.notes += "Failed getting last logged in user. "
                # $Prop.LastLoggedOnUser = "Could not get last user"
            } finally{}
            
            Try {
                Write-Verbose "Getting software called '$software'..."

                $Prop.Software = Get-WmiObject -Class Win32_Product -computername $pc -ErrorAction stop| 
                    select @{n="ComputerName";e={$_.__Server}},name, version | where name -match $software | 
                    where name -NotMatch "MUI"
                
            } Catch {
                Write-Warning "Failed WMI query getting software"
                $Prop.notes += "Failed WMI query getting software. "
            } Finally {
                
            }
        } else {
                Write-Verbose "$pc Can't ping"
                $Prop.Notes += "Can't ping. " 
               # $Prop.Software.Name = "No Ping"
        }
        
        #ok this might not be needed any more - this whole thing needs refactored to get away from doing this and including everything in the output seamlessly
        if ($Prop.Software.name) {
            $Prop.SoftwareName = ([string]::join(“;”, ($Prop.Software.name)))
            Write-Verbose ($Prop.SoftwareName)
        }

        if ($Prop.Software.version) {
            $Prop.SoftwareVersion = ([string]::join(“;”, ($Prop.Software.Version)))
        }

        $obj = New-Object -TypeName PSObject -Property $prop
        $obj.psobject.typenames.insert(0, 'daveb.systools.software')
        Write-Output $obj
        }
    }
}

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

.PARAMETER FileName
    Either a plain text list of computernames or a CSV file with a column headed "Computername".
  
.EXAMPLE 
    Get-AVProduct 
    Returns the AV details of the current computer

.EXAMPLE
    Get-AVProduct -FileName c:\temp\computers.csv

     A progress bar appears while the file is processed. If the file is CSV then it must have a field named "computername". 
     If it's not a CSV (or if the the first line is not just :computername") then the file is loaded with the asumption it is a list of computernames

.EXAMPLE
    gc 'c:\temp\computers.txt' | 
        Get-AVProduct | 
        select ComputerName,OS,CountProdsInstalled,AVProductName,ProductExecutable,versionNumber,DefinitionStatus,RealTimeProtectionStatus,QueryStatus,DateTime |
        Export-Csv 'f:\reports\AVreport.csv' -NoTypeInformation
    
    Tests all of the computers in the text file and outputs a csv file

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
 
 
#Requires -Version 2.0 
#> 
[CmdletBinding(DefaultParametersetName="computername")] 
[OutputType('PSobject')] 

param ( 
    [parameter(
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=1,
        ParameterSetName="computername")] 
    [Alias('CN')] 
    [String[]]$ComputerName=$env:computername,

    
    [Parameter (
        Mandatory=$True,
        Position=1,
        ValueFromPipelineByPropertyName = $False,
        
        ParameterSetName="file"
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
                throw "File '${_}' does not exist. Please provide the path to a file (not a directory) on your local computer and try again."
             } $true
         })]
        [string] $FileName
    
) 
 
BEGIN { 
 
    Set-StrictMode -Version Latest 
 
    ${CmdletName} = $Pscmdlet.MyInvocation.MyCommand.Name 
    
    Write-Debug -Message "${CmdletName}: Starting Begin Block"

    $set = $PsCmdlet.ParameterSetName
    Write-Verbose ("Set: {0}" -f $Set)
   
    
   if ($set -eq "file") {
          Write-Verbose ("Filename: {0}" -f $FileName)
          try { 

            #first try to open as CSV, if it doesn't look like a csv file then try just importing as a 
            if ((((([array](get-content $FileName))[0]) -split ",").count -gt 1) -or ( (gc C:\temp\compname-plain.txt -first 1) -eq 'computername' ) ) {
                Write-Verbose "Loading CSV"
                
                    $ComputerName = ((Import-Csv $FileName | Select computername).computername) -notmatch '^\s*$'
                    
                
             } else {
                Write-Verbose "Loading plain text"
                $ComputerName = (gc $FileName -notmatch '^\s*$')
                }
          } catch {
                throw ("File '{0}' looks empty" -f $filename)
            
            exit
          }

          #ok this SHOULD be in the bit where we're loading csv but I couldn't get it to work there
          if (($ComputerName).Count -eq 0) {
            Throw ("File '{0}' looks like it is a csv without a heading of `"ComputerName`"" -f $filename )
            exit
          }

           
     }
     
    $tot = ($computername | measure).count   
    Write-Verbose ("Total is {0}" -f $tot)
 
} # end BEGIN
 
PROCESS { 
    
    Write-Debug ("PROCESS:`n{0}" -f ($PSBoundParameters | Out-String)) 

    $counter=0 #for progress bar 
   
    ForEach ($Computer in $ComputerName) { 
       $counter+=1

       if ($tot -gt 2) { #don't  bother with progress bar if there's only a couple of devices
            $prog=[system.math]::round($counter/$tot*100,2)
            write-progress -activity ("Checking {0}. {1} computers left to check" -f $computer,($tot-$counter)) -status "$prog% Complete:" -percentcomplete $prog;
       } 
        
       Write-verbose ("Computer: {0}" -f $Computer)
        
                
       If (Test-Connection -ComputerName $Computer -count 2 -quiet) {  
            Try {
                $OSDetails = Get-WmiObject –Class Win32_OperatingSystem –ComputerName $Computer -ErrorAction Stop 
                $OSVersion = $OSDetails.version
                $OS = $OSVersion.split(".") 
                Write-Debug "`$OS[0]: $($OS[0])" 
                $OSName = $OSDetails.Caption
            } catch {
                Write-verbose "WMI Error getting OS"
                Write-verbose $_ 
                $OSName = "WMI Error getting OS Details"
                $prop =  @{ 
                        ComputerName = $Computer; 
                        OS = $Null;
                        CountProdsInstalled = $null;
                        QueryStatus = ("WMI Error querying OS" ); 
                        AVProductName = $null; 
                        versionNumber = $null; 
                        ProductExecutable = $null;  
                        DefinitionStatus = $null;
                        RealTimeProtectionStatus = $null;
                        DateTime = Get-Date
                        } 
                
                $obj = New-Object -TypeName PSObject -Property $prop
                $obj.psobject.typenames.insert(0, 'daveb.av')
                Write-Output $obj
                Continue
            } #try get-wmi for OS

            IF ($OS[0] -eq "5") { 
                Write-Verbose "Windows 2000, 2003, XP"  
                Try { 
                    $AntiVirusProducts = Get-WmiObject -Namespace root\SecurityCenter -Class AntiVirusProduct  -ComputerName $Computer -ErrorAction Stop 
                    $ProdCount = ($AntiVirusProducts | measure-object).count
                    if ($ProdCount -eq 0 ) {
                        Write-Warning "\\$computer MISSING!!!!!!!!!!!!!!!!!!!!!!!!!!!" 
                        $prop =  @{ 
                                        ComputerName = $Computer; 
                                        OS = $OSName;
                                        #CountProdsInstalled = $AntiVirusProduct.count;
                                         CountProdsInstalled = $ProdCount
                                        QueryStatus = "Success"; 
                                        AVProductName = "MISSING"; 
                                        versionNumber = $nullr; 
                                        ProductExecutable = $null;  
                                        DefinitionStatus = $null;
                                        RealTimeProtectionStatus = $null;
                                        DateTime = Get-Date
                                    }
                            $obj = New-Object -TypeName PSObject -Property $prop
                            $obj.psobject.typenames.insert(0, 'daveb.av')
                            Write-Output $obj
                    } else {
                        foreach ($AVProd in $AntiVirusProducts) {
                            $prop =  @{ 
                                        ComputerName = $Computer; 
                                        OS = $OSName;
                                        #CountProdsInstalled = $AntiVirusProduct.count;
                                         CountProdsInstalled = $ProdCount
                                        QueryStatus = "Success"; 
                                        AVProductName = $AVProd.displayName; 
                                        versionNumber = $AVProd.versionNumber; 
                                        ProductExecutable = $null;  
                                        DefinitionStatus = $AVProd.productUptoDate;
                                        RealTimeProtectionStatus = $AVProd.onAccessScanningEnabled;
                                        DateTime = Get-Date
                                            
                            }
                            $obj = New-Object -TypeName PSObject -Property $prop
                            $obj.psobject.typenames.insert(0, 'daveb.av')
                            Write-Output $obj
                        
                        }#foreach AV
                        
                       
                     }  #if AV prod
                    } Catch { 
                        $Errordetails = $_
                        Write-Error "$Computer : WMI Error" 
                        Write-Error $_
                        
                        $prop =  @{ 
                                    ComputerName = $Computer; 
                                    OS = $OSName;
                                    CountProdsInstalled = $null;
                                    QueryStatus = ("WMI ERROR: {0}" -f $Errordetails); 
                                    AVProductName = $null; 
                                    versionNumber = $null; 
                                    ProductExecutable = $null;  
                                    DefinitionStatus = $null;
                                    RealTimeProtectionStatus = $null;
                                    DateTime = Get-Date
                        } 
                        
                        $obj = New-Object -TypeName PSObject -Property $prop
                        $obj.psobject.typenames.insert(0, 'daveb.av')
                        Write-Output $obj
                        Continue 
                }     

            } ElseIF ($OS[0] -eq "6" -or $OS[0] -eq "10") { 
                Write-Verbose "Windows Vista, 7, 2008, 2008R2" 
                Try { 
                    $AntiVirusProducts = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct  -ComputerName $Computer -ErrorAction Stop 
                    $ProdCount = ($AntiVirusProducts | measure-object).count
                    if ($ProdCount -eq 0 ) {
                        Write-Warning "\\$computer MISSING!!!!!!!!!!!!!!!!!!!!!!!!!!!" 
                        $prop =  @{ 
                                        ComputerName = $Computer; 
                                        OS = $OSName;
                                        #CountProdsInstalled = $AntiVirusProduct.count;
                                         CountProdsInstalled = $ProdCount
                                        QueryStatus = "Success"; 
                                        AVProductName = "MISSING"; 
                                        versionNumber = $null; 
                                        ProductExecutable = $null;  
                                        DefinitionStatus = $null;
                                        RealTimeProtectionStatus = $null;
                                        DateTime = Get-Date
                                    }
                           $obj = New-Object -TypeName PSObject -Property $prop
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
                           $prop =  @{ 
                                ComputerName = $Computer; 
                                OS = $OSDetails.Caption;
                               # CountProdsInstalled = $AntiVirusProducts.count;
                               CountProdsInstalled = $ProdCount;
                                QueryStatus = "Success"; 
                                AVProductName = $AVProd.displayName;
                                versionNumber = $null; 
                                ProductExecutable = $AVProd.pathToSignedProductExe;;  
                                DefinitionStatus = $defstatus;
                                RealTimeProtectionStatus = $rtstatus;
                                DateTime = Get-Date
                                }
                        $obj = New-Object -TypeName PSObject -Property $prop
                        $obj.psobject.typenames.insert(0, 'daveb.av')
                        Write-Output $obj  
                        }
                                
                     }           
                     
                              
                 } Catch { 
                    $Errordetails = $_
                    Write-Error "$Computer : WMI Error" 
                    Write-Error $Errordetails 
                    $prop =  @{ 
                            ComputerName = $Computer; 
                            OS = $OSName;
                            CountProdsInstalled = $null;
                            QueryStatus = ("WMI ERROR: {0}" -f $Errordetails); 
                            AVProductName = $null; 
                            versionNumber = $null; 
                            ProductExecutable = $null;  
                            DefinitionStatus = $null;
                            RealTimeProtectionStatus = $null;
                            DateTime = Get-Date
                        }
                    $obj = New-Object -TypeName PSObject -Property $prop
                    $obj.psobject.typenames.insert(0, 'daveb.av')
                    Write-Output $obj         
                }  
 
            } Else { 
                Write-Error "\\$Computer : Unknown OS Version"
                $prop =  @{ 
                        ComputerName = $Computer; 
                        OS = $Null;
                        CountProdsInstalled = $null;
                        QueryStatus = ("Unknown OS or Error querying OS - Query Skipped" ); 
                        AVProductName = $null; 
                        versionNumber = $null; 
                        ProductExecutable = $null;  
                        DefinitionStatus = $null;
                        RealTimeProtectionStatus = $null;
                        DateTime = Get-Date
                        } 
                
                $obj = New-Object -TypeName PSObject -Property $prop
                $obj.psobject.typenames.insert(0, 'daveb.av')
                Write-Output $obj
            } # end If $OS 
             
             
        } Else { 
            Write-verbose "\\$computer No ping" 
            $prop =  @{ 
                    ComputerName = $Computer; 
                    OS = $null;
                    CountProdsInstalled = $null;
                    QueryStatus = ("No Ping"); 
                    AVProductName = $null; 
                    versionNumber = $null; 
                    ProductExecutable = $null;  
                    DefinitionStatus = $null;
                    RealTimeProtectionStatus = $null;
                    DateTime = Get-Date
                 }
             
                            
                $obj = New-Object -TypeName PSObject -Property $prop
                $obj.psobject.typenames.insert(0, 'daveb.av')
                Write-Output $obj
                 
        } # end IF (Test-Connection -ComputerName $Computer -count 2 -quiet)      
        
    } # end ForEach ($Computer in $computerName) 
 
} # end PROCESS 
 
END { Write-Verbose "Function Get-AVProduct finished." }  
} # end function Get-AVProduct

Function Get-TMServer {
<#
.SYNOPSIS


.DESCRIPTION
This is a simple Powershell script to find the Trend Micro server that a computer is talking too. This information is stored in the registry key on a machine

.SYNTAX
    get-TMServer

.EXAMPLE

Find the server
    Get-TM Server -computer 'COMPUTERNAME' 

Get all information stored in the key
    Get-TM Server -computer 'COMPUTERNAME' -FullInfo

.NOTES
Limited error handling is intentional due to errors being one of three things. No key (custom error message), WMI error or permission error
Autho: Owen Miller

#>

param(
[parameter(mandatory=$true)] $Computer,
[switch]$FullInfo
)

    if(Invoke-command -computer $Computer {test-path 'C:\Program Files (x86)'}){

        try{
            $RegInfo = Invoke-command -computer $Computer {Get-ItemProperty 'hklm:SOFTWARE\Wow6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion'}

            if($fullinfo)
            {
                $RegInfo
            }
            else{
                $RegInfo.Server.ToString()
            }

        }
        Catch{       
            write-warning 'x64 Registry key not found. Please confirm Trend Micro AV is installed on the machine'

        }
        
    }

    else{

        try{
            $RegInfo = Invoke-command -computer $Computer {Get-ItemProperty 'hklm:SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion'}

            if($fullinfo)
            {
                $RegInfo
            }
            else{
                $RegInfo.Server.ToString()
            }

        }
        catch{     
            write-warning 'x86 Registry key not found. Please confirm Trend Micro AV is installed on the machine'    
        
        }

    }  
    
}
