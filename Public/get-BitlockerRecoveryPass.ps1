function Get-BitlockerRecoveryPass {
<#
.SYNOPSIS
    Returns the bitlocker key of a computer from AD

.DESCRIPTION
   Returns the bitlocker key of a computer from AD

.PARAMETER ComputerName
    The name of the Computer, or comma seperated list of computers

.EXAMPLE
 Get-BitlockerRecoveryPass l-asd123gh
 Returns the details of the computer object l-asd123gh


.NOTES
 Author: Dave Bremer
 Updates: 28/5/2018 created - based on notes from http://eddiejackson.net/wp/?p=7464
    
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
        
        [String[]] $ComputerName
        )
    
    BEGIN{
        

        $obj = New-Object PSObject -Property @{
            ComputerName = $null
            PasswordDate = $null
            RecoveryPassword = $null
            QueryStatus = $null          
            }
    }

PROCESS{
    foreach ($comp in $ComputerName ) {
        #reset values
        $comp = $comp.trim()
        $obj.ComputerName = $null
        $obj.RecoveryPassword = $null
        $obj.PasswordDate = $null
        $obj.QueryStatus = $null

        write-verbose ("Looking up: `"{0}`"" -f $comp)

            

        try { 
            $Computer_Object = (Get-ADComputer -Filter {name -eq $Comp})   
            $obj.ComputerName = $comp
            if ($Computer_Object) {
                $Bitlocker_Object = (Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $Computer_Object.DistinguishedName -Properties 'msFVE-RecoveryPassword',created | 
                                    sort created |
                                    Select-Object -Last 1 )
                        
                        
                $obj.RecoveryPassword = $Bitlocker_Object.'msFVE-RecoveryPassword'
                if ($Bitlocker_Object.created) {
                    $obj.PasswordDate = $Bitlocker_Object.Created.tostring('dd/MM/yy hh:mm:ss')
                } else {
                    $obj.PasswordDate = $null
                }
                $obj.QueryStatus = "Success"
            } else {
                $obj.RecoveryPassword = $null
                $obj.QueryStatus = "Computer object not found"
                Write-Warning (" {0} not found" -f $comp)
            }
     
        } catch {
            $error = $_.Exception.Message
            $obj.Computername = $Comp
            $obj.QueryStatus = $error
            Write-Warning ("Error: {0} on {1}" -f $error,$comp)
                        
        }

        $obj.psobject.typenames.insert(0, 'daveb.systools.get-BitlockerRecoveryPass')
        Write-Output $obj
        } # foreach in ComputerName
    } #process
    END{}
}