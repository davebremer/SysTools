Function Get-Online {

<#
.SYNOPSIS
    Lists whether a device can be pinged and also looks up DNS & ADComputer names 

.DESCRIPTION
    Lists whether a device can be pinged and also looks up DNS & ADComputer  names to give an indication of whether
    the device actually exists. The AD Distinguished name is only looked up if the ActiveDirectory module is loaded.

    Computername will take input from the pipleline, either as a stream of values or from objects which have a value "computername"
    

.PARAMETER ComputerName

.EXAMPLE
    get-online abc123

    DNSName           : abc123.example.com
    IPAddress         : 10.1.1.123
    ComputerName      : abc123
    DistinguishedName : CN=abc123,OU=Workstations,DC=example,DC=cp,
    Online            : True

.EXAMPLE
    gc simplelist.txt | get-online 

    This will pass each line of the text file as a computername - assumes no headers

.EXAMPLE
    import-csv TableOfComputers.csv | get-online

    This will pass the field ComputerName (assuming one exists) to the parameter ComputerName


.NOTES
 Author: Dave Bremer

#>
[cmdletBinding()]
Param (
        [Parameter(ValueFromPipelineByPropertyName,
            ValueFromPipeline)]
        [string[]] $ComputerName
)

BEGIN{
    $AD=$false
    $prop = @{
        "ComputerName"=$Null;
        "Online" = $False;
        "DNSName" = $null;
        IPAddress = $null
        }

    if (get-module -name ActiveDirectory -ErrorAction SilentlyContinue) {
        $prop.add("DistinguishedName", $null)
        $AD=$true
    }

    $obj = New-Object -TypeName PSObject -Property $prop
    $obj.psobject.typenames.insert(0, 'daveb.systools.getOnline')
        
}

PROCESS{
    foreach ($name in $ComputerName){
        
        $obj.Computername = $name
        $obj.Online = $False
        
        try {
            $lookup = (Resolve-DnsName $name -ErrorAction Stop )
            $obj.IPAddress = ($lookup.IPAddress -join ", ")
            if ($lookup.count -gt 1) {
                $obj.DNSName = $lookup[0].name
            } else {
                $obj.DNSName = $lookup.Name
                #$obj.IPAddress = $lookup.IPAddress
                
            }
        } catch {
            $obj.DNSName = $null
            $obj.IPAddress = $null
        }

      
        $obj.Online = (Test-Connection -ComputerName $name -Count 1 -quiet)

        write-verbose ("Checking {0} - online: {1}" -f $name, $obj.online )

        if ($AD) {
            try {
                $obj.DistinguishedName = (get-adcomputer $name -ErrorAction stop).DistinguishedName
            } catch {
                $obj.DistinguishedName = $null
            }
        }
    
        $obj
    }
}

}

#get-online W-GHP2YC2
#get-online nosuchname,W-GHP2YC2,L-47Z95S2 # -Verbose