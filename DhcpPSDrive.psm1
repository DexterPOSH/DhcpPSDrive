using namespace Microsoft.PowerShell.SHiPS

[SHiPSProvider(UseCache=$true)]
class DhcpPSDrive : SHiPSDirectory
{
    DhcpPSDrive ([String]$name) : base($name)
    {

    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        foreach ($DhcpServer in (Get-DhcpServerInDC | Where-Object -FilterScript {$PSitem.DnsName -eq 'stg-dhcp02.stage.linkedin.biz'}))
        {
            $obj.Add([DhcpServer]::new($DhcpServer))
        }
        
        return $obj
    }
}

[SHiPSProvider(UseCache=$true)]
class DhcpServer : SHiPSDirectory
{
    [String] $DnsName
    [String] $IPAddress
    [String] $MSReleaseLease
    [String[]] $TimeList
    [String[]] $DnsList
    [String[]] $DomainList
    [String[]] $NtpList
    [String[]] $UcTftpCallMgrList
    [int] $DynamicDnsQueueLength
    [hashtable] $IPv4Binding
    [hashtable] $Ipv6Binding
    
    # Constructor used for mounting a PSDrive for the local DNS Server
    DhcpServer ([string] $name) :base($env:COMPUTERNAME)
    {
        $this.DnsName = $env:COMPUTERNAME
        $DnsService = Get-Service -Name DhcpServer
        if ($DnsService.Status -eq 'Running')
        {
            $this.IPAddress = Resolve-DnsName -Name $env:COMPUTERNAME -Type A -DnsOnly | Select-Object -First 1 | Select-Object -ExpandProperty IPAddress
        }
        else 
        {
            Throw "DNS service is not running on $($this.DnsName)"
        }
        
        $this.InitializeDHCPServerProperties()
    }

    DhcpServer ([object]$InputObject) : base($InputObject.DnsName)
    {
        $this.DnsName           = $InputObject.DnsName
        $this.IPAddress         = $InputObject.IPAddress
        $this.InitializeDHCPServerProperties()
    }

    InitializeDHCPServerProperties ()
    {
        try 
        {
            $this.MsReleaseLease    = Get-DhcpServerv4OptionValue -ComputerName $this.DnsName -OptionId 2 -VendorClass 'Microsoft Options' -ErrorAction SilentlyContinue | 
                                    Select-Object -ExpandProperty Value
            $this.TimeList          = ( Get-DhcpServerv4OptionValue -ComputerName $this.DnsName -OptionId 4 -ErrorAction SilentlyContinue ).Value
            $this.DnsList           = ( Get-DhcpServerv4OptionValue -ComputerName $this.DnsName -OptionId 6 -ErrorAction SilentlyContinue ).Value
            $this.DomainList        = ( Get-DhcpServerv4OptionValue -ComputerName $this.DnsName -OptionId 15 -ErrorAction SilentlyContinue ).Value
            $this.NtpList           = ( Get-DhcpServerv4OptionValue -ComputerName $this.DnsName -OptionId 42 -ErrorAction SilentlyContinue ).Value
            $this.UcTftpCallMgrList = ( Get-DhcpServerv4OptionValue -ComputerName $this.DnsName -OptionId 150 -ErrorAction SilentlyContinue ).Value
            $this.IPv4Binding       = Get-DhcpServerv4Binding | Convert-PSObjectToHashTable
            $this.Ipv6Binding       = Get-DhcpServerv6Binding | Convert-PSObjectToHashTable
            $this.DynamicDnsQueueLength = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DhcpServer\Parameters `
                                            -Name DynamicDNSQueueLength -ErrorAction SilentlyContinue |
                                                Select-Object -ExpandProperty DynamicDNSQueueLength
        }
        catch
        {
            Write-Warning -Message "[InitializeDHCPServerProperties] $PSItem.Exception"
        }
        
    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        $obj.Add([IPv4]::new($this.DnsName))
        #$obj.Add([IPv6]::new($this.DnsName))
        return $obj 
    }

    [Microsoft.Management.Infrastructure.CimInstance[]] DisplayV4Statistics ()
    {
        return $(Get-DhcpServerv4Statistics -ComputerName $this.DnsName)
    }

    [Microsoft.Management.Infrastructure.CimInstance[]] DisplayV6Statistics ()
    {
        return $(Get-DhcpServerv6Statistics -ComputerName $this.DnsName)
    }
}


[SHiPSProvider(UseCache=$true)]
class IPv4 : SHiPSDirectory
{
    [String] $DnsName

    IPv4 ([string]$DnsName) :base($this.GetType())
    {
        $this.DnsName = $DnsName
    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        $v4Scopes = @(Get-DhcpServerv4Scope -ComputerName $this.DnsName)
        foreach ($v4Scope in $v4Scopes)
        {
            $obj.Add([v4Scope]::new($v4Scope, $this.DnsName))
        }
        return $obj
    }

}

[SHiPSProvider(UseCache=$true)]
class v4Scope : SHiPSDirectory
{
    [String] $DnsName
    [String] $Name
    [String] $ScopeId
    [String] $SubnetMask
    [String] $State
    [String] $StartRange
    [String] $EndRange
    [string] $LeaseDuration
    [hashtable] $DNSSettings

    v4Scope([object] $InputObject, [string] $DnsName) :base($InputObject.Name)
    {
        $this.Name          = $InputObject.Name
        $this.ScopeId       = $InputObject.ScopeId
        $this.SubnetMask    = $InputObject.SubnetMask
        $this.State         = $InputObject.State
        $this.StartRange    = $InputObject.StartRange
        $this.EndRange      = $InputObject.EndRange
        $this.LeaseDuration = $InputObject.LeaseDuration
        $this.DnsName       = $DnsName

        # Populate the DNS Settings hashtable
        $DnsSetting = Get-DhcpServerv4DnsSetting -ComputerName $this.DnsName -ScopeId $this.ScopeId -ErrorAction SilentlyContinue
        $this.DNSSettings = Convert-PSObjectToHashTable -InputObject $DnsSetting

    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        $obj.Add([ScopeOptions]::new($this.ScopeId, $this.DnsName))
        $obj.Add([Reservations]::new($this.ScopeId, $this.DnsName))
        $obj.Add([AddressLeases]::new($this.ScopeId, $this.DnsName))
        return $obj
    }

    [Microsoft.Management.Infrastructure.CimInstance[]] DisplayStatistics ()
    {
        return $(Get-DhcpServerv4ScopeStatistics -ComputerName $this.DnsName -ScopeId $this.ScopeId)
    }

    ReplicateScope ()
    {

    }

    [bool] TestReverseDNSLookupZone ()
    {
        # this method will test if the reverse lookup zones are created for the scope
        return $false
    }

    [bool] TestADSubnet ()
    {
        # this method will test if the corresponding AD subnet exists for the DHCP v4 Scope
        return $false
    }
}

[SHiPSProvider(UseCache=$true)]
class ScopeOptions : SHiPSDirectory
{
    [String] $ScopeId
    [String] $DnsName
    
    ScopeOptions ([String] $ScopeId, [String] $DnsName) :base($this.GetType())
    {
        $this.ScopeId = $ScopeId 
        $this.DnsName = $DnsName
    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        $ScopeOptions = @(
            @{
                Name = 'MsReleaseDhcpLease'
                OptionId = 2
                VendorClass = 'Microsoft Options'
            },
            @{
                Name = 'DnsServers'
                OptionId = 6
            },
            @{
                Name = 'DomainList'
                OptionId = 15
            },
            @{
                Name = 'NtpList'
                OptionId = 42
            },
            @{
                Name = 'TimeList'
                OptionId = 4
            }
        )

        Foreach ($scopeOption in $ScopeOptions)
        {
            $obj.Add([v4ScopeOption]::New($this.ScopeId, $this.DnsName, $scopeOption))
        }
        
        return $obj
    }
}

[SHiPSProvider(UseCache=$true)]
class v4ScopeOption : SHiPSLeaf
{
    [String] $DnsName
    [String] $ScopeId
    [String] $VendorClass
    [String] $OptionId
    [String] $Name
    [object] $Value

    v4ScopeOption ([String] $ScopeId, [String] $DnsName, [hashtable] $ScopeOption) :base("$($ScopeOption['OptionId']) $($ScopeOption['Name'])")
    {
        $this.ScopeId = $ScopeId
        $this.DnsName = $DnsName
        $this.Name = $ScopeOption['Name']
        $this.OptionId = $ScopeOption['OptionId']

        if ($ScopeOption['VendorClass'])
        {
            $this.VendorClass = $ScopeOption['VendorClass']
        }
        else
        {
            $this.VendorClass = $ScopeOption['Standard']
        }

        $null = $ScopeOption.Remove('Name')
        $this.Value = Get-DhcpServerv4OptionValue -ComputerName $this.DnsName -ScopeId $this.ScopeId @ScopeOption -ErrorAction SilentlyContinue |
                            Select-Object -ExpandProperty Value
        
    }
}

#region reservations
[SHiPSProvider(UseCache=$true)]
class Reservations : SHiPSDirectory
{
    [String] $ScopeId
    [String] $DnsName
    
    Reservations ([String] $ScopeId, [String] $DnsName) :base($this.GetType())
    {
        $this.ScopeId = $ScopeId 
        $this.DnsName = $DnsName
    }

    [Reservation[]] GetChildItem ()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        foreach ($reservation in $(Get-DhcpServerv4Reservation -ScopeId $this.ScopeId -ComputerName $this.DnsName)) {
            $obj.Add([Reservation]::new($this.ScopeId, $this.DnsName, $reservation))
        }
        return $obj
    }

}


[SHiPSProvider(UseCache=$true)]
class Reservation : SHiPSLeaf
{
    [String] $ScopeId
    [String] $ClientId
    [String] $Name
    [String] $Type
    [String] $IPAddress
    [String] $AddressState
    [String] $Description
    [String] $DnsName

    Reservation ([String] $ScopeId, [String] $DnsName, [Object] $InputObject) :base($InputObject.Name)
    {
        $this.ScopeId = $ScopeId
        $this.DnsName = $DnsName
        $this.ClientId = $InputObject.ClientId
        $this.Name = $InputObject.Name
        $this.Type = $InputObject.Type
        $this.IPAddress = $InputObject.IPAddress
        $this.AddressState = $InputObject.AddressState
        $this.Description = $InputObject.Description
    }
}
#endregion reservations

#region AddressLeases
[SHiPSProvider(UseCache=$true)]
class AddressLeases : SHiPSDirectory
{
    [String] $ScopeId
    [String] $DnsName
    
    AddressLeases ([String] $ScopeId, [String] $DnsName) :base($this.GetType())
    {
        $this.ScopeId = $ScopeId 
        $this.DnsName = $DnsName
    }

    [AddressLease[]] GetChildItem ()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        foreach ($reservation in $(Get-DhcpServerv4Lease -ScopeId $this.ScopeId -ComputerName $this.DnsName)) {
            $obj.Add([AddressLease]::new($this.ScopeId, $this.DnsName, $reservation))
        }
        return $obj
    }

}


[SHiPSProvider(UseCache=$true)]
class AddressLease : SHiPSLeaf
{
    [String] $AddressState
    [String] $ClientId
    [String] $ClientType
    [String] $Description
    [String] $DnsRegistration
    [String] $DnsRR
    [String] $HostName
    [String] $LeaseExpiryTime
    [bool] $NapCapable
    [String] $NapStatus
    [String] $PolicyName
    [String] $ProbationEnds
    [String] $ServerIP
    [String] $ScopeId
    [String] $DnsName

    AddressLease ([String] $ScopeId, [String] $DnsName, [Object] $InputObject) :base($InputObject.IPAddress)
    {
        $this.ScopeId = $ScopeId
        $this.DnsName = $DnsName
        $this.ClientId = $InputObject.ClientId
        $this.Name = $InputObject.Name
        $this.Type = $InputObject.Type
        $this.IPAddress = $InputObject.IPAddress
        $this.AddressState = $InputObject.AddressState
        $this.Description = $InputObject.Description
    }
}

#endregion AddressLeases
Function Convert-PSObjectToHashTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
                    ValueFromPipeline = $true)]
        [object]$InputObject,

        [Parameter()]
        [String[]]$Exclude
    )
    Process
    {
        $returnHashTable = @{}
        $InputObject | Get-Member -MemberType Property | Foreach-Object -Process {
            if ($Exclude -notcontains $PSItem.Name)
            {
                $returnHashTable[$($PSItem.Name)] = $InputObject.$($PSItem.Name)
            }
        }
        return $returnHashTable
    }
}
