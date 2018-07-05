using namespace Microsoft.PowerShell.SHiPS

[SHiPSProvider()]
class DhcpPSDrive : SHiPSDirectory
{
    #static [System.Collections.ArrayList] $DHCPServers
    static [System.Collections.Generic.List``1[Microsoft.Management.Infrastructure.CimSession]] $Sessions

    DhcpPSDrive ([String]$name) : base($name)
    {

    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        if([DhcpPSDrive]::sessions){
            [DhcpPSDrive]::sessions | ForEach-Object {
                $obj += [DhcpServer]::new($_.ComputerName, $_)
            }
        }
        else{
            $obj += [DhcpPSDrive]::new('localhost')
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
    [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null
    
    # Constructor used for mounting a PSDrive for the local DNS Server
    DhcpServer ([string] $name) :base($name)
    {
        $this.CimSession = New-CimSession -ComputerName $name
        if (Get-DhcpServerSetting -CimSession $this.CimSession) # Check if it is a DHCP Server first
        {
            [DhcpPSDrive]::Sessions += $this.CimSession
            $this.InitializeDHCPServerProperties()
        }
        
    }

    DhcpServer([string]$name, [Microsoft.Management.Infrastructure.CimSession]$cimsession):base($name)
    {
        $this.CimSession = $cimsession
    }


    InitializeDHCPServerProperties ()
    {
        try 
        {
            $this.MsReleaseLease    = Get-DhcpServerv4OptionValue -CimSession $this.CimSession -OptionId 2 -VendorClass 'Microsoft Options' -ErrorAction SilentlyContinue | 
                                    Select-Object -ExpandProperty Value
            $this.TimeList          = ( Get-DhcpServerv4OptionValue -CimSession $this.CimSession -OptionId 4 -ErrorAction SilentlyContinue ).Value
            $this.DnsList           = ( Get-DhcpServerv4OptionValue -CimSession $this.CimSession -OptionId 6 -ErrorAction SilentlyContinue ).Value
            $this.DomainList        = ( Get-DhcpServerv4OptionValue -CimSession $this.CimSession -OptionId 15 -ErrorAction SilentlyContinue ).Value
            $this.NtpList           = ( Get-DhcpServerv4OptionValue -CimSession $this.CimSession -OptionId 42 -ErrorAction SilentlyContinue ).Value
            $this.UcTftpCallMgrList = ( Get-DhcpServerv4OptionValue -CimSession $this.CimSession -OptionId 150 -ErrorAction SilentlyContinue ).Value
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
        $obj.Add([IPv4]::new($this.DnsName, $this.CimSession))
        #$obj.Add([IPv6]::new($this.DnsName))
        return $obj 
    }

    [Microsoft.Management.Infrastructure.CimInstance[]] DisplayV4Statistics ()
    {
        return $(Get-DhcpServerv4Statistics -CimSession $this.CimSession)
    }

    [Microsoft.Management.Infrastructure.CimInstance[]] DisplayV6Statistics ()
    {
        return $(Get-DhcpServerv6Statistics -CimSession $this.CimSession)
    }
}


[SHiPSProvider(UseCache=$true)]
class IPv4 : SHiPSDirectory
{
    [String] $DnsName
    [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null

    IPv4 ([string]$DnsName, [Microsoft.Management.Infrastructure.CimSession]$CimSession) :base($this.GetType())
    {
        $this.DnsName       = $DnsName
        $this.CimSession    = $CimSession
    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        $v4Scopes = @(Get-DhcpServerv4Scope -CimSession $this.CimSession)
        foreach ($v4Scope in $v4Scopes)
        {
            $obj.Add([v4Scope]::new($v4Scope, $this.DnsName, $this.CimSession))
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
    [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null

    v4Scope([object] $InputObject, [string] $DnsName, [Microsoft.Management.Infrastructure.CimSession]$CimSession) :base($InputObject.Name)
    {
        $this.Name          = $InputObject.Name
        $this.ScopeId       = $InputObject.ScopeId
        $this.SubnetMask    = $InputObject.SubnetMask
        $this.State         = $InputObject.State
        $this.StartRange    = $InputObject.StartRange
        $this.EndRange      = $InputObject.EndRange
        $this.LeaseDuration = $InputObject.LeaseDuration
        $this.DnsName       = $DnsName
        $this.CimSession    = $CimSession

        # Populate the DNS Settings hashtable
        $DnsSetting = Get-DhcpServerv4DnsSetting -CimSession $this.CimSession -ScopeId $this.ScopeId -ErrorAction SilentlyContinue
        $this.DNSSettings = Convert-PSObjectToHashTable -InputObject $DnsSetting

    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        $obj.Add([ScopeOptions]::new($this.ScopeId, $this.DnsName, $this.CimSession))
        $obj.Add([Reservations]::new($this.ScopeId, $this.DnsName, $this.CimSession))
        $obj.Add([AddressLeases]::new($this.ScopeId, $this.DnsName, $this.CimSession))
        return $obj
    }

    [Microsoft.Management.Infrastructure.CimInstance[]] DisplayStatistics ()
    {
        return $(Get-DhcpServerv4ScopeStatistics -CimSession $this.CimSession -ScopeId $this.ScopeId)
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
    [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null
    
    ScopeOptions ([String] $ScopeId, [String] $DnsName, [Microsoft.Management.Infrastructure.CimSession]$CimSession) :base($this.GetType())
    {
        $this.ScopeId       = $ScopeId 
        $this.DnsName       = $DnsName
        $this.CimSession    = $CimSession
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
    [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null

    v4ScopeOption ([String] $ScopeId, [String] $DnsName, [hashtable] $ScopeOption, [Microsoft.Management.Infrastructure.CimSession]$CimSession) :base("$($ScopeOption['OptionId']) $($ScopeOption['Name'])")
    {
        $this.ScopeId = $ScopeId
        $this.DnsName = $DnsName
        $this.CimSession = $CimSession
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
        $this.Value = Get-DhcpServerv4OptionValue -CimSession $this.CimSession -ScopeId $this.ScopeId @ScopeOption -ErrorAction SilentlyContinue |
                            Select-Object -ExpandProperty Value
        
    }
}

#region reservations
[SHiPSProvider(UseCache=$true)]
class Reservations : SHiPSDirectory
{
    [String] $ScopeId
    [String] $DnsName
    [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null
    
    Reservations ([String] $ScopeId, [String] $DnsName, [Microsoft.Management.Infrastructure.CimSession]$CimSession) :base($this.GetType())
    {
        $this.ScopeId       = $ScopeId 
        $this.DnsName       = $DnsName
        $this.CimSession    = $CimSession
    }

    [Reservation[]] GetChildItem ()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        foreach ($reservation in $(Get-DhcpServerv4Reservation -ScopeId $this.ScopeId -CimSession $this.CimSession)) {
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
    [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null

    
    AddressLeases ([String] $ScopeId, [String] $DnsName, [Microsoft.Management.Infrastructure.CimSession]$CimSession) :base($this.GetType())
    {
        $this.ScopeId       = $ScopeId 
        $this.DnsName       = $DnsName
        $this.CimSession    = $CimSession
    }

    [AddressLease[]] GetChildItem ()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        foreach ($reservation in $(Get-DhcpServerv4Lease -ScopeId $this.ScopeId -CimSession $this.CimSession)) {
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


#region cmdlets

function Get-CMSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )    
    [DhcpPSDrive]::Sessions | Where-Object {$_.ComputerName -eq $ComputerName}
}


function Connect-DHCPServer {
    [CmdletBinding()]
    param(
        # Specify the list of DHCP servers to connect to
        [Parameter(Mandatory = $true)]
        [string] $ComputerName,

        # Specify the credentials used to connect.
        [Parameter()]
        [pscredential] $Credential

    )

    if (Get-CMSession -ComputerName $ComputerName)
    {
        Write-Verbose -Message "Already connected to DHCP Server $ComputerName. Skipping ..."
    }
    else
    {
        if ([DhcpPSDrive]::Sessions)
        {
            ([DhcpPSDrive]::Sessions).Add((New-CimSession -ComputerName $ComputerName -Credential $Credential)) 
        }
        else
        {
            [DhcpPSDrive]::Sessions += New-CimSession -ComputerName $ComputerName -Credential $Credential
        }

        
    }
}


function Disconnect-DHCPServer {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )
    $sessionToRemove = Get-DHCPSession -ComputerName $ComputerName

    if($sessionToRemove){
        if(([DhcpPSDrive]::Sessions).Remove($sessionToRemove)){
            Remove-CimSession -CimSession $sessionToRemove -ErrorAction Stop
        }
    }
    else{
        Write-Verbose -Verbose -Message "No connection to DHCP Server $ComputerName. Skipping ..."        
    }
}
#endregion cmdlets

Export-ModuleMember -Function 'Connect-DHCPServer','Disconnect-DHCPServer'