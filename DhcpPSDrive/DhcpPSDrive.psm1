using namespace Microsoft.PowerShell.SHiPS

[SHiPSProvider(UseCache=$True)]
class DhcpRoot : SHiPSDirectory
{
    #static [System.Collections.ArrayList] $DHCPServers
    static [System.Collections.Generic.List``1[Microsoft.Management.Infrastructure.CimSession]] $Sessions

    DhcpRoot ([String]$name) : base($name)
    {

    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        if([DhcpRoot]::sessions){
            [DhcpRoot]::sessions | ForEach-Object {
                $obj += [DhcpServer]::new($_.ComputerName, $_)
            }
        }
        else{
            $obj += [DhcpServer]::new("$env:COMPUTERNAME")
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
    [hashtable[]] $IPv4Binding
    [hashtable[]] $Ipv6Binding
    [hashtable] $ServerSetting
    
    hidden [Microsoft.Management.Infrastructure.CimSession] $CimSession = $null
    
    # Constructor used for mounting a PSDrive for the local DNS Server
    DhcpServer ([string] $name) :base($name)
    {
        $this.CimSession = New-CimSession -ComputerName $name
        $DhcpSetting = Get-DhcpServerSetting -CimSession $this.CimSession
        if ($DhcpSetting) # Check if it is a DHCP Server first, 
        {
            [DhcpRoot]::Sessions += $this.CimSession
            $this.ServerSetting = $DhcpSetting | Convert-PSObjectToHashTable -Exclude PSComupterName
        }
        
    }

    DhcpServer([string]$name, [Microsoft.Management.Infrastructure.CimSession]$cimsession):base($name)
    {
        $this.CimSession = $cimsession
        $DhcpSetting = Get-DhcpServerSetting -CimSession $this.CimSession
        if ($DhcpSetting) # Check if it is a DHCP Server first, 
        {
            [DhcpRoot]::Sessions += $this.CimSession
            $this.ServerSetting = $DhcpSetting | Convert-PSObjectToHashTable -Exclude PSComupterName
        }
    }


    Initialize ()
    {
        try 
        {
            Write-Verbose -Message "Setting Dhcp Server $this.Name properties..." -Verbose
            $this.MsReleaseLease    = Get-DhcpServerv4OptionValue -CimSession $this.CimSession -OptionId 2 -VendorClass 'Microsoft Options' -ErrorAction SilentlyContinue | 
                                        Select-Object -ExpandProperty Value
            $this.TimeList          = ( Get-DhcpServerv4OptionValue -CimSession $this.CimSession -OptionId 4 -ErrorAction SilentlyContinue ).Value
            $this.DnsList           = ( Get-DhcpServerv4OptionValue -CimSession $this.CimSession -OptionId 6 -ErrorAction SilentlyContinue ).Value
            $this.DomainList        = ( Get-DhcpServerv4OptionValue -CimSession $this.CimSession -OptionId 15 -ErrorAction SilentlyContinue ).Value
            $this.NtpList           = ( Get-DhcpServerv4OptionValue -CimSession $this.CimSession -OptionId 42 -ErrorAction SilentlyContinue ).Value
            $this.UcTftpCallMgrList = ( Get-DhcpServerv4OptionValue -CimSession $this.CimSession -OptionId 150 -ErrorAction SilentlyContinue ).Value
            $this.IPv4Binding       = Get-DhcpServerv4Binding -CimSession $this.CimSession -ErrorAction SilentlyContinue | Convert-PSObjectToHashTable
            $this.Ipv6Binding       = Get-DhcpServerv6Binding -CimSession $this.CimSession -ErrorAction SilentlyContinue | Convert-PSObjectToHashTable
            <#
            $this.DynamicDnsQueueLength = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\DhcpServer\Parameters `
                                            -Name DynamicDNSQueueLength -ErrorAction SilentlyContinue |
                                                Select-Object -ExpandProperty DynamicDNSQueueLength
            #>
            Write-Verbose -Message "Setting Dhcp Server properties done." -Verbose
        }
        catch
        {
            Write-Warning -Message "[Initialize] $PSItem.Exception"
        }
        
    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        $obj.Add([IPv4]::new($this.CimSession))
        $obj.Add([IPv6]::new($this.CimSession))
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


#region IPv4 Scopes

[SHiPSProvider(UseCache=$true)]
class IPv4 : SHiPSDirectory
{
    [hashtable] $DNSSetting
    [hashtable[]] $FailoverRelationShips
    hidden [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null

    IPv4 ([Microsoft.Management.Infrastructure.CimSession]$CimSession) :base($this.GetType())
    {
        $this.CimSession    = $CimSession
        $this.DnsSetting = Get-DhcpServerv4DnsSetting -CimSession $this.CimSession -ErrorAction SilentlyContinue |
                            Convert-PSObjectToHashTable
        $this.FailoverRelationShips = Get-DhcpServerv4Failover -CimSession $this.CimSession | Convert-PSObjectToHashTable
    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        $v4Scopes = @(Get-DhcpServerv4Scope -CimSession $this.CimSession)
        foreach ($v4Scope in $v4Scopes)
        {
            $obj.Add([v4Scope]::new($v4Scope, $this.CimSession))
        }
        return $obj
    }

}

[SHiPSProvider(UseCache=$true)]
class v4Scope : SHiPSDirectory
{
    [String] $Name
    [String] $SubnetMask
    [String] $State
    [String] $StartRange
    [String] $EndRange
    [string] $LeaseDuration
    [hashtable] $DNSSetting
    [hashtable] $FailoverRelationShip
    hidden [String] $ScopeId
    hidden [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null

    v4Scope([object] $InputObject, [Microsoft.Management.Infrastructure.CimSession]$CimSession) :base($InputObject.Name)
    {
        $this.Name          = $InputObject.Name
        $this.ScopeId       = $InputObject.ScopeId
        $this.SubnetMask    = $InputObject.SubnetMask
        $this.State         = $InputObject.State
        $this.StartRange    = $InputObject.StartRange
        $this.EndRange      = $InputObject.EndRange
        $this.LeaseDuration = $InputObject.LeaseDuration
        $this.CimSession    = $CimSession

        # Populate the DNS Settings hashtable
        $this.DNSSetting = Get-DhcpServerv4DnsSetting -CimSession $this.CimSession -ScopeId $this.ScopeId |
                                Convert-PSObjectToHashTable
        $this.FailoverRelationShip = Get-DhcpServerv4Failover -CimSession $this.CimSession -ScopeId $this.ScopeId  -ErrorAction SilentlyContinue|
                                        Convert-PSObjectToHashTable

    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        $obj.Add([ScopeOptions]::new($this.ScopeId, $this.CimSession))
        $obj.Add([Reservations]::new($this.ScopeId, $this.CimSession))
        $obj.Add([AddressLeases]::new($this.ScopeId, $this.CimSession))
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
    hidden [String] $ScopeId
    hidden [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null
    
    ScopeOptions ([String] $ScopeId, [Microsoft.Management.Infrastructure.CimSession]$CimSession) :base($this.GetType())
    {
        $this.ScopeId       = $ScopeId 
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
            $obj.Add([v4ScopeOption]::New($this.ScopeId, $scopeOption, $this.CimSession))
        }
        
        return $obj
    }
}

[SHiPSProvider(UseCache=$true)]
class v4ScopeOption : SHiPSLeaf
{
    [String] $VendorClass
    [String] $OptionId
    [String] $Name
    [object] $Value
    hidden [String] $ScopeId
    hidden [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null

    v4ScopeOption ([String] $ScopeId, [hashtable] $ScopeOption, [Microsoft.Management.Infrastructure.CimSession]$CimSession) :base("$($ScopeOption['OptionId']) $($ScopeOption['Name'])")
    {
        $this.ScopeId = $ScopeId
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
    hidden [String] $ScopeId
    hidden [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null
    
    Reservations ([String] $ScopeId, [Microsoft.Management.Infrastructure.CimSession]$CimSession) :base($this.GetType())
    {
        $this.ScopeId       = $ScopeId 
        $this.CimSession    = $CimSession
    }

    [Reservation[]] GetChildItem ()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        foreach ($reservation in $(Get-DhcpServerv4Reservation -ScopeId $this.ScopeId -CimSession $this.CimSession)) {
            $obj.Add([Reservation]::new($this.ScopeId, $reservation))
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

    Reservation ([String] $ScopeId, [Object] $InputObject) :base($InputObject.Name)
    {
        $this.ScopeId = $ScopeId
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
    hidden [String] $ScopeId
    hidden [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null

    
    AddressLeases ([String] $ScopeId, [Microsoft.Management.Infrastructure.CimSession]$CimSession) :base($this.GetType())
    {
        $this.ScopeId       = $ScopeId 
        $this.CimSession    = $CimSession
    }

    [AddressLease[]] GetChildItem ()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        foreach ($reservation in $(Get-DhcpServerv4Lease -ScopeId $this.ScopeId -CimSession $this.CimSession)) {
            $obj.Add([AddressLease]::new($this.ScopeId, $reservation))
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

    AddressLease ([String] $ScopeId, [Object] $InputObject) :base($InputObject.IPAddress)
    {
        $this.ScopeId = $ScopeId
        $this.ClientId = $InputObject.ClientId
        $this.Name = $InputObject.Name
        $this.Type = $InputObject.Type
        $this.IPAddress = $InputObject.IPAddress
        $this.AddressState = $InputObject.AddressState
        $this.Description = $InputObject.Description
    }
}

#endregion AddressLeases

#endregion IPv4 Scopes


#region IPv6 Scopes
[SHiPSProvider(UseCache=$true)]
class IPv6 : SHiPSDirectory
{
    [hashtable] $DNSSetting
    hidden [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null

    IPv6 ([Microsoft.Management.Infrastructure.CimSession]$CimSession) :base($this.GetType())
    {
        $this.CimSession    = $CimSession
        $this.DnsSetting = Get-DhcpServerv6DnsSetting -CimSession $this.CimSession -ErrorAction SilentlyContinue |
                            Convert-PSObjectToHashTable
    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        $v6Scopes = @(Get-DhcpServerv6Scope -CimSession $this.CimSession)
        foreach ($v6Scope in $v6Scopes)
        {
            $obj.Add([v6Scope]::new($v6Scope, $this.CimSession))
        }
        return $obj
    }

}

[SHiPSProvider(UseCache=$true)]
class v6Scope : SHiPSDirectory
{
    [String] $Name
    [String] $Prefix
    [String] $PrefixLength
    [String] $PreferredLifetime
    [String] $ValidLifeTime
    [hashtable] $DNSSetting
    hidden [Microsoft.Management.Infrastructure.CimSession]$CimSession = $null

    v6Scope([object] $InputObject, [Microsoft.Management.Infrastructure.CimSession]$CimSession) :base($InputObject.Name)
    {
        $this.Name              = $InputObject.Name
        $this.Prefix            = $InputObject.Prefix
        $this.PrefixLength      = $InputObject.PrefixLength
        $this.PreferredLifetime = $InputObject.PreferredLifetime
        $this.ValidLifeTime     = $InputObject.ValidLifeTime
        $this.CimSession        = $CimSession

        # Populate the DNS Settings hashtable
        $this.DNSSetting = Get-DhcpServerv6DnsSetting -CimSession $this.CimSession -Prefix $this.Prefix |
                                Convert-PSObjectToHashTable

    }

    [object[]] GetChildItem()
    {
        $obj = New-Object -TypeName System.Collections.ArrayList
        #$obj.Add([v6ScopeOptions]::new($this.ScopeId, $this.CimSession))
        #$obj.Add([v6Reservations]::new($this.ScopeId, $this.CimSession))
        #$obj.Add([v6AddressLeases]::new($this.ScopeId, $this.CimSession))
        return $obj
    }

    [Microsoft.Management.Infrastructure.CimInstance[]] DisplayStatistics ()
    {
        return $(Get-DhcpServerv6ScopeStatistics -CimSession $this.CimSession -Prefix $this.Prefix)
    }

}

#endregion IPv6 Scopes

#region cmdlets

function Get-CMSession {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ComputerName
    )
    if ($ComputerName)
    {
        [DhcpRoot]::Sessions | Where-Object {$_.ComputerName -eq $ComputerName}
    }
    else
    {
        [DhcpRoot]::Sessions
    }
    
}


function Connect-DHCPServer {
    <#
        .SYNOPSIS
            Allows to connect to a DHCP Server, the connected server then reflects inside the DhcpRoot
        .DESCRIPTION
            The function allows to connect to any DHCP Server (supports passing credentials), it uses CIM sessions in the backend.
        .EXAMPLE
            Connect-DHCPServer -ComputerName stg-dhcp01 -Credential (Get-Credential)
    #>
    [CmdletBinding()]
    param(
        # Specify the DHCP server to connect to
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
        if ([DhcpRoot]::Sessions)
        {
            ([DhcpRoot]::Sessions).Add((New-CimSession -ComputerName $ComputerName -Credential $Credential)) 
        }
        else
        {
            [DhcpRoot]::Sessions += New-CimSession -ComputerName $ComputerName -Credential $Credential
        }
        
    }
}


function Disconnect-DHCPServer {
        <#
        .SYNOPSIS
            Allows to disconnect from a DHCP Server, the disconnected server then is removed from inside the DhcpRoot.
        .DESCRIPTION
            The function allows to disconnect to the current connected DHCP Server, it simply removes the CIM session for the DHCP server.
        .EXAMPLE
            Disconnect-DHCPServer -ComputerName stg-dhcp01
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )
    $sessionToRemove = Get-DHCPSession -ComputerName $ComputerName

    if($sessionToRemove){
        if(([DhcpRoot]::Sessions).Remove($sessionToRemove)){
            Remove-CimSession -CimSession $sessionToRemove -ErrorAction Stop
        }
    }
    else{
        Write-Verbose -Verbose -Message "No connection to DHCP Server $ComputerName. Skipping ..."        
    }
}

Function Convert-PSObjectToHashTable {
    <#
        .SYNOPSIS
            Helper function to convert PSObjects to HAshtable
        .DESCRIPTION
            This function converts an input PSObject to a hashtable, it also
            allows specifying the properties to exclude during the conversion.
            It is used internally to map the PSDrive objects as Key-Value pairs for export.
        .EXAMPLE
            Convert-PSObjectToHashtable -InputObject (Get-Process -Name powershell) -Exlcude PID
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,
                    ValueFromPipeline = $true)]
        [AllowNull()]
        [object]$InputObject,

        [Parameter()]
        [String[]]$Exclude
    )
    Process
    {
        if ($InputObject)
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
}

Function Export-PSDrive {
    [CmdletBinding()]
    param(
        [Parameter()]
        [String] $Name,

        [Parameter()]
        [ValidateSet('JSON','CLIXML')]
        [String] $Type = 'JSON'
    )
    $PSDrive = Get-PSDriveAsPSObject -Name $Name -ErrorAction Stop

    Switch -Exact ($Type)
    {
        'JSON'
        {
            Add-Content -Path "$PSScriptRoot\$Name.json" -Value  ($PSDrive | ConvertTo-Json ) -Depth 99
            break
        }
        'CLIXML'
        {
            $PSDrive | Export-CLIXml -Depth 99 -Path "$PSScriptRoot\$Name.xml"
            break
        }
    }
}
Function Get-PSDriveAsPSObject {
    [CmdletBinding()]
    param(
        [Parameter()]
        [String] $Name
    )
    $PSDrive =  Get-PSDrive -Name $Name -ErrorAction SilentlyContinue
    if (-not $PSDrive)
    {
        throw "PSDrive with $name not found"
    }
    Push-Location
    $path = Resolve-Path -Path $("{0}:/" -f $Name)
    Set-Location -Path $Path
    Get-ShiPSItemAsPSObject -Path $path
    Pop-Location
}



function Get-ShiPSItemAsPSObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        [String] $Path,

        [Parameter()]
        [string[]] $Exclude = @()
    )
    process
    {
        try {
            $null = $Exclude.Add('ScopeId')
            $null = $Exclude.Add('CimSession')
        }
        catch {
        # swallow the error in above step
        }
        try 
        {
            
            $Path = Resolve-Path -Path $Path -ErrorAction Stop | Select-Object -ExpandProperty Path
        }
        catch 
        {
            Throw "$Path not resolvable. $PSitem.Exception"
        }
        $Item = Get-Item -Path $Path
        if ( $Item.PSIsContainer)
        {
            $psObject = [PSCustomObject]($Item | Convert-PSObjectToHashTable -Exclude $Exclude) # First capture all the item properties
            Add-Member -InputObject $psObject -MemberType NoteProperty -Name Type -Value "$($Item.GetType().FullName)" -ErrorAction SilentlyContinue
            $ChildItem = Get-ChildItem -Path $Path
            if ($ChildItem)
            {
                # Add the childitem member
                Add-Member -InputObject $psObject -MemberType NoteProperty -Name ChildItem -Value @()
                Foreach ($child in (Get-ChildItem -Path $Path))
                {
                    if ($child.PSIsContainer)
                    {
                        $childPath = if ($Path[-1] -eq "\") {"$Path$($child.PSChildName)"} else {"$Path\$($child.PSChildName)"}
                        $psObject.ChildItem += $(Get-ShiPSItemAsPSObject -Path $childPath -Exclude $Exclude)
                    }
                    else
                    {
                        $psObject.ChildItem += [PSCustomObject]($child | Convert-PSObjectToHashTable -Exclude $Exclude)
                    }
                }
            }
            
        }
        return $psObject
    }
}

#endregion cmdlets

Export-ModuleMember -Function 'Connect-DHCPServer','Disconnect-DHCPServer','Export-PSDrive','Get-CMSession'