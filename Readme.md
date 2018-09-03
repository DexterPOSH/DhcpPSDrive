# DhcpPSDrive

The DhcpPSDrive provider allows easy navigation and discovery of a DHCP Server as a drive.
It is based on SHiPS provider and uses DHCP Server PowerShell module present locally to pull the information in current user context.

## Supported Platform

- PowerShell 5.1 (or later), which is shipped in Windows 10, Windows Server 2016, or [WMF 5.1][wmf51]

## Dependencies

[SHiPS](https://github.com/PowerShell/SHiPS) PowerShell module is required.

## Usage

- To start using the functionality of `DhcpPSDrive`, import the `DhcpPSDrive` module and create a PSDrive

    ```powershell
    Import-Module -Name DhcpPSDrive -Verbose
    New-PSDrive -Name DhcpServers -PSProvider SHiPS -Root DhcpPSDrive#DhcpRoot
    ```
    **By default the DhcpPSDrive will check if the localmachine is a DhcpServer and map it.**

- You will be then able to see the DhcpServer inside the PSDrive. Now navigate it as a PSDrive.
    ```powershell
    # Change location to the DhcpServers PSDrive and then list the child items
    PS C:\Windows\system32> Set-Location -Path DHCPServers:/

    

    ```

- Using `dir` or `ls`, you can traverse through the DHCP Server mapped as a Drive.

    ```powershell
    PS DHCPServers:\> Get-ChildItem

    Name      IPv4Address
    ----      -----------
    dhcp02
    PS DHCPServers:\> cd .\dhcp02\
    PS DHCPServers:\dhcp02> ls

        Directory: DHCPServers:\dhcp02

    Mode  Name
    ----  ----
    +     IPv4
    +     IPv6
    ```

- To connect to remote machines, use the `Connect-DHCPServer` command
    > Note: This command only  works from within the PSDrive created above

    ```powershell

    PS DHCPServers:\> Connect-DHCPServer -ComputerName dhcp01 -Credential (Get-Credential)
    PS DHCPServers:\> ls # Now since the PSDrive caches the connected DHCP servers, this does not reflect the new machine

    Name      IPv4Address
    ----      -----------
    dhcp02

    PS DHCPServers:\> ls -Force # Pass -Force switch to reflect the new machine connected

    Name       IPv4Address
    ----       -----------
    dhcp02
    dhcp01

    ```
- Use `Disconnect-DhcpServer` command to disconnect from the remote DHCP Server
    > Note: This command only works from within the PSDrive created above

## Installing DhcpPSDrive

- `git clone` https://github.com/DexterPOSH/DhcpPSDrive.git

## Developing and Contributing

Pull Requests are welcome or raise any issues.

## Legal and Licensing

DhcpPSDrive is under the [MIT license][license].

[license]: LICENSE