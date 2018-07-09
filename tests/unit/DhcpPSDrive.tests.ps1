if(-not $ENV:BHProjectPath)
{
    Set-BuildEnvironment -Path $PSScriptRoot\..\..\DhcpPSDrive
}

Remove-Module $ENV:BHProjectName -ErrorAction SilentlyContinue
Import-Module (Join-Path $ENV:BHProjectPath $ENV:BHProjectName) -Force
Push-Location
try
{
    InModuleScope -ModuleName $ENV:BHProjectName -ScriptBlock {

        Describe "DhcpPSDrive" -Tag Unit {
            BeforeAll {
                New-PSDrive -Name DhcpServers -PSProvider SHiPS -Root 'DhcpPSDrive#DhcpRoot' -ErrorAction SilentlyContinue
                $DhcpPSDrive  = Get-PSDrive -Name DhcpServers -ErrorAction SilentlyContinue
            }

            AfterAll {
                Remove-PSDrive -Name DhcpServers -ErrorAction SilentlyContinue -Force
            }
            Context "Maps a PSDrive" {
    
                
                It "Should Map a PSDrive" {
                    $DhcpPSDrive | Should -Not -BeNullOrEmpty
    
                }
    
                It "Should have SHiPs as the Provider" {
                    $DhcpPSDrive.Provider | Should -Be 'Microsoft.PowerShell.SHiPS\SHiPS'
                }
    
                It "Should be able to set location to the PSDrive" {
                    {Set-Location -Path DhcpServers:\ } |
                        Should -Not -Throw
                }
    
                if (Get-Service -Name DhcpServer -ErrorAction SilentlyContinue) {
                    It "Should NOT be empty if the local machine is a Dhcp Server" {
                        Get-ChildItem -Path DhcpServers:\ -Force -ErrorAction SilentlyContinue|
                            Should -Not -BeNullOrEmpty
                    }
                }
                else {
                    It "Should be empty if local machine is not a DHCP server" {
                        Get-ChildItem -Path DhcpServers:\ -Force -ErrorAction SilentlyContinue |
                        Should -BeNullOrEmpty
                    }
                }
                
            }

            Context "Connect to a remote DHCP server" {
                Mock -CommandName Connect-DHCPServer -MockWith {
                    if (-not [DhcpRoot]::Sessions) {
                        [DhcpRoot]::Sessions += New-CimSession -ComputerName $env:COMPUTERNAME
                    }
                }
                
                Connect-DHCPServer -ComputerName dummyDHCPServer 
                $RemoteDhcpServer = Get-Item -Path "DhcpServers:\$env:COMPUTERNAME" 

                It "Should NOT be empty if the local machine is a Dhcp Server" {
                    Get-ChildItem -Path DhcpServers:\ -ErrorAction SilentlyContinue|
                        Should -Not -BeNullOrEmpty
                }

                It "Should map the DhcpServer as a SHiPS Directory" {
                    $RemoteDhcpServer.SSItemMode | Should -Be '+'
                    ($RemoteDhcpServer | Measure-Object).Count | Should -Be 1
                }

                It "Should connect to the remote machine using CIM" {
                    Assert-MockCalled -CommandName Connect-DHCPServer
                }
               
            }

            Context "Loads the Dhcp Server specific attributes when initialized" {
                Mock -CommandName Connect-DHCPServer -MockWith {
                    if (-not [DhcpRoot]::Sessions) {
                        [DhcpRoot]::Sessions += New-CimSession -ComputerName $env:COMPUTERNAME
                    }
                }
                Mock -CommandName Get-DhcpServerSetting -MockWith {$true} 
                Mock -CommandName Get-DhcpServerv4OptionValue -MockWith {[pscustomobject]@{Value='dummy'}} -ModuleName $ENV:BHProjectName -ParameterFilter { -not [string]::IsNullOrEmpty($CimSession)}
                Mock -CommandName Get-DhcpServerv4Binding -MockWith {[pscustomobject]@{key='ipv4'; value='Bind'}} -ModuleName $ENV:BHProjectName -ParameterFilter { -not [string]::IsNullOrEmpty($CimSession)}
                Mock -CommandName Get-DhcpServerv6Binding -MockWith {[pscustomobject]@{key='ipv6'; value='Bind'}} -ModuleName $ENV:BHProjectName -ParameterFilter { -not [string]::IsNullOrEmpty($CimSession)}

                
                $RemoteDhcpServer = [DhcpServer]::new($env:COMPUTERNAME)

                It "Should query the remote DHCP server to fetch V4 Option Values" {
                    Assert-MockCalled -CommandName Get-DhcpServerv4OptionValue -Times 6 -Exactly
                }

                It "Should set the returned value on the attributes for Option value" {
                    $RemoteDhcpServer.MsReleaseLease | Should -Be 'dummy'
                    $RemoteDhcpServer.TimeList | Should -Be 'dummy'
                    $RemoteDhcpServer.DnsList | Should -Be 'dummy'
                    $RemoteDhcpServer.DomainList | Should -Be 'dummy'
                    $RemoteDhcpServer.NtpList | Should -Be 'dummy'
                    $RemoteDhcpServer.UcTftpCallMgrList | Should -Be 'dummy'
                }

                It "Should query & populate IPv4 & IPv6 binding" {
                    Assert-MockCalled -CommandName Get-DhcpServerv4Binding -Times 1 -Exactly
                    Assert-MockCalled -CommandName Get-DhcpServerv6Binding -Times 1 -Exactly
                }
            }
        }
    }
}
catch
{
    $PSCmdlet.ThrowTerminatingError()
}
finally
{
    Pop-Location
    Remove-PSDrive -Name DhcpServers -Force -ErrorAction SilentlyContinue
    Get-CimSession | Remove-CimSession
}
