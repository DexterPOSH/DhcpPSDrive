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
                Mock -CommandName Connect-DHCPServer -MockWith {[DhcpRoot]::Sessions += New-CimSession -ComputerName $env:COMPUTERNAME}
                
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
