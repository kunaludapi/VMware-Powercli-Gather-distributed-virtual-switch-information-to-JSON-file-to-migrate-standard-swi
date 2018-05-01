#requires -version 4
<#
.SYNOPSIS
    Migrate VMs from DVSwitches to Standard Switches and vice versa.
.DESCRIPTION
    The Move-VMPortgroup cmdlets migrates VMs Network. This script is a part of earlier written script Copy-DvsPortGroupToSSwitch.
.PARAMETER vCenter
    Prompts you for vCenter server FQDN or IP address to connect, vc parameter is an alias, This value can be taken from pipline by property name.
.PARAMETER VirtualSwitch
    This ask for existing distributed virtual switch (dvswitch) or standard switch. Default value is SvSwitch100, if you have same Virtual standard swtich. VMs will be migrated to this portgroups on this virtual switch, it helps you to migrate VMs from VDSwitch to Standard swtich and vice versa
.PARAMETER XmlFile
    This is xml file I created earlier, It will migrate these VMs to given virtual switch.
.INPUTS
    VMware.VimAutomation.ViCore.Impl.V1.Inventory.ClusterImpl
    VMware.VimAutomation.Vds.Impl.V1.VmwareVDSwitchImpl
    VMware.VimAutomation.ViCore.Impl.V1.Host.Networking.VirtualPortGroupImpl
    VMware.VimAutomation.ViCore.Impl.V1.Host.Networking.VirtualSwitchImpl
.OUTPUTS
    VMware.VimAutomation.ViCore.Impl.V1.Host.Networking.VirtualPortGroupImpl
    VMware.VimAutomation.ViCore.Impl.V1.Host.Networking.VirtualSwitchImpl
.NOTES
  Version:        2.0
  Author:         Kunal Udapi
  Creation Date:  30 April 2018
  Purpose/Change: Part 1: VMware Powercli : Gather distributed virtual switch information to JSON file to migrate standard switch
  Useful URLs: http://vcloud-lab.com
.EXAMPLE
    PS C:\>.\Copy-DvsPortGroupToSSwitch.ps1 -vCenter vcsa65.vcloud-lab.com -Cluster Cluster01 -DVSwitch DVSwitch-NonProd-01

    This command connects vcenter 'vcsa65.vcloud-lab.com', copy/clone dvswitch portgroups from 'DVSwitch-NonProd-01' and create new vswitch and copied portgroups on all esxi host in the cluster name 'cluster01'
#>
[CmdletBinding(SupportsShouldProcess=$True,
    ConfirmImpact='Medium', 
    HelpURI='http://vcloud-lab.com', 
    SupportsTransactions=$True)]
Param (
    [parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, HelpMessage='Type vCenter server IP or FQDN you want to connect')]
    [alias('vc')]
    [String]$vCenter,
    [parameter(Position=2, ValueFromPipelineByPropertyName=$true, HelpMessage='Type valid virtual switch name')]
    [alias('Switch')]
    [String]$VirtualSwitch = 'SvSwitch100',
    [parameter(Position=3, Mandatory=$true, ValueFromPipelineByPropertyName=$true, HelpMessage='Type valid virtual switch name')]
    [alias('File')]
    [String]$XmlFile
)

Begin {
    if (Test-Path -Path $XmlFile) {
        $XmlFile = Import-Clixml $XmlFile
    }
    else {
        Write-Host "Provided XML file $XmlFile is not valid" -BackgroundColor DarkRed
        break
    }
    
    try {
        if (!(Import-Module vmware.vimautomation.Core) -and !(Import-Module vmware.vimautomation.vds)) {
            Import-Module VMware.VimAutomation.Core -ErrorAction SilentlyContinue
            Import-Module vmware.vimautomation.vds -ErrorAction SilentlyContinue
        }
        else {
            Write-Host 'Download and install PowerCLI version 6.5 and above' -BackgroundColor DarkRed
        }
        Connect-viserver $vCenter -ErrorAction Stop
    }
    catch {
        Write-Host $Error[0].Exception.Message -BackgroundColor DarkRed
        break
    }
}
Process {
    #$VirtualSwitch = 'DVSwitch-NonProd-01' # 'SvSwitch100' # 
    foreach ($esxiVms in $XmlFile) {
        $VMNetwork = $esxiVms.VMNetwork
        $VMHost = Get-VMHost $esxiVms.EsxiHost
        $VMHostname = $Vmhost.name
        if ($VMHost.ConnectionState -ne 'Connected') {
            "$VMHostname is $($VMHost.ConnectionState), Cannot continue on this host"
        }
        else {
            $SvSwitch100 = $VMHost | Get-VirtualSwitch -Name $VirtualSwitch
            $GroupdVMs = $esxiVms.VMNetwork | Group-Object PortGroupName
            foreach ($PortGroups in $GroupdVMs) {
                Write-Host "$([char]8734) " -ForegroundColor Yellow -NoNewline
                Write-Host "Migrating '$VMHostname' VMs from portGroup '$($PortGroups.Name)'" -BackgroundColor Yellow -ForegroundColor Black
                foreach ($VM in $PortGroups.Group) {
                    $VMNicAdapter = $VMHost | Get-VM -Name $VM.VMName | Get-NetworkAdapter -Name $VM.AdapterName 
                    $SSwitchPortGroup = $SvSwitch100 | Get-VirtualPortGroup -Name $VM.PortGroupName
                    try {
                        $SetNicAdapter = $VMNicAdapter | Set-NetworkAdapter -Portgroup $SSwitchPortGroup -Confirm:$false -ErrorAction Stop 
                        Write-Host "`t $([char]8730) " -ForegroundColor Green -NoNewline
                        Write-Host "`tMigrated VM '$($SetNicAdapter.Parent)' Nic '$($SetNicAdapter.Name)' to portGroup '$($PortGroups.Name)' on vSwitch '$($SSwitchPortGroup.VirtualSwitch)'"                
                    }
                    catch {
                        Write-Host "`t $([char]215) " -ForegroundColor DarkRed -NoNewline
                        Write-Host "`tMigrated VM '$($SetNicAdapter.Parent)' Nic '$($SetNicAdapter.Name)' to portGroup '$($PortGroups.Name)' on vSwitch '$($SSwitchPortGroup.VirtualSwitch)'"                
                    }
                }
            }
        }
    }
}
end {
    Disconnect-VIServer * -Confirm:$false -ErrorAction SilentlyContinue
}