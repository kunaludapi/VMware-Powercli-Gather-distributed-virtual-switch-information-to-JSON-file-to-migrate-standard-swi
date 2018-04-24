#requires -version 4
<#
.SYNOPSIS
    Collects vDSwitch (Distributed virtual switch) portgroups, Virtual machines and Physical Port infromation for migration.
.DESCRIPTION
    The Get-VDswitchInfo Collects existing virtual distributed switch information, This script is written for one dvswitch in a cluster, and 2 nics per esxi server. Here it collects info about EsxiHost, DVSwitch Physical Adapters, VMKernel adapters, Virtual Machine Network. This is information is useful in my next script when migrating from DvSwitch to Standard switch.
.PARAMETER vCenter
    Prompts you for vCenter server FQDN or IP address to connect, vc parameter is an alias, This value can be taken from pipline by property name. 
.PARAMETER Cluster
    Make sure you type a valid ClusterName within the provided vCenter server. This script collect information from this Cluster and host.
.PARAMETER DVSwitch
    This ask for existing distributed virtual switch (dvswitch) in the cluster.
.PARAMETER JsonFile
    Collected information is stored in JSON file, provide a path for json ie: c:\temp\vdinfo.json 
.INPUTS
    VMware.VimAutomation.ViCore.Impl.V1.Inventory.ClusterImpl
    VMware.VimAutomation.Vds.Impl.V1.VmwareVDSwitchImpl
    VMware.VimAutomation.ViCore.Impl.V1.Host.Networking.VirtualPortGroupImpl
    VMware.VimAutomation.ViCore.Impl.V1.Host.Networking.VirtualSwitchImpl
.OUTPUTS
    VMware.VimAutomation.ViCore.Impl.V1.Host.Networking.VirtualPortGroupImpl
    VMware.VimAutomation.ViCore.Impl.V1.Host.Networking.VirtualSwitchImpl
.NOTES
  Version:        1.0
  Author:         Kunal Udapi
  Creation Date:  12 August 2017
  Purpose/Change: Collect dvswitch information to json file for DVswtich to SSwitch migration
  Useful URLs:    http://vcloud-lab.com/entries/powercli/copy-or-clone-distributed-virtual-switch-portgroups-to-standard-switch-portgroups-powercli
  OS Version:     Windows 10 pro version 1703, Build 15063.726
  Powershell:     5.1.15063.726  Desktop Edition
  Powercli:       VMware PowerCLI 6.5 Release 1 build 4624819
                  VMware VimAutomation Core PowerCLI Component 6.5 build 4624450
                  VMware Vds PowerCLI Component 6.5 build 4624695

.EXAMPLE
    PS C:\>.\Get-VDswitchInfo.ps1 -vCenter vcsa65.vcloud-lab.com -Cluster Cluster01 -VDSwitch DVSwitch-NonProd-01 -JsonFile c:\temp\dvswitchInfo.json

    This command connects vcenter 'vcsa65.vcloud-lab.com',  infCollectormation from 'DVSwitch-NonProd-01' and Cluster 'Cluster01' its esxi host, keep the information in c:\temp\dvswitchInfo.json file.
#>

[CmdletBinding(SupportsShouldProcess=$True,
    ConfirmImpact='Medium', 
    HelpURI='http://vcloud-lab.com', 
    SupportsTransactions=$True)]
Param (
    [parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, HelpMessage='Type vCenter server IP or FQDN you want to connect')]
    [alias('vc')]
    [String]$vCenter,
    [parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true, HelpMessage='Type valid Cluster Name within vCenter server')]
    [alias('c')]
    [String]$Cluster,
    [parameter(Position=2, Mandatory=$true, ValueFromPipelineByPropertyName=$true, HelpMessage='Type valid distributed virtual switch (dvswitch) name')]
    [alias('vds')]
    [String]$VDSwitch,
    [parameter(Position=3, Mandatory=$true, ValueFromPipelineByPropertyName=$true, HelpMessage='Type valid distributed virtual switch (dvswitch) name')]
    [alias('File')]
    [String]$JsonFile
)
Begin {
    if ( -not (Get-Module  vmware.vimautomation.core)) {
        Import-Module vmware.vimautomation.core
        Import-Module vmware.vimautomation.vds
    }

    if ($global:DefaultVIServers.Name -notcontains $vCenter) {
        try {
            Connect-VIServer $vCenter -ErrorAction Stop
        }
        catch {
            Write-Host $($Error[0].Exception) -ForegroundColor Red
            break
        }
    }

    $OverAllInfo = @()
} #Begin
Process {
    try {
        $ClusterInfo = Get-Cluster $Cluster -ErrorAction Stop
        $DvSwitchInfo = Get-VDSwitch -Name $VDSwitch -ErrorAction Stop
    }
    catch {
        Write-Host $($Error[0].Exception) -ForegroundColor Red
        break
    }

    $EsxiHosts = $ClusterInfo | Get-VMHost | Sort-Object Name
    foreach ($ESXi in $EsxiHosts) {
        $ESXiHostName = $ESXi.Name
        Write-Host "Collecting information from $ESXiHostName ..." -ForegroundColor Green
        try {
            $DistributedSwitch = $ESXi | Get-VDSwitch -Name $VDSwitch
        }
        catch {
            Write-Host $($Error[0].Exception) -ForegroundColor Red
            Continue
        }
        $vDSwitchName = $DistributedSwitch.Name

        $UplinkPortGroups = $DistributedSwitch | Get-VDPort -Uplink | Where-Object {$_.ProxyHost.Name -eq $ESXiHostName} | Sort-Object Name
        $PhysicalAdapters = $DistributedSwitch | Get-VMHostNetworkAdapter -Physical | Where-Object {$_.VMHost.Name -eq $ESXiHostName} | Sort-Object Name
        $VMKernelAdapters = $DistributedSwitch | Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.VMHost.Name -eq $ESXiHostName} | Sort-Object Name
        $VDPortGroup = $DistributedSwitch | Get-VDPortgroup 
        #$UPLinks = $VDPortGroup | Where-Object {$_.IsUplink -eq $true}
        
        if ($PhysicalAdapters.Count -lt 2) {
            Write-Host "No network redundancy found on server $ESXiHostName, do no proceed until you have 2 Nic cards..." -ForegroundColor Red
        } #if ($PhysicalAdapters.Count -lt 2)

        $PNicInfo = $UplinkPortGroups | Select-Object Name, ConnectedEntity, Switch, ProxyHost
    
        $CompleteVMKInfo = @()
        $VMKArray = @('Management', 'vMotion')
        foreach ($VMK in $VMKArray) {
            switch ($VMK) { 
                Management {
                    $SpecificVMK = $VMKernelAdapters | Where-Object {$_.ManagementTrafficEnabled -eq $true}
                } #Management {
                vMotion {
                    $SpecificVMK = $VMKernelAdapters | Where-Object {$_.VMotionEnabled -eq $true}
                } #vMotion
            } #switch ($VMK) {
        
            $VMKPortGroup = $VDPortGroup | Where-Object {$_.Name -eq $SpecificVMK.PortGroupName}
            $VMKVLanId = $VMKPortGroup.VlanConfiguration.VlanId
            $VMKInfo = [PSCustomObject]@{
                Name = $SpecificVMK.Name
                IP = $SpecificVMK.IP
                SubnetMask = $SpecificVMK.SubnetMask
                VLANId = $VMKVLanId
            } #$ManagementVMKInfo = [PSCustomObject]@{  
            $CompleteVMKInfo += $VMKInfo
        } #foreach ($VMK in $VMKArray) {
    
        $CompleteVMNetInfo = @()
        $VirtualMachines = $ESXi | Get-VM 
        foreach ($VM in $VirtualMachines) {
            $VMNetAdapters = $VM | Get-NetworkAdapter 

            foreach ($VMNet in $VMNetAdapters) {
                if ($VMNet.ExtensionData.DeviceInfo.Summary -match 'DVSwitch') {
                    $VMNetworks = [PSCustomObject]@{
                        VMName = $VM.Name
                        AdapterName = $VMNet.Name
                        PortGroupName = $VMNet.NetworkName
                        EsxiName = $VM.VMhost
                    } #$VMNetworks = [PSCustomObject]@{
                }  #if ($VMNet.ExtensionData.DeviceInfo.Summary -match 'DVSwitch') {
            $CompleteVMNetInfo += $VMNetworks
            } #foreach ($VMNet in $VMNetAdapters) {
        } #foreach ($vm in $VirtualMachines) {
    
        $MainObj = New-Object psobject
        $MainObj | Add-Member -Name EsxiHost -MemberType NoteProperty -Value $ESXi.Name
        $MainObj | Add-Member -Name ConnectionState -MemberType NoteProperty -Value $ESXi.ConnectionState
        $MainObj | Add-Member -Name PowerState -MemberType NoteProperty -Value $ESXi.PowerState
        $MainObj | Add-Member -Name PhysicalNics -MemberType NoteProperty -Value $PNicInfo
        $MainObj | Add-Member -Name VMKernels -MemberType NoteProperty -Value $CompleteVMKInfo
        $MainObj | Add-Member -Name VMNetwork -MemberType NoteProperty -Value $CompleteVMNetInfo
        $OverAllInfo += $MainObj
    }#foreach ($ESXi in $EsxiHosts) {
} #Process
End {#requires -version 4
<#
.SYNOPSIS
    Collects vDSwitch (Distributed virtual switch) portgroups, Virtual machines and Physical Port infromation for migration.
.DESCRIPTION
    The Get-VDswitchInfo Collects existing virtual distributed switch information, This script is written for one dvswitch in a cluster, and 2 nics per esxi server. Here it collects info about EsxiHost, DVSwitch Physical Adapters, VMKernel adapters, Virtual Machine Network. This is information is useful in my next script when migrating from DvSwitch to Standard switch.
.PARAMETER vCenter
    Prompts you for vCenter server FQDN or IP address to connect, vc parameter is an alias, This value can be taken from pipline by property name. 
.PARAMETER Cluster
    Make sure you type a valid ClusterName within the provided vCenter server. This script collect information from this Cluster and host.
.PARAMETER DVSwitch
    This ask for existing distributed virtual switch (dvswitch) in the cluster.
.PARAMETER JsonFile
    Collected information is stored in JSON file, provide a path for json ie: c:\temp\vdinfo.json 
.INPUTS
    VMware.VimAutomation.ViCore.Impl.V1.Inventory.ClusterImpl
    VMware.VimAutomation.Vds.Impl.V1.VmwareVDSwitchImpl
    VMware.VimAutomation.ViCore.Impl.V1.Host.Networking.VirtualPortGroupImpl
    VMware.VimAutomation.ViCore.Impl.V1.Host.Networking.VirtualSwitchImpl
.OUTPUTS
    VMware.VimAutomation.ViCore.Impl.V1.Host.Networking.VirtualPortGroupImpl
    VMware.VimAutomation.ViCore.Impl.V1.Host.Networking.VirtualSwitchImpl
.NOTES
  Version:        1.0
  Author:         Kunal Udapi
  Creation Date:  12 August 2017
  Purpose/Change: Collect dvswitch information to json file for DVswtich to SSwitch migration
  Useful URLs:    http://vcloud-lab.com/entries/powercli/copy-or-clone-distributed-virtual-switch-portgroups-to-standard-switch-portgroups-powercli
  OS Version:     Windows 10 pro version 1703, Build 15063.726
  Powershell:     5.1.15063.726  Desktop Edition
  Powercli:       VMware PowerCLI 6.5 Release 1 build 4624819
                  VMware VimAutomation Core PowerCLI Component 6.5 build 4624450
                  VMware Vds PowerCLI Component 6.5 build 4624695

.EXAMPLE
    PS C:\>.\Get-VDswitchInfo.ps1 -vCenter vcsa65.vcloud-lab.com -Cluster Cluster01 -VDSwitch DVSwitch-NonProd-01 -JsonFile c:\temp\dvswitchInfo.json

    This command connects vcenter 'vcsa65.vcloud-lab.com',  infCollectormation from 'DVSwitch-NonProd-01' and Cluster 'Cluster01' its esxi host, keep the information in c:\temp\dvswitchInfo.json file.
#>

[CmdletBinding(SupportsShouldProcess=$True,
    ConfirmImpact='Medium', 
    HelpURI='http://vcloud-lab.com', 
    SupportsTransactions=$True)]
Param (
    [parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, HelpMessage='Type vCenter server IP or FQDN you want to connect')]
    [alias('vc')]
    [String]$vCenter,
    [parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true, HelpMessage='Type valid Cluster Name within vCenter server')]
    [alias('c')]
    [String]$Cluster,
    [parameter(Position=2, Mandatory=$true, ValueFromPipelineByPropertyName=$true, HelpMessage='Type valid distributed virtual switch (dvswitch) name')]
    [alias('vds')]
    [String]$VDSwitch,
    [parameter(Position=3, Mandatory=$true, ValueFromPipelineByPropertyName=$true, HelpMessage='Type valid distributed virtual switch (dvswitch) name')]
    [alias('File')]
    [String]$JsonFile
)
Begin {
    if ( -not (Get-Module  vmware.vimautomation.core)) {
        Import-Module vmware.vimautomation.core
        Import-Module vmware.vimautomation.vds
    }

    if ($global:DefaultVIServers.Name -notcontains $vCenter) {
        try {
            Connect-VIServer $vCenter -ErrorAction Stop
        }
        catch {
            Write-Host $($Error[0].Exception) -ForegroundColor Red
            break
        }
    }

    $OverAllInfo = @()
} #Begin
Process {
    try {
        $ClusterInfo = Get-Cluster $Cluster -ErrorAction Stop
        $DvSwitchInfo = Get-VDSwitch -Name $VDSwitch -ErrorAction Stop
    }
    catch {
        Write-Host $($Error[0].Exception) -ForegroundColor Red
        break
    }

    $EsxiHosts = $ClusterInfo | Get-VMHost | Sort-Object Name
    foreach ($ESXi in $EsxiHosts) {
        $ESXiHostName = $ESXi.Name
        Write-Host "Collecting information from $ESXiHostName ..." -ForegroundColor Green
        try {
            $DistributedSwitch = $ESXi | Get-VDSwitch -Name $VDSwitch
        }
        catch {
            Write-Host $($Error[0].Exception) -ForegroundColor Red
            Continue
        }
        $vDSwitchName = $DistributedSwitch.Name

        $UplinkPortGroups = $DistributedSwitch | Get-VDPort -Uplink | Where-Object {$_.ProxyHost.Name -eq $ESXiHostName} | Sort-Object Name
        $PhysicalAdapters = $DistributedSwitch | Get-VMHostNetworkAdapter -Physical | Where-Object {$_.VMHost.Name -eq $ESXiHostName} | Sort-Object Name
        $VMKernelAdapters = $DistributedSwitch | Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.VMHost.Name -eq $ESXiHostName} | Sort-Object Name
        $VDPortGroup = $DistributedSwitch | Get-VDPortgroup 
        #$UPLinks = $VDPortGroup | Where-Object {$_.IsUplink -eq $true}
        
        if ($PhysicalAdapters.Count -lt 2) {
            Write-Host "No network redundancy found on server $ESXiHostName, do no proceed until you have 2 Nic cards..." -ForegroundColor Red
        } #if ($PhysicalAdapters.Count -lt 2)

        $PNicInfo = $UplinkPortGroups | Select-Object Name, ConnectedEntity, Switch, ProxyHost
    
        $CompleteVMKInfo = @()
        $VMKArray = @('Management', 'vMotion')
        foreach ($VMK in $VMKArray) {
            switch ($VMK) { 
                Management {
                    $SpecificVMK = $VMKernelAdapters | Where-Object {$_.ManagementTrafficEnabled -eq $true}
                } #Management {
                vMotion {
                    $SpecificVMK = $VMKernelAdapters | Where-Object {$_.VMotionEnabled -eq $true}
                } #vMotion
            } #switch ($VMK) {
        
            $VMKPortGroup = $VDPortGroup | Where-Object {$_.Name -eq $SpecificVMK.PortGroupName}
            $VMKVLanId = $VMKPortGroup.VlanConfiguration.VlanId
            $VMKInfo = [PSCustomObject]@{
                Name = $SpecificVMK.Name
                IP = $SpecificVMK.IP
                SubnetMask = $SpecificVMK.SubnetMask
                VLANId = $VMKVLanId
            } #$ManagementVMKInfo = [PSCustomObject]@{  
            $CompleteVMKInfo += $VMKInfo
        } #foreach ($VMK in $VMKArray) {
    
        $CompleteVMNetInfo = @()
        $VirtualMachines = $ESXi | Get-VM 
        foreach ($VM in $VirtualMachines) {
            $VMNetAdapters = $VM | Get-NetworkAdapter 

            foreach ($VMNet in $VMNetAdapters) {
                if ($VMNet.ExtensionData.DeviceInfo.Summary -match 'DVSwitch') {
                    $VMNetworks = [PSCustomObject]@{
                        VMName = $VM.Name
                        AdapterName = $VMNet.Name
                        PortGroupName = $VMNet.NetworkName
                        EsxiName = $VM.VMhost
                    } #$VMNetworks = [PSCustomObject]@{
                }  #if ($VMNet.ExtensionData.DeviceInfo.Summary -match 'DVSwitch') {
            $CompleteVMNetInfo += $VMNetworks
            } #foreach ($VMNet in $VMNetAdapters) {
        } #foreach ($vm in $VirtualMachines) {
    
        $MainObj = New-Object psobject
        $MainObj | Add-Member -Name EsxiHost -MemberType NoteProperty -Value $ESXi.Name
        $MainObj | Add-Member -Name ConnectionState -MemberType NoteProperty -Value $ESXi.ConnectionState
        $MainObj | Add-Member -Name PowerState -MemberType NoteProperty -Value $ESXi.PowerState
        $MainObj | Add-Member -Name PhysicalNics -MemberType NoteProperty -Value $PNicInfo
        $MainObj | Add-Member -Name VMKernels -MemberType NoteProperty -Value $CompleteVMKInfo
        $MainObj | Add-Member -Name VMNetwork -MemberType NoteProperty -Value $CompleteVMNetInfo
        $OverAllInfo += $MainObj
    }#foreach ($ESXi in $EsxiHosts) {
} #Process
End {$XmlFile = $JsonFile -Replace 'json', 'xml'; $OverAllInfo | Export-CliXml -Path $JsonFile
    $OverAllInfo | ConvertTo-Json | Out-File -FilePath $JsonFile 
} #End
    $OverAllInfo | ConvertTo-Json | Out-File -FilePath $JsonFile
} #End
