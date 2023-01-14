#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2022-02-28 15:16:37
# @Author  : Your Name (you@example.org)
# @Link    : http://example.org
# @Version : $Id$

import re

from random import shuffle, randint, choice


def Remove_Comments(ps1Content):
	SLCPattern = '\#(.*?)\n'
	MLCPattern = '<#([\s\S]*?)#>'

	for i in re.findall(MLCPattern, ps1Content):
		ps1Content = ps1Content.replace('<#' + i + '#>', '')

	for i in re.findall(SLCPattern, ps1Content):
		if i == ' ' or i == '':
			continue
		ps1Content = ps1Content.replace('#' + i, '')
	
	return ps1Content


def Resolve_Aliases(ps1Content):

	stripPs1Content = stripQMark(ps1Content)

	AliasList = {'ac': 'Add-Content', 'asnp': 'Add-PSSnapin', 'cat': 'Get-Content', 'compare': 'Compare-Object', 'cd': 'Set-Location', 'CFS': 'ConvertFrom-String', 'chdir': 'Set-Location', 'clc': 'Clear-Content', 'clear': 'Clear-Host', 'clhy': 'Clear-History', 'cli': 'Clear-Item', 'clp': 'Clear-ItemProperty', 'cls': 'Clear-Host', 'clv': 'Clear-Variable', 'cnsn': 'Connect-PSSession', 'copy': 'Copy-Item', 'cp': 'Copy-Item', 'cpi': 'Copy-Item', 'cpp': 'Copy-ItemProperty', 'curl': 'Invoke-WebRequest', 'cvpa': 'Convert-Path', 'dbp': 'Disable-PSBreakpoint', 'del': 'Remove-Item', 'diff': 'Compare-Object', 'dir': 'Get-ChildItem', 'dnsn': 'Disconnect-PSSession', 'ebp': 'Enable-PSBreakpoint', 'epal': 'Export-Alias', 'epcsv': 'Export-Csv', 'epsn': 'Export-PSSession', 'erase': 'Remove-Item', 'etsn': 'Enter-PSSession', 'exsn': 'Exit-PSSession', 'fc': 'Format-Custom', 'fhx': 'Format-Hex', 'fl': 'Format-List', 'ft': 'Format-Table', 'fw': 'Format-Wide', 'gal': 'Get-Alias', 'gbp': 'Get-PSBreakpoint', 'gc': 'Get-Content', 'gcb': 'Get-Clipboard', 'gci': 'Get-ChildItem', 'gcm': 'Get-Command', 'gcs': 'Get-PSCallStack', 'gdr': 'Get-PSDrive', 'ghy': 'Get-History', 'gin': 'Get-ComputerInfo', 'gjb': 'Get-Job', 'gl': 'Get-Location', 'gm': 'Get-Member', 'gmo': 'Get-Module', 'gps': 'Get-Process', 'group': 'Group-Object', 'gsn': 'Get-PSSession', 'gsnp': 'Get-PSSnapin', 'gsv': 'Get-Service', 'gtz': 'Get-TimeZone', 'gu': 'Get-Unique', 'gv': 'Get-Variable', 'gwmi': 'Get-WmiObject', 'h': 'Get-History', 'history': 'Get-History', 'icm': 'Invoke-Command', 'iex': 'Invoke-Expression', 'ihy': 'Invoke-History', 'ii': 'Invoke-Item', 'ipal': 'Import-Alias', 'ipcsv': 'Import-Csv', 'ipmo': 'Import-Module', 'ipsn': 'Import-PSSession', 'irm': 'Invoke-RestMethod', 'ise': 'powershell_ise.exe', 'iwmi': 'Invoke-WmiMethod', 'iwr': 'Invoke-WebRequest', 'kill': 'Stop-Process', 'lp': 'Out-Printer', 'ls': 'Get-ChildItem', 'man': 'help', 'md': 'mkdir', 'measure': 'Measure-Object', 'mi': 'Move-Item', 'mount': 'New-PSDrive', 'move': 'Move-Item', 'mp': 'Move-ItemProperty', 'mv': 'Move-Item', 'nal': 'New-Alias', 'ndr': 'New-PSDrive', 'ni': 'New-Item', 'nmo': 'New-Module', 'npssc': 'New-PSSessionConfigurationFile', 'nsn': 'New-PSSession', 'nv': 'New-Variable', 'ogv': 'Out-GridView', 'oh': 'Out-Host', 'popd': 'Pop-Location', 'ps': 'Get-Process', 'pushd': 'Push-Location', 'pwd': 'Get-Location', 'rbp': 'Remove-PSBreakpoint', 'rcjb': 'Receive-Job', 'rcsn': 'Receive-PSSession', 'rd': 'Remove-Item', 'rdr': 'Remove-PSDrive', 'ren': 'Rename-Item', 'ri': 'Remove-Item', 'rjb': 'Remove-Job', 'rm': 'Remove-Item', 'rmdir': 'Remove-Item', 'rmo': 'Remove-Module', 'rni': 'Rename-Item', 'rnp': 'Rename-ItemProperty', 'rp': 'Remove-ItemProperty', 'rsn': 'Remove-PSSession', 'rsnp': 'Remove-PSSnapin', 'rujb': 'Resume-Job', 'rv': 'Remove-Variable', 'rvpa': 'Resolve-Path', 'rwmi': 'Remove-WmiObject', 'sajb': 'Start-Job', 'sal': 'Set-Alias', 'saps': 'Start-Process', 'sasv': 'Start-Service', 'sbp': 'Set-PSBreakpoint', 'sc': 'Set-Content', 'scb': 'Set-Clipboard', 'select': 'Select-Object', 'set': 'Set-Variable', 'shcm': 'Show-Command', 'si': 'Set-Item', 'sl': 'Set-Location', 'sleep': 'Start-Sleep', 'sls': 'Select-String', 'sort': 'Sort-Object', 'sp': 'Set-ItemProperty', 'spjb': 'Stop-Job', 'spps': 'Stop-Process', 'spsv': 'Stop-Service', 'stz': 'Set-TimeZone', 'sujb': 'Suspend-Job', 'sv': 'Set-Variable', 'swmi': 'Set-WmiInstance', 'tee': 'Tee-Object', 'trcm': 'Trace-Command', 'type': 'Get-Content', 'wget': 'Invoke-WebRequest', 'where': 'Where-Object', 'wjb': 'Wait-Job', 'write': 'Write-Output'}

	for i in AliasList.keys():
		pat = '[ \n](' + i + ') [^=]'
		data = re.findall(pat, stripPs1Content, re.I)
		for j in set(data):
			# print('\t' + i + '  =>  ' + AliasList[i])
			ps1Content = ps1Content.replace(i, AliasList[i])

	return ps1Content


def ObfCmdLet(cmdlet):

	charray = list('-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
	shuffle(charray)
	newCharray = ''.join(charray)
	obfList = []

	for i in cmdlet:
		if i in newCharray:
			obfList.append(newCharray.index(i))

	return '& (("' + newCharray + '")' + str(obfList).replace(' ', '') + ' -join "")'



def Find_cmdLet(ps1Content):

	cmdLetList = ['Add-AppPackage', 'Add-AppPackageVolume', 'Add-AppProvisionedPackage', 'Add-ProvisionedAppPackage', 'Add-ProvisionedAppxPackage', 'Add-ProvisioningPackage', 'Add-TrustedProvisioningCertificate', 'Apply-WindowsUnattend', 'Disable-PhysicalDiskIndication', 'Disable-StorageDiagnosticLog', 'Dismount-AppPackageVolume', 'Enable-PhysicalDiskIndication', 'Enable-StorageDiagnosticLog', 'Flush-Volume', 'Get-AppPackage', 'Get-AppPackageDefaultVolume', 'Get-AppPackageLastError', 'Get-AppPackageLog', 'Get-AppPackageManifest', 'Get-AppPackageVolume', 'Get-AppProvisionedPackage', 'Get-DiskSNV', 'Get-PhysicalDiskSNV', 'Get-ProvisionedAppPackage', 'Get-ProvisionedAppxPackage', 'Get-StorageEnclosureSNV', 'Initialize-Volume', 'Mount-AppPackageVolume', 'Move-AppPackage', 'Move-SmbClient', 'Optimize-AppProvisionedPackages', 'Optimize-ProvisionedAppPackages', 'Optimize-ProvisionedAppxPackages', 'Remove-AppPackage', 'Remove-AppPackageVolume', 'Remove-AppProvisionedPackage', 'Remove-EtwTraceSession', 'Remove-ProvisionedAppPackage', 'Remove-ProvisionedAppxPackage', 'Remove-ProvisioningPackage', 'Remove-TrustedProvisioningCertificate', 'Set-AppPackageDefaultVolume', 'Set-AppPackageProvisionedDataFile', 'Set-AutologgerConfig', 'Set-EtwTraceSession', 'Set-ProvisionedAppPackageDataFile', 'Set-ProvisionedAppXDataFile', 'Write-FileSystemCache', 'Add-BCDataCacheExtension', 'Add-BitLockerKeyProtector', 'Add-DnsClientNrptRule', 'Add-DtcClusterTMMapping', 'Add-EtwTraceProvider', 'Add-InitiatorIdToMaskingSet', 'Add-MpPreference', 'Add-MpPreference', 'Add-NetEventNetworkAdapter', 'Add-NetEventPacketCaptureProvider', 'Add-NetEventProvider', 'Add-NetEventVFPProvider', 'Add-NetEventVmNetworkAdapter', 'Add-NetEventVmSwitch', 'Add-NetEventVmSwitchProvider', 'Add-NetEventWFPCaptureProvider', 'Add-NetIPHttpsCertBinding', 'Add-NetLbfoTeamMember', 'Add-NetLbfoTeamNic', 'Add-NetNatExternalAddress', 'Add-NetNatStaticMapping', 'Add-NetSwitchTeamMember', 'Add-OdbcDsn', 'Add-PartitionAccessPath', 'Add-PhysicalDisk', 'Add-Printer', 'Add-PrinterDriver', 'Add-PrinterPort', 'Add-StorageFaultDomain', 'Add-TargetPortToMaskingSet', 'Add-VirtualDiskToMaskingSet', 'Add-VpnConnection', 'Add-VpnConnectionRoute', 'Add-VpnConnectionTriggerApplication', 'Add-VpnConnectionTriggerDnsConfiguration', 'Add-VpnConnectionTriggerTrustedNetwork', 'Assert-MockCalled', 'Assert-VerifiableMocks', 'Backup-BitLockerKeyProtector', 'BackupToAAD-BitLockerKeyProtector', 'Block-FileShareAccess', 'Block-SmbShareAccess', 'Clear-AssignedAccess', 'Clear-BCCache', 'Clear-BitLockerAutoUnlock', 'Clear-Disk', 'Clear-DnsClientCache', 'Clear-FileStorageTier', 'Clear-Host', 'Clear-PcsvDeviceLog', 'Clear-StorageBusDisk', 'Clear-StorageDiagnosticInfo', 'Close-SmbOpenFile', 'Close-SmbSession', 'Compress-Archive', 'Connect-IscsiTarget', 'Connect-VirtualDisk', 'ConvertFrom-SddlString', 'Copy-NetFirewallRule', 'Copy-NetIPsecMainModeCryptoSet', 'Copy-NetIPsecMainModeRule', 'Copy-NetIPsecPhase1AuthSet', 'Copy-NetIPsecPhase2AuthSet', 'Copy-NetIPsecQuickModeCryptoSet', 'Copy-NetIPsecRule', 'Debug-FileShare', 'Debug-MMAppPrelaunch', 'Debug-StorageSubSystem', 'Debug-Volume', 'Disable-BC', 'Disable-BCDowngrading', 'Disable-BCServeOnBattery', 'Disable-BitLocker', 'Disable-BitLockerAutoUnlock', 'Disable-DAManualEntryPointSelection', 'Disable-DscDebug', 'Disable-MMAgent', 'Disable-NetAdapter', 'Disable-NetAdapterBinding', 'Disable-NetAdapterChecksumOffload', 'Disable-NetAdapterEncapsulatedPacketTaskOffload', 'Disable-NetAdapterIPsecOffload', 'Disable-NetAdapterLso', 'Disable-NetAdapterPacketDirect', 'Disable-NetAdapterPowerManagement', 'Disable-NetAdapterQos', 'Disable-NetAdapterRdma', 'Disable-NetAdapterRsc', 'Disable-NetAdapterRss', 'Disable-NetAdapterSriov', 'Disable-NetAdapterUso', 'Disable-NetAdapterVmq', 'Disable-NetDnsTransitionConfiguration', 'Disable-NetFirewallRule', 'Disable-NetIPHttpsProfile', 'Disable-NetIPsecMainModeRule', 'Disable-NetIPsecRule', 'Disable-NetNatTransitionConfiguration', 'Disable-NetworkSwitchEthernetPort', 'Disable-NetworkSwitchFeature', 'Disable-NetworkSwitchVlan', 'Disable-OdbcPerfCounter', 'Disable-PhysicalDiskIdentification', 'Disable-PnpDevice', 'Disable-PSTrace', 'Disable-PSWSManCombinedTrace', 'Disable-ScheduledTask', 'Disable-SmbDelegation', 'Disable-StorageBusCache', 'Disable-StorageBusDisk', 'Disable-StorageEnclosureIdentification', 'Disable-StorageEnclosurePower', 'Disable-StorageHighAvailability', 'Disable-StorageMaintenanceMode', 'Disable-WdacBidTrace', 'Disable-WSManTrace', 'Disconnect-IscsiTarget', 'Disconnect-VirtualDisk', 'Dismount-DiskImage', 'Enable-BCDistributed', 'Enable-BCDowngrading', 'Enable-BCHostedClient', 'Enable-BCHostedServer', 'Enable-BCLocal', 'Enable-BCServeOnBattery', 'Enable-BitLocker', 'Enable-BitLockerAutoUnlock', 'Enable-DAManualEntryPointSelection', 'Enable-DscDebug', 'Enable-MMAgent', 'Enable-NetAdapter', 'Enable-NetAdapterBinding', 'Enable-NetAdapterChecksumOffload', 'Enable-NetAdapterEncapsulatedPacketTaskOffload', 'Enable-NetAdapterIPsecOffload', 'Enable-NetAdapterLso', 'Enable-NetAdapterPacketDirect', 'Enable-NetAdapterPowerManagement', 'Enable-NetAdapterQos', 'Enable-NetAdapterRdma', 'Enable-NetAdapterRsc', 'Enable-NetAdapterRss', 'Enable-NetAdapterSriov', 'Enable-NetAdapterUso', 'Enable-NetAdapterVmq', 'Enable-NetDnsTransitionConfiguration', 'Enable-NetFirewallRule', 'Enable-NetIPHttpsProfile', 'Enable-NetIPsecMainModeRule', 'Enable-NetIPsecRule', 'Enable-NetNatTransitionConfiguration', 'Enable-NetworkSwitchEthernetPort', 'Enable-NetworkSwitchFeature', 'Enable-NetworkSwitchVlan', 'Enable-OdbcPerfCounter', 'Enable-PhysicalDiskIdentification', 'Enable-PnpDevice', 'Enable-PSTrace', 'Enable-PSWSManCombinedTrace', 'Enable-ScheduledTask', 'Enable-SmbDelegation', 'Enable-StorageBusCache', 'Enable-StorageBusDisk', 'Enable-StorageEnclosureIdentification', 'Enable-StorageEnclosurePower', 'Enable-StorageHighAvailability', 'Enable-StorageMaintenanceMode', 'Enable-WdacBidTrace', 'Enable-WSManTrace', 'Expand-Archive', 'Export-BCCachePackage', 'Export-BCSecretKey', 'Export-ODataEndpointProxy', 'Export-ScheduledTask', 'Find-Cmdlet', 'Find-Command', 'Find-DscResource', 'Find-Integer', 'Find-Method', 'Find-Module', 'Find-Namespace', 'Find-NetIPsecRule', 'Find-NetRoute', 'Find-Pipe', 'Find-PipelineVariable', 'Find-RoleCapability', 'Find-Script', 'Find-String', 'Find-Variable', 'Flush-EtwTraceSession', 'Format-Hex', 'Format-Volume', 'Get-AppBackgroundTask', 'Get-AppvVirtualProcess', 'Get-AppxLastError', 'Get-AppxLog', 'Get-AssignedAccess', 'Get-AutologgerConfig', 'Get-BCClientConfiguration', 'Get-BCContentServerConfiguration', 'Get-BCDataCache', 'Get-BCDataCacheExtension', 'Get-BCHashCache', 'Get-BCHostedCacheServerConfiguration', 'Get-BCNetworkConfiguration', 'Get-BCStatus', 'Get-BitLockerVolume', 'Get-ClusteredScheduledTask', 'Get-DAClientExperienceConfiguration', 'Get-DAConnectionStatus', 'Get-DAEntryPointTableItem', 'Get-DedupProperties', 'Get-Disk', 'Get-DiskImage', 'Get-DiskStorageNodeView', 'Get-DnsClient', 'Get-DnsClientCache', 'Get-DnsClientGlobalSetting', 'Get-DnsClientNrptGlobal', 'Get-DnsClientNrptPolicy', 'Get-DnsClientNrptRule', 'Get-DnsClientServerAddress', 'Get-DscConfiguration', 'Get-DscConfigurationStatus', 'Get-DscLocalConfigurationManager', 'Get-DscResource', 'Get-Dtc', 'Get-DtcAdvancedHostSetting', 'Get-DtcAdvancedSetting', 'Get-DtcClusterDefault', 'Get-DtcClusterTMMapping', 'Get-DtcDefault', 'Get-DtcLog', 'Get-DtcNetworkSetting', 'Get-DtcTransaction', 'Get-DtcTransactionsStatistics', 'Get-DtcTransactionsTraceSession', 'Get-DtcTransactionsTraceSetting', 'Get-EtwTraceProvider', 'Get-EtwTraceSession', 'Get-FileHash', 'Get-FileIntegrity', 'Get-FileShare', 'Get-FileShareAccessControlEntry', 'Get-FileStorageTier', 'Get-InitiatorId', 'Get-InitiatorPort', 'Get-InstalledModule', 'Get-InstalledScript', 'Get-IscsiConnection', 'Get-IscsiSession', 'Get-IscsiTarget', 'Get-IscsiTargetPortal', 'Get-IseSnippet', 'Get-LogProperties', 'Get-MaskingSet', 'Get-MMAgent', 'Get-MockDynamicParameters', 'Get-MpComputerStatus', 'Get-MpComputerStatus', 'Get-MpPerformanceReport', 'Get-MpPreference', 'Get-MpPreference', 'Get-MpThreat', 'Get-MpThreat', 'Get-MpThreatCatalog', 'Get-MpThreatCatalog', 'Get-MpThreatDetection', 'Get-MpThreatDetection', 'Get-NCSIPolicyConfiguration', 'Get-Net6to4Configuration', 'Get-NetAdapter', 'Get-NetAdapterAdvancedProperty', 'Get-NetAdapterBinding', 'Get-NetAdapterChecksumOffload', 'Get-NetAdapterEncapsulatedPacketTaskOffload', 'Get-NetAdapterHardwareInfo', 'Get-NetAdapterIPsecOffload', 'Get-NetAdapterLso', 'Get-NetAdapterPacketDirect', 'Get-NetAdapterPowerManagement', 'Get-NetAdapterQos', 'Get-NetAdapterRdma', 'Get-NetAdapterRsc', 'Get-NetAdapterRss', 'Get-NetAdapterSriov', 'Get-NetAdapterSriovVf', 'Get-NetAdapterStatistics', 'Get-NetAdapterUso', 'Get-NetAdapterVmq', 'Get-NetAdapterVMQQueue', 'Get-NetAdapterVPort', 'Get-NetCompartment', 'Get-NetConnectionProfile', 'Get-NetDnsTransitionConfiguration', 'Get-NetDnsTransitionMonitoring', 'Get-NetEventNetworkAdapter', 'Get-NetEventPacketCaptureProvider', 'Get-NetEventProvider', 'Get-NetEventSession', 'Get-NetEventVFPProvider', 'Get-NetEventVmNetworkAdapter', 'Get-NetEventVmSwitch', 'Get-NetEventVmSwitchProvider', 'Get-NetEventWFPCaptureProvider', 'Get-NetFirewallAddressFilter', 'Get-NetFirewallApplicationFilter', 'Get-NetFirewallInterfaceFilter', 'Get-NetFirewallInterfaceTypeFilter', 'Get-NetFirewallPortFilter', 'Get-NetFirewallProfile', 'Get-NetFirewallRule', 'Get-NetFirewallSecurityFilter', 'Get-NetFirewallServiceFilter', 'Get-NetFirewallSetting', 'Get-NetIPAddress', 'Get-NetIPConfiguration', 'Get-NetIPHttpsConfiguration', 'Get-NetIPHttpsState', 'Get-NetIPInterface', 'Get-NetIPsecDospSetting', 'Get-NetIPsecMainModeCryptoSet', 'Get-NetIPsecMainModeRule', 'Get-NetIPsecMainModeSA', 'Get-NetIPsecPhase1AuthSet', 'Get-NetIPsecPhase2AuthSet', 'Get-NetIPsecQuickModeCryptoSet', 'Get-NetIPsecQuickModeSA', 'Get-NetIPsecRule', 'Get-NetIPv4Protocol', 'Get-NetIPv6Protocol', 'Get-NetIsatapConfiguration', 'Get-NetLbfoTeam', 'Get-NetLbfoTeamMember', 'Get-NetLbfoTeamNic', 'Get-NetNat', 'Get-NetNatExternalAddress', 'Get-NetNatGlobal', 'Get-NetNatSession', 'Get-NetNatStaticMapping', 'Get-NetNatTransitionConfiguration', 'Get-NetNatTransitionMonitoring', 'Get-NetNeighbor', 'Get-NetOffloadGlobalSetting', 'Get-NetPrefixPolicy', 'Get-NetQosPolicy', 'Get-NetRoute', 'Get-NetSwitchTeam', 'Get-NetSwitchTeamMember', 'Get-NetTCPConnection', 'Get-NetTCPSetting', 'Get-NetTeredoConfiguration', 'Get-NetTeredoState', 'Get-NetTransportFilter', 'Get-NetUDPEndpoint', 'Get-NetUDPSetting', 'Get-NetworkSwitchEthernetPort', 'Get-NetworkSwitchFeature', 'Get-NetworkSwitchGlobalData', 'Get-NetworkSwitchVlan', 'Get-ObfuscatedCmdlet', 'Get-ObfuscatedInteger', 'Get-ObfuscatedMethod', 'Get-ObfuscatedNamespace', 'Get-ObfuscatedPipe', 'Get-ObfuscatedPipelineVariable', 'Get-ObfuscatedString', 'Get-ObfuscatedVariable', 'Get-OdbcDriver', 'Get-OdbcDsn', 'Get-OdbcPerfCounter', 'Get-OffloadDataTransferSetting', 'Get-OperationValidation', 'Get-OperatorEncapsulation', 'Get-Partition', 'Get-PartitionSupportedSize', 'Get-PcsvDevice', 'Get-PcsvDeviceLog', 'Get-PhysicalDisk', 'Get-PhysicalDiskStorageNodeView', 'Get-PhysicalExtent', 'Get-PhysicalExtentAssociation', 'Get-PnpDevice', 'Get-PnpDeviceProperty', 'Get-PrintConfiguration', 'Get-Printer', 'Get-PrinterDriver', 'Get-PrinterPort', 'Get-PrinterProperty', 'Get-PrintJob', 'Get-PSRepository', 'Get-ResiliencySetting', 'Get-ScheduledTask', 'Get-ScheduledTaskInfo', 'Get-SmbBandWidthLimit', 'Get-SmbClientConfiguration', 'Get-SmbClientNetworkInterface', 'Get-SmbConnection', 'Get-SmbDelegation', 'Get-SmbGlobalMapping', 'Get-SmbMapping', 'Get-SmbMultichannelConnection', 'Get-SmbMultichannelConstraint', 'Get-SmbOpenFile', 'Get-SmbServerConfiguration', 'Get-SmbServerNetworkInterface', 'Get-SmbSession', 'Get-SmbShare', 'Get-SmbShareAccess', 'Get-SmbWitnessClient', 'Get-StartApps', 'Get-StorageAdvancedProperty', 'Get-StorageBusBinding', 'Get-StorageBusDisk', 'Get-StorageChassis', 'Get-StorageDiagnosticInfo', 'Get-StorageEnclosure', 'Get-StorageEnclosureStorageNodeView', 'Get-StorageEnclosureVendorData', 'Get-StorageExtendedStatus', 'Get-StorageFaultDomain', 'Get-StorageFileServer', 'Get-StorageFirmwareInformation', 'Get-StorageHealthAction', 'Get-StorageHealthReport', 'Get-StorageHealthSetting', 'Get-StorageHistory', 'Get-StorageJob', 'Get-StorageNode', 'Get-StoragePool', 'Get-StorageProvider', 'Get-StorageRack', 'Get-StorageReliabilityCounter', 'Get-StorageScaleUnit', 'Get-StorageSetting', 'Get-StorageSite', 'Get-StorageSubSystem', 'Get-StorageTier', 'Get-StorageTierSupportedSize', 'Get-SupportedClusterSizes', 'Get-SupportedFileSystems', 'Get-TargetPort', 'Get-TargetPortal', 'Get-TestDriveItem', 'Get-Verb', 'Get-VirtualDisk', 'Get-VirtualDiskSupportedSize', 'Get-Volume', 'Get-VolumeCorruptionCount', 'Get-VolumeScrubPolicy', 'Get-VpnConnection', 'Get-VpnConnectionTrigger', 'Get-WdacBidTrace', 'Get-WindowsUpdateLog', 'Get-WUAVersion', 'Get-WUIsPendingReboot', 'Get-WULastInstallationDate', 'Get-WULastScanSuccessDate', 'Grant-FileShareAccess', 'Grant-SmbShareAccess', 'Hide-VirtualDisk', 'Import-BCCachePackage', 'Import-BCSecretKey', 'Import-IseSnippet', 'Import-PowerShellDataFile', 'Initialize-Disk', 'Install-Dtc', 'Install-Module', 'Install-Script', 'Install-WUUpdates', 'Invoke-AsWorkflow', 'Invoke-Mock', 'Invoke-OperationValidation', 'Invoke-Pester', 'Invoke-PSObfuscation', 'Lock-BitLocker', 'Mount-DiskImage', 'Move-SmbWitnessClient', 'New-AutologgerConfig', 'New-DAEntryPointTableItem', 'New-DscChecksum', 'New-EapConfiguration', 'New-EncodedBeacon', 'New-EtwTraceSession', 'New-FileShare', 'New-Fixture', 'New-Guid', 'New-IscsiTargetPortal', 'New-IseSnippet', 'New-MaskingSet', 'New-MpPerformanceRecording', 'New-NetAdapterAdvancedProperty', 'New-NetEventSession', 'New-NetFirewallRule', 'New-NetIPAddress', 'New-NetIPHttpsConfiguration', 'New-NetIPsecDospSetting', 'New-NetIPsecMainModeCryptoSet', 'New-NetIPsecMainModeRule', 'New-NetIPsecPhase1AuthSet', 'New-NetIPsecPhase2AuthSet', 'New-NetIPsecQuickModeCryptoSet', 'New-NetIPsecRule', 'New-NetLbfoTeam', 'New-NetNat', 'New-NetNatTransitionConfiguration', 'New-NetNeighbor', 'New-NetQosPolicy', 'New-NetRoute', 'New-NetSwitchTeam', 'New-NetTransportFilter', 'New-NetworkSwitchVlan', 'New-Partition', 'New-PesterOption', 'New-PSWorkflowSession', 'New-ScheduledTask', 'New-ScheduledTaskAction', 'New-ScheduledTaskPrincipal', 'New-ScheduledTaskSettingsSet', 'New-ScheduledTaskTrigger', 'New-ScriptFileInfo', 'New-SmbGlobalMapping', 'New-SmbMapping', 'New-SmbMultichannelConstraint', 'New-SmbShare', 'New-StorageBusBinding', 'New-StorageBusCacheStore', 'New-StorageFileServer', 'New-StoragePool', 'New-StorageSubsystemVirtualDisk', 'New-StorageTier', 'New-TemporaryFile', 'New-VirtualDisk', 'New-VirtualDiskClone', 'New-VirtualDiskSnapshot', 'New-Volume', 'New-VpnServerAddress', 'Open-NetGPO', 'Optimize-StoragePool', 'Optimize-Volume', 'Publish-BCFileContent', 'Publish-BCWebContent', 'Publish-Module', 'Publish-Script', 'Read-PrinterNfcTag', 'Register-ClusteredScheduledTask', 'Register-DnsClient', 'Register-IscsiSession', 'Register-PSRepository', 'Register-ScheduledTask', 'Register-StorageSubsystem', 'Remove-AutologgerConfig', 'Remove-BCDataCacheExtension', 'Remove-BitLockerKeyProtector', 'Remove-Comments', 'Remove-DAEntryPointTableItem', 'Remove-DnsClientNrptRule', 'Remove-DscConfigurationDocument', 'Remove-DtcClusterTMMapping', 'Remove-EtwTraceProvider', 'Remove-FileShare', 'Remove-InitiatorId', 'Remove-InitiatorIdFromMaskingSet', 'Remove-IscsiTargetPortal', 'Remove-MaskingSet', 'Remove-MpPreference', 'Remove-MpPreference', 'Remove-MpThreat', 'Remove-MpThreat', 'Remove-NetAdapterAdvancedProperty', 'Remove-NetEventNetworkAdapter', 'Remove-NetEventPacketCaptureProvider', 'Remove-NetEventProvider', 'Remove-NetEventSession', 'Remove-NetEventVFPProvider', 'Remove-NetEventVmNetworkAdapter', 'Remove-NetEventVmSwitch', 'Remove-NetEventVmSwitchProvider', 'Remove-NetEventWFPCaptureProvider', 'Remove-NetFirewallRule', 'Remove-NetIPAddress', 'Remove-NetIPHttpsCertBinding', 'Remove-NetIPHttpsConfiguration', 'Remove-NetIPsecDospSetting', 'Remove-NetIPsecMainModeCryptoSet', 'Remove-NetIPsecMainModeRule', 'Remove-NetIPsecMainModeSA', 'Remove-NetIPsecPhase1AuthSet', 'Remove-NetIPsecPhase2AuthSet', 'Remove-NetIPsecQuickModeCryptoSet', 'Remove-NetIPsecQuickModeSA', 'Remove-NetIPsecRule', 'Remove-NetLbfoTeam', 'Remove-NetLbfoTeamMember', 'Remove-NetLbfoTeamNic', 'Remove-NetNat', 'Remove-NetNatExternalAddress', 'Remove-NetNatStaticMapping', 'Remove-NetNatTransitionConfiguration', 'Remove-NetNeighbor', 'Remove-NetQosPolicy', 'Remove-NetRoute', 'Remove-NetSwitchTeam', 'Remove-NetSwitchTeamMember', 'Remove-NetTransportFilter', 'Remove-NetworkSwitchEthernetPortIPAddress', 'Remove-NetworkSwitchVlan', 'Remove-OdbcDsn', 'Remove-Partition', 'Remove-PartitionAccessPath', 'Remove-PhysicalDisk', 'Remove-Printer', 'Remove-PrinterDriver', 'Remove-PrinterPort', 'Remove-PrintJob', 'Remove-SmbBandwidthLimit', 'Remove-SmbGlobalMapping', 'Remove-SmbMapping', 'Remove-SmbMultichannelConstraint', 'Remove-SmbShare', 'Remove-StorageBusBinding', 'Remove-StorageFaultDomain', 'Remove-StorageFileServer', 'Remove-StorageHealthIntent', 'Remove-StorageHealthSetting', 'Remove-StoragePool', 'Remove-StorageTier', 'Remove-TargetPortFromMaskingSet', 'Remove-VirtualDisk', 'Remove-VirtualDiskFromMaskingSet', 'Remove-VpnConnection', 'Remove-VpnConnectionRoute', 'Remove-VpnConnectionTriggerApplication', 'Remove-VpnConnectionTriggerDnsConfiguration', 'Remove-VpnConnectionTriggerTrustedNetwork', 'Rename-DAEntryPointTableItem', 'Rename-MaskingSet', 'Rename-NetAdapter', 'Rename-NetFirewallRule', 'Rename-NetIPHttpsConfiguration', 'Rename-NetIPsecMainModeCryptoSet', 'Rename-NetIPsecMainModeRule', 'Rename-NetIPsecPhase1AuthSet', 'Rename-NetIPsecPhase2AuthSet', 'Rename-NetIPsecQuickModeCryptoSet', 'Rename-NetIPsecRule', 'Rename-NetLbfoTeam', 'Rename-NetSwitchTeam', 'Rename-Printer', 'Repair-FileIntegrity', 'Repair-VirtualDisk', 'Repair-Volume', 'Reset-BC', 'Reset-DAClientExperienceConfiguration', 'Reset-DAEntryPointTableItem', 'Reset-DtcLog', 'Reset-NCSIPolicyConfiguration', 'Reset-Net6to4Configuration', 'Reset-NetAdapterAdvancedProperty', 'Reset-NetDnsTransitionConfiguration', 'Reset-NetIPHttpsConfiguration', 'Reset-NetIsatapConfiguration', 'Reset-NetTeredoConfiguration', 'Reset-PhysicalDisk', 'Reset-StorageReliabilityCounter', 'Resize-Partition', 'Resize-StorageTier', 'Resize-VirtualDisk', 'Resolve-Aliases', 'Restart-NetAdapter', 'Restart-PcsvDevice', 'Restart-PrintJob', 'Restore-DscConfiguration', 'Restore-NetworkSwitchConfiguration', 'Resume-BitLocker', 'Resume-PrintJob', 'Resume-StorageBusDisk', 'Revoke-FileShareAccess', 'Revoke-SmbShareAccess', 'Save-EtwTraceSession', 'Save-Module', 'Save-NetGPO', 'Save-NetworkSwitchConfiguration', 'Save-Script', 'Send-EtwTraceSession', 'Set-AssignedAccess', 'Set-BCAuthentication', 'Set-BCCache', 'Set-BCDataCacheEntryMaxAge', 'Set-BCMinSMBLatency', 'Set-BCSecretKey', 'Set-ClusteredScheduledTask', 'Set-DAClientExperienceConfiguration', 'Set-DAEntryPointTableItem', 'Set-Disk', 'Set-DnsClient', 'Set-DnsClientGlobalSetting', 'Set-DnsClientNrptGlobal', 'Set-DnsClientNrptRule', 'Set-DnsClientServerAddress', 'Set-DtcAdvancedHostSetting', 'Set-DtcAdvancedSetting', 'Set-DtcClusterDefault', 'Set-DtcClusterTMMapping', 'Set-DtcDefault', 'Set-DtcLog', 'Set-DtcNetworkSetting', 'Set-DtcTransaction', 'Set-DtcTransactionsTraceSession', 'Set-DtcTransactionsTraceSetting', 'Set-DynamicParameterVariables', 'Set-EtwTraceProvider', 'Set-FileIntegrity', 'Set-FileShare', 'Set-FileStorageTier', 'Set-InitiatorPort', 'Set-IscsiChapSecret', 'Set-LogProperties', 'Set-MMAgent', 'Set-MpPreference', 'Set-MpPreference', 'Set-NCSIPolicyConfiguration', 'Set-Net6to4Configuration', 'Set-NetAdapter', 'Set-NetAdapterAdvancedProperty', 'Set-NetAdapterBinding', 'Set-NetAdapterChecksumOffload', 'Set-NetAdapterEncapsulatedPacketTaskOffload', 'Set-NetAdapterIPsecOffload', 'Set-NetAdapterLso', 'Set-NetAdapterPacketDirect', 'Set-NetAdapterPowerManagement', 'Set-NetAdapterQos', 'Set-NetAdapterRdma', 'Set-NetAdapterRsc', 'Set-NetAdapterRss', 'Set-NetAdapterSriov', 'Set-NetAdapterUso', 'Set-NetAdapterVmq', 'Set-NetConnectionProfile', 'Set-NetDnsTransitionConfiguration', 'Set-NetEventPacketCaptureProvider', 'Set-NetEventProvider', 'Set-NetEventSession', 'Set-NetEventVFPProvider', 'Set-NetEventVmSwitchProvider', 'Set-NetEventWFPCaptureProvider', 'Set-NetFirewallAddressFilter', 'Set-NetFirewallApplicationFilter', 'Set-NetFirewallInterfaceFilter', 'Set-NetFirewallInterfaceTypeFilter', 'Set-NetFirewallPortFilter', 'Set-NetFirewallProfile', 'Set-NetFirewallRule', 'Set-NetFirewallSecurityFilter', 'Set-NetFirewallServiceFilter', 'Set-NetFirewallSetting', 'Set-NetIPAddress', 'Set-NetIPHttpsConfiguration', 'Set-NetIPInterface', 'Set-NetIPsecDospSetting', 'Set-NetIPsecMainModeCryptoSet', 'Set-NetIPsecMainModeRule', 'Set-NetIPsecPhase1AuthSet', 'Set-NetIPsecPhase2AuthSet', 'Set-NetIPsecQuickModeCryptoSet', 'Set-NetIPsecRule', 'Set-NetIPv4Protocol', 'Set-NetIPv6Protocol', 'Set-NetIsatapConfiguration', 'Set-NetLbfoTeam', 'Set-NetLbfoTeamMember', 'Set-NetLbfoTeamNic', 'Set-NetNat', 'Set-NetNatGlobal', 'Set-NetNatTransitionConfiguration', 'Set-NetNeighbor', 'Set-NetOffloadGlobalSetting', 'Set-NetQosPolicy', 'Set-NetRoute', 'Set-NetTCPSetting', 'Set-NetTeredoConfiguration', 'Set-NetUDPSetting', 'Set-NetworkSwitchEthernetPortIPAddress', 'Set-NetworkSwitchPortMode', 'Set-NetworkSwitchPortProperty', 'Set-NetworkSwitchVlanProperty', 'Set-OdbcDriver', 'Set-OdbcDsn', 'Set-Partition', 'Set-PcsvDeviceBootConfiguration', 'Set-PcsvDeviceNetworkConfiguration', 'Set-PcsvDeviceUserPassword', 'Set-PhysicalDisk', 'Set-PrintConfiguration', 'Set-Printer', 'Set-PrinterProperty', 'Set-PSRepository', 'Set-ResiliencySetting', 'Set-ScheduledTask', 'Set-SmbBandwidthLimit', 'Set-SmbClientConfiguration', 'Set-SmbPathAcl', 'Set-SmbServerConfiguration', 'Set-SmbShare', 'Set-StorageBusProfile', 'Set-StorageFileServer', 'Set-StorageHealthSetting', 'Set-StoragePool', 'Set-StorageProvider', 'Set-StorageSetting', 'Set-StorageSubSystem', 'Set-StorageTier', 'Set-TestInconclusive', 'Set-VirtualDisk', 'Set-Volume', 'Set-VolumeScrubPolicy', 'Set-VpnConnection', 'Set-VpnConnectionIPsecConfiguration', 'Set-VpnConnectionProxy', 'Set-VpnConnectionTriggerDnsConfiguration', 'Set-VpnConnectionTriggerTrustedNetwork', 'Show-NetFirewallRule', 'Show-NetIPsecRule', 'Show-StorageHistory', 'Show-VirtualDisk', 'Start-AppBackgroundTask', 'Start-AppvVirtualProcess', 'Start-AutologgerConfig', 'Start-Dtc', 'Start-DtcTransactionsTraceSession', 'Start-EtwTraceSession', 'Start-MpRollback', 'Start-MpScan', 'Start-MpScan', 'Start-MpWDOScan', 'Start-MpWDOScan', 'Start-NetEventSession', 'Start-PcsvDevice', 'Start-ScheduledTask', 'Start-StorageDiagnosticLog', 'Start-Trace', 'Start-WUScan', 'Stop-DscConfiguration', 'Stop-Dtc', 'Stop-DtcTransactionsTraceSession', 'Stop-EtwTraceSession', 'Stop-NetEventSession', 'Stop-PcsvDevice', 'Stop-ScheduledTask', 'Stop-StorageDiagnosticLog', 'Stop-StorageJob', 'Stop-Trace', 'Suspend-BitLocker', 'Suspend-PrintJob', 'Suspend-StorageBusDisk', 'Sync-NetIPsecRule', 'Test-Dtc', 'Test-NetConnection', 'Test-ScriptFileInfo', 'Unblock-FileShareAccess', 'Unblock-SmbShareAccess', 'Uninstall-Dtc', 'Uninstall-Module', 'Uninstall-Script', 'Unlock-BitLocker', 'Unregister-AppBackgroundTask', 'Unregister-ClusteredScheduledTask', 'Unregister-IscsiSession', 'Unregister-PSRepository', 'Unregister-ScheduledTask', 'Unregister-StorageSubsystem', 'Update-AutologgerConfig', 'Update-Disk', 'Update-DscConfiguration', 'Update-EtwTraceSession', 'Update-HostStorageCache', 'Update-IscsiTarget', 'Update-IscsiTargetPortal', 'Update-Module', 'Update-ModuleManifest', 'Update-MpSignature', 'Update-MpSignature', 'Update-NetIPsecRule', 'Update-Script', 'Update-ScriptFileInfo', 'Update-SmbMultichannelConnection', 'Update-StorageFirmware', 'Update-StoragePool', 'Update-StorageProviderCache', 'Write-DtcTransactionsTraceSession', 'Write-PrinterNfcTag', 'Write-VolumeCache', 'Add-AppvClientConnectionGroup', 'Add-AppvClientPackage', 'Add-AppvPublishingServer', 'Add-AppxPackage', 'Add-AppxProvisionedPackage', 'Add-AppxVolume', 'Add-BitsFile', 'Add-CertificateEnrollmentPolicyServer', 'Add-Computer', 'Add-Content', 'Add-History', 'Add-JobTrigger', 'Add-KdsRootKey', 'Add-LocalGroupMember', 'Add-Member', 'Add-PSSnapin', 'Add-SignerRule', 'Add-Type', 'Add-WindowsCapability', 'Add-WindowsDriver', 'Add-WindowsImage', 'Add-WindowsPackage', 'Checkpoint-Computer', 'Clear-Content', 'Clear-EventLog', 'Clear-History', 'Clear-Item', 'Clear-ItemProperty', 'Clear-KdsCache', 'Clear-RecycleBin', 'Clear-Tpm', 'Clear-UevAppxPackage', 'Clear-UevConfiguration', 'Clear-Variable', 'Clear-WindowsCorruptMountPoint', 'Compare-Object', 'Complete-BitsTransfer', 'Complete-DtcDiagnosticTransaction', 'Complete-Transaction', 'Confirm-SecureBootUEFI', 'Connect-PSSession', 'Connect-WSMan', 'ConvertFrom-CIPolicy', 'ConvertFrom-Csv', 'ConvertFrom-Json', 'ConvertFrom-SecureString', 'ConvertFrom-String', 'ConvertFrom-StringData', 'Convert-Path', 'Convert-String', 'ConvertTo-Csv', 'ConvertTo-Html', 'ConvertTo-Json', 'ConvertTo-ProcessMitigationPolicy', 'ConvertTo-SecureString', 'ConvertTo-TpmOwnerAuth', 'ConvertTo-Xml', 'Copy-Item', 'Copy-ItemProperty', 'Debug-Job', 'Debug-Process', 'Debug-Runspace', 'Delete-DeliveryOptimizationCache', 'Disable-AppBackgroundTaskDiagnosticLog', 'Disable-Appv', 'Disable-AppvClientConnectionGroup', 'Disable-ComputerRestore', 'Disable-JobTrigger', 'Disable-LocalUser', 'Disable-PSBreakpoint', 'Disable-PSRemoting', 'Disable-PSSessionConfiguration', 'Disable-RunspaceDebug', 'Disable-ScheduledJob', 'Disable-TlsCipherSuite', 'Disable-TlsEccCurve', 'Disable-TlsSessionTicketKey', 'Disable-TpmAutoProvisioning', 'Disable-Uev', 'Disable-UevAppxPackage', 'Disable-UevTemplate', 'Disable-WindowsErrorReporting', 'Disable-WindowsOptionalFeature', 'Disable-WSManCredSSP', 'Disconnect-PSSession', 'Disconnect-WSMan', 'Dismount-AppxVolume', 'Dismount-WindowsImage', 'Edit-CIPolicyRule', 'Enable-AppBackgroundTaskDiagnosticLog', 'Enable-Appv', 'Enable-AppvClientConnectionGroup', 'Enable-ComputerRestore', 'Enable-JobTrigger', 'Enable-LocalUser', 'Enable-PSBreakpoint', 'Enable-PSRemoting', 'Enable-PSSessionConfiguration', 'Enable-RunspaceDebug', 'Enable-ScheduledJob', 'Enable-TlsCipherSuite', 'Enable-TlsEccCurve', 'Enable-TlsSessionTicketKey', 'Enable-TpmAutoProvisioning', 'Enable-Uev', 'Enable-UevAppxPackage', 'Enable-UevTemplate', 'Enable-WindowsErrorReporting', 'Enable-WindowsOptionalFeature', 'Enable-WSManCredSSP', 'Enter-PSHostProcess', 'Enter-PSSession', 'Exit-PSHostProcess', 'Exit-PSSession', 'Expand-WindowsCustomDataImage', 'Expand-WindowsImage', 'Export-Alias', 'Export-BinaryMiLog', 'Export-Certificate', 'Export-Clixml', 'Export-Console', 'Export-Counter', 'Export-Csv', 'Export-FormatData', 'Export-ModuleMember', 'Export-PfxCertificate', 'Export-ProvisioningPackage', 'Export-PSSession', 'Export-StartLayout', 'Export-StartLayoutEdgeAssets', 'Export-TlsSessionTicketKey', 'Export-Trace', 'Export-UevConfiguration', 'Export-UevPackage', 'Export-WindowsCapabilitySource', 'Export-WindowsDriver', 'Export-WindowsImage', 'Find-Package', 'Find-PackageProvider', 'ForEach-Object', 'Format-Custom', 'Format-List', 'Format-SecureBootUEFI', 'Format-Table', 'Format-Wide', 'Get-Acl', 'Get-Alias', 'Get-AppLockerFileInformation', 'Get-AppLockerPolicy', 'Get-AppvClientApplication', 'Get-AppvClientConfiguration', 'Get-AppvClientConnectionGroup', 'Get-AppvClientMode', 'Get-AppvClientPackage', 'Get-AppvPublishingServer', 'Get-AppvStatus', 'Get-AppxDefaultVolume', 'Get-AppxPackage', 'Get-AppxPackageManifest', 'Get-AppxProvisionedPackage', 'Get-AppxVolume', 'Get-AuthenticodeSignature', 'Get-BitsTransfer', 'Get-Certificate', 'Get-CertificateAutoEnrollmentPolicy', 'Get-CertificateEnrollmentPolicyServer', 'Get-CertificateNotificationTask', 'Get-ChildItem', 'Get-CimAssociatedInstance', 'Get-CimClass', 'Get-CimInstance', 'Get-CimSession', 'Get-CIPolicy', 'Get-CIPolicyIdInfo', 'Get-CIPolicyInfo', 'Get-Clipboard', 'Get-CmsMessage', 'Get-Command', 'Get-ComputerInfo', 'Get-ComputerRestorePoint', 'Get-Content', 'Get-ControlPanelItem', 'Get-Counter', 'Get-Credential', 'Get-Culture', 'Get-DAPolicyChange', 'Get-Date', 'Get-DeliveryOptimizationLog', 'Get-DeliveryOptimizationPerfSnap', 'Get-DeliveryOptimizationPerfSnapThisMonth', 'Get-DeliveryOptimizationStatus', 'Get-DOConfig', 'Get-DODownloadMode', 'Get-DOPercentageMaxBackgroundBandwidth', 'Get-DOPercentageMaxForegroundBandwidth', 'Get-Event', 'Get-EventLog', 'Get-EventSubscriber', 'Get-ExecutionPolicy', 'Get-FormatData', 'Get-Help', 'Get-History', 'Get-Host', 'Get-HotFix', 'Get-Job', 'Get-JobTrigger', 'Get-KdsConfiguration', 'Get-KdsRootKey', 'Get-LocalGroup', 'Get-LocalGroupMember', 'Get-LocalUser', 'Get-Location', 'Get-Member', 'Get-Module', 'Get-NonRemovableAppsPolicy', 'Get-Package', 'Get-PackageProvider', 'Get-PackageSource', 'Get-PfxCertificate', 'Get-PfxData', 'Get-PmemDisk', 'Get-PmemPhysicalDevice', 'Get-PmemUnusedRegion', 'Get-Process', 'Get-ProcessMitigation', 'Get-ProvisioningPackage', 'Get-PSBreakpoint', 'Get-PSCallStack', 'Get-PSDrive', 'Get-PSHostProcessInfo', 'Get-PSProvider', 'Get-PSReadLineKeyHandler', 'Get-PSReadLineOption', 'Get-PSSession', 'Get-PSSessionCapability', 'Get-PSSessionConfiguration', 'Get-PSSnapin', 'Get-Random', 'Get-Runspace', 'Get-RunspaceDebug', 'Get-ScheduledJob', 'Get-ScheduledJobOption', 'Get-SecureBootPolicy', 'Get-SecureBootUEFI', 'Get-Service', 'Get-SystemDriver', 'Get-TimeZone', 'Get-TlsCipherSuite', 'Get-TlsEccCurve', 'Get-Tpm', 'Get-TpmEndorsementKeyInfo', 'Get-TpmSupportedFeature', 'Get-TraceSource', 'Get-Transaction', 'Get-TroubleshootingPack', 'Get-TrustedProvisioningCertificate', 'Get-TypeData', 'Get-UevAppxPackage', 'Get-UevConfiguration', 'Get-UevStatus', 'Get-UevTemplate', 'Get-UevTemplateProgram', 'Get-UICulture', 'Get-Unique', 'Get-Variable', 'Get-WheaMemoryPolicy', 'Get-WIMBootEntry', 'Get-WinAcceptLanguageFromLanguageListOptOut', 'Get-WinCultureFromLanguageListOptOut', 'Get-WinDefaultInputMethodOverride', 'Get-WindowsCapability', 'Get-WindowsDeveloperLicense', 'Get-WindowsDriver', 'Get-WindowsEdition', 'Get-WindowsErrorReporting', 'Get-WindowsImage', 'Get-WindowsImageContent', 'Get-WindowsOptionalFeature', 'Get-WindowsPackage', 'Get-WindowsSearchSetting', 'Get-WinEvent', 'Get-WinHomeLocation', 'Get-WinLanguageBarOption', 'Get-WinSystemLocale', 'Get-WinUILanguageOverride', 'Get-WinUserLanguageList', 'Get-WmiObject', 'Get-WSManCredSSP', 'Get-WSManInstance', 'Group-Object', 'Import-Alias', 'Import-BinaryMiLog', 'Import-Certificate', 'Import-Clixml', 'Import-Counter', 'Import-Csv', 'Import-LocalizedData', 'Import-Module', 'Import-PackageProvider', 'Import-PfxCertificate', 'Import-PSSession', 'Import-StartLayout', 'Import-TpmOwnerAuth', 'Import-UevConfiguration', 'Initialize-PmemPhysicalDevice', 'Initialize-Tpm', 'Install-Package', 'Install-PackageProvider', 'Install-ProvisioningPackage', 'Install-TrustedProvisioningCertificate', 'Invoke-CimMethod', 'Invoke-Command', 'Invoke-CommandInDesktopPackage', 'Invoke-DscResource', 'Invoke-Expression', 'Invoke-History', 'Invoke-Item', 'Invoke-RestMethod', 'Invoke-TroubleshootingPack', 'Invoke-WebRequest', 'Invoke-WmiMethod', 'Invoke-WSManAction', 'Join-DtcDiagnosticResourceManager', 'Join-Path', 'Limit-EventLog', 'Measure-Command', 'Measure-Object', 'Merge-CIPolicy', 'Mount-AppvClientConnectionGroup', 'Mount-AppvClientPackage', 'Mount-AppxVolume', 'Mount-WindowsImage', 'Move-AppxPackage', 'Move-Item', 'Move-ItemProperty', 'New-Alias', 'New-AppLockerPolicy', 'New-CertificateNotificationTask', 'New-CimInstance', 'New-CimSession', 'New-CimSessionOption', 'New-CIPolicy', 'New-CIPolicyRule', 'New-DtcDiagnosticTransaction', 'New-Event', 'New-EventLog', 'New-FileCatalog', 'New-Item', 'New-ItemProperty', 'New-JobTrigger', 'New-LocalGroup', 'New-LocalUser', 'New-Module', 'New-ModuleManifest', 'New-NetIPsecAuthProposal', 'New-NetIPsecMainModeCryptoProposal', 'New-NetIPsecQuickModeCryptoProposal', 'New-Object', 'New-PmemDisk', 'New-ProvisioningRepro', 'New-PSDrive', 'New-PSRoleCapabilityFile', 'New-PSSession', 'New-PSSessionConfigurationFile', 'New-PSSessionOption', 'New-PSTransportOption', 'New-PSWorkflowExecutionOption', 'New-ScheduledJobOption', 'New-SelfSignedCertificate', 'New-Service', 'New-TimeSpan', 'New-TlsSessionTicketKey', 'New-Variable', 'New-WebServiceProxy', 'New-WindowsCustomImage', 'New-WindowsImage', 'New-WinEvent', 'New-WinUserLanguageList', 'New-WSManInstance', 'New-WSManSessionOption', 'Optimize-AppxProvisionedPackages', 'Optimize-WindowsImage', 'Out-Default', 'Out-File', 'Out-GridView', 'Out-Host', 'Out-Null', 'Out-Printer', 'Out-String', 'Pop-Location', 'Protect-CmsMessage', 'Publish-AppvClientPackage', 'Publish-DscConfiguration', 'Push-Location', 'Read-Host', 'Receive-DtcDiagnosticTransaction', 'Receive-Job', 'Receive-PSSession', 'Register-ArgumentCompleter', 'Register-CimIndicationEvent', 'Register-EngineEvent', 'Register-ObjectEvent', 'Register-PackageSource', 'Register-PSSessionConfiguration', 'Register-ScheduledJob', 'Register-UevTemplate', 'Register-WmiEvent', 'Remove-AppvClientConnectionGroup', 'Remove-AppvClientPackage', 'Remove-AppvPublishingServer', 'Remove-AppxPackage', 'Remove-AppxProvisionedPackage', 'Remove-AppxVolume', 'Remove-BitsTransfer', 'Remove-CertificateEnrollmentPolicyServer', 'Remove-CertificateNotificationTask', 'Remove-CimInstance', 'Remove-CimSession', 'Remove-CIPolicyRule', 'Remove-Computer', 'Remove-Event', 'Remove-EventLog', 'Remove-Item', 'Remove-ItemProperty', 'Remove-Job', 'Remove-JobTrigger', 'Remove-LocalGroup', 'Remove-LocalGroupMember', 'Remove-LocalUser', 'Remove-Module', 'Remove-PmemDisk', 'Remove-PSBreakpoint', 'Remove-PSDrive', 'Remove-PSReadLineKeyHandler', 'Remove-PSSession', 'Remove-PSSnapin', 'Remove-TypeData', 'Remove-Variable', 'Remove-WindowsCapability', 'Remove-WindowsDriver', 'Remove-WindowsImage', 'Remove-WindowsPackage', 'Remove-WmiObject', 'Remove-WSManInstance', 'Rename-Computer', 'Rename-Item', 'Rename-ItemProperty', 'Rename-LocalGroup', 'Rename-LocalUser', 'Repair-AppvClientConnectionGroup', 'Repair-AppvClientPackage', 'Repair-UevTemplateIndex', 'Repair-WindowsImage', 'Reset-ComputerMachinePassword', 'Resolve-DnsName', 'Resolve-Path', 'Restart-Computer', 'Restart-Service', 'Restore-Computer', 'Restore-UevBackup', 'Restore-UevUserSetting', 'Resume-BitsTransfer', 'Resume-Job', 'Resume-ProvisioningSession', 'Resume-Service', 'Save-Help', 'Save-Package', 'Save-WindowsImage', 'Select-Object', 'Select-String', 'Select-Xml', 'Send-AppvClientReport', 'Send-DtcDiagnosticTransaction', 'Send-MailMessage', 'Set-Acl', 'Set-Alias', 'Set-AppBackgroundTaskResourcePolicy', 'Set-AppLockerPolicy', 'Set-AppvClientConfiguration', 'Set-AppvClientMode', 'Set-AppvClientPackage', 'Set-AppvPublishingServer', 'Set-AppxDefaultVolume', 'Set-AppXProvisionedDataFile', 'Set-AuthenticodeSignature', 'Set-BitsTransfer', 'Set-CertificateAutoEnrollmentPolicy', 'Set-CimInstance', 'Set-CIPolicyIdInfo', 'Set-CIPolicySetting', 'Set-CIPolicyVersion', 'Set-Clipboard', 'Set-Content', 'Set-Culture', 'Set-Date', 'Set-DeliveryOptimizationStatus', 'Set-DODownloadMode', 'Set-DOPercentageMaxBackgroundBandwidth', 'Set-DOPercentageMaxForegroundBandwidth', 'Set-DscLocalConfigurationManager', 'Set-ExecutionPolicy', 'Set-HVCIOptions', 'Set-Item', 'Set-ItemProperty', 'Set-JobTrigger', 'Set-KdsConfiguration', 'Set-LocalGroup', 'Set-LocalUser', 'Set-Location', 'Set-NonRemovableAppsPolicy', 'Set-PackageSource', 'Set-ProcessMitigation', 'Set-PSBreakpoint', 'Set-PSDebug', 'Set-PSReadLineKeyHandler', 'Set-PSReadLineOption', 'Set-PSSessionConfiguration', 'Set-RuleOption', 'Set-ScheduledJob', 'Set-ScheduledJobOption', 'Set-SecureBootUEFI', 'Set-Service', 'Set-StrictMode', 'Set-TimeZone', 'Set-TpmOwnerAuth', 'Set-TraceSource', 'Set-UevConfiguration', 'Set-UevTemplateProfile', 'Set-Variable', 'Set-WheaMemoryPolicy', 'Set-WinAcceptLanguageFromLanguageListOptOut', 'Set-WinCultureFromLanguageListOptOut', 'Set-WinDefaultInputMethodOverride', 'Set-WindowsEdition', 'Set-WindowsProductKey', 'Set-WindowsSearchSetting', 'Set-WinHomeLocation', 'Set-WinLanguageBarOption', 'Set-WinSystemLocale', 'Set-WinUILanguageOverride', 'Set-WinUserLanguageList', 'Set-WmiInstance', 'Set-WSManInstance', 'Set-WSManQuickConfig', 'Show-Command', 'Show-ControlPanelItem', 'Show-EventLog', 'Show-WindowsDeveloperLicenseRegistration', 'Sort-Object', 'Split-Path', 'Split-WindowsImage', 'Start-BitsTransfer', 'Start-DscConfiguration', 'Start-DtcDiagnosticResourceManager', 'Start-Job', 'Start-OSUninstall', 'Start-Process', 'Start-Service', 'Start-Sleep', 'Start-Transaction', 'Start-Transcript', 'Stop-AppvClientConnectionGroup', 'Stop-AppvClientPackage', 'Stop-Computer', 'Stop-DtcDiagnosticResourceManager', 'Stop-Job', 'Stop-Process', 'Stop-Service', 'Stop-Transcript', 'Suspend-BitsTransfer', 'Suspend-Job', 'Suspend-Service', 'Switch-Certificate', 'Sync-AppvPublishingServer', 'Tee-Object', 'Test-AppLockerPolicy', 'Test-Certificate', 'Test-ComputerSecureChannel', 'Test-Connection', 'Test-DscConfiguration', 'Test-FileCatalog', 'Test-KdsRootKey', 'Test-ModuleManifest', 'Test-Path', 'Test-PSSessionConfigurationFile', 'Test-UevTemplate', 'Test-WSMan', 'Trace-Command', 'Unblock-File', 'Unblock-Tpm', 'Undo-DtcDiagnosticTransaction', 'Undo-Transaction', 'Uninstall-Package', 'Uninstall-ProvisioningPackage', 'Uninstall-TrustedProvisioningCertificate', 'Unprotect-CmsMessage', 'Unpublish-AppvClientPackage', 'Unregister-Event', 'Unregister-PackageSource', 'Unregister-PSSessionConfiguration', 'Unregister-ScheduledJob', 'Unregister-UevTemplate', 'Unregister-WindowsDeveloperLicense', 'Update-DscConfiguration', 'Update-FormatData', 'Update-Help', 'Update-List', 'Update-TypeData', 'Update-UevTemplate', 'Update-WIMBootEntry', 'Use-Transaction', 'Use-WindowsUnattend', 'Wait-Debugger', 'Wait-Event', 'Wait-Job', 'Wait-Process', 'Where-Object', 'Write-Debug', 'Write-Error', 'Write-EventLog', 'Write-Host', 'Write-Information', 'Write-Output', 'Write-Progress', 'Write-Verbose', 'Write-Warning']

	for i in cmdLetList:
		data = re.findall('[ \n](' + i + ') [^=]', ps1Content, re.I)

		for j in set(data):

			# print('\t' + i.strip() + '  =>  ' + ObfCmdLet(j))
			ps1Content = ps1Content.replace(j, ObfCmdLet(j))

	return ps1Content


def ObfMethod(method):

	ascStr = ''
	for i in method:
		ascStr += str(ord(i)) + ','

	return "<iex> ([string]::join('', ( (<OBFUSCATED>) |%{ ( [char][int] $_)})) | % {$_})".replace('<OBFUSCATED>', ascStr[:-1]).replace('<iex>', ObfCmdLet('invoke-expression'))


def Find_Method(ps1Content):
	pat = '[^\(]\$\w+\.\w+\(\)[\s]'
	data = re.findall(pat, ps1Content)

	for i in data:
		# print('\t' + i + '  =>  ' + ObfMethod(i))
		ps1Content = ps1Content.replace(i.strip(), ObfMethod(i))

	return ps1Content


def ObfNameSpace(NameSpace):

	obfType = ['[char](%s+%s-%s)', '[char](%s*%s/%s)']

	ascStr = ''
	for i in NameSpace:
		randStr = str(randint(1, 122))
		ascStr += choice(obfType) % (randStr, ord(i), randStr) + '+'

	return '$(' + ascStr[:-1] + ')'


def Find_NameSpace(ps1Content):

	pat = '(?<!\[)System\.IO\.MemoryStream|System\.IO\.Compression\.GZipStream|System\.Net\.Sockets\.TCPClient|System\.Text\.ASCIIEncoding|System\.Text\.UnicodeEncoding|System\.IO\.Compression\.CompressionMode(?!\])'
	data = re.findall(pat, ps1Content)

	for i in set(data):
		# print('\t' + i + '  =>  ' + ObfNameSpace(i))
		ps1Content = ps1Content.replace(i, ObfNameSpace(i))

	return ps1Content


def Find_Pipe(ps1Content):
	pat = '\|'
	data = re.findall(pat, ps1Content)

	PipeList = ['|%{$_}|', '|%{;$_}|', '|%{$_;}|', '|%{;$_;}|', '|<##>%{$_}<##>|']

	for i in set(data):
		# print('\t' + i + '  =>  ' + choice(PipeList))
		ps1Content = ps1Content.replace(i, choice(PipeList))

	return ps1Content


def Find_PipelineVariable(ps1Content):
	pat = '\$_(?!\.)'
	data = re.findall(pat, ps1Content)

	PipelineVariableList = ['<##>$_', '$_<##>', '<##>$_<##>', '<##>$($_)']

	for i in set(data):
		# print('\t' + i + '  =>  ' + choice(PipelineVariableList))
		ps1Content = ps1Content.replace(i, choice(PipelineVariableList))

	return ps1Content


def ObfString(String):

	stringList = ['$(%s)', '(%s)']

	obfStr = ''
	for i in String:
		obfStr += "'" + i + "'+"

	obfStr = obfStr[:-1]

	for i in stringList:
		obfStr = i % obfStr

	return obfStr


def Find_String(ps1Content):
	
	singlePat = "'(.*?)'"

	data = list(filter(None, re.findall(singlePat, ps1Content)))# + 
	for i in set(data):
		# print('\t' + i + '  =>  ' + ObfString(i))
		ps1Content = ps1Content.replace("'" + i + "'", ObfString(i))

	return ps1Content


def ObfVariable():

	charList = list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')

	obfVar = '$'
	for i in range(randint(10, 15)):
		obfVar += choice(charList)

	return obfVar


def Find_Variable(ps1Content):
	pat = '\W(\$\w+)'
	data = re.findall(pat, ps1Content)

	blacklist = ['$?', '$^', '$_', '$env', '$ENV', '$Env', '$args', '$ConfirmPreference', '$ConsoleFileName', '$DebugPreference', '$Error', '$ErrorActionPreference', '$ErrorView', '$ExecutionContext', '$False', '$false', '$FormatEnumerationLimit', '$HOME', '$Host', '$InformationPreference', '$input', '$LASTEXITCODE', '$MaximumAliasCount', '$MaximumDriveCount', '$MaximumErrorCount', '$MaximumFunctionCount', '$MaximumHistoryCount', '$MaximumVariableCount', '$MyInvocation', '$NestedPromptLevel', '$null', '$OutputEncoding', '$PID', '$PROFILE', '$ProgressPreference', '$PSBoundParameters', '$PSCommandPath', '$PSCulture', '$PSDefaultParameterValues', '$PSEdition', '$PSEmailServer', '$PSHOME', '$PSScriptRoot', '$PSSessionApplicationName', '$PSSessionConfigurationName', '$PSSessionOption', '$PSUICulture', '$PSVersionTable', '$PWD', '$ShellId', '$StackTrace', '$True', '$true', '$VerbosePreference', '$WarningPreference', '$WhatIfPreference', '$Position', '$Ocpffset', '$MarshalAs', '$DllName', '$FunctionName', '$EntryPoint', '$ReturnType', '$ParameterTypes', '$NativeCallingConvention', '$Charset', '$SetLastError', '$Module', '$Namespace']

	for i in set(data):
		if i not in blacklist:
			randStr = ObfVariable()
			# print('\t' + i + '  =>  ' + randStr)
			ps1Content = ps1Content.replace(i, randStr)

	return ps1Content


def Find_Func(ps1Content):

	pat = 'function (.*?)[ \(\)]{'
	data = re.findall(pat, ps1Content)

	for i in set(data):
		randStr = ObfVariable().replace('$', '')
		# print('\t' + i.replace('()', '') + '  =>  ' + randStr)
		ps1Content = ps1Content.replace(i.replace('()', ''), randStr + ' ')
		ps1Content = ps1Content.replace('"' + randStr + ' ', '"' + i.replace('()', ''))
		ps1Content = ps1Content.replace(randStr + ' "', i.replace('()', '') + '"')

	return ps1Content


def stripQMark(ps1Content):
	pat = '"(.*?)"'
	pat2 = "'(.*?)'"

	for i in re.findall(pat, ps1Content):
		if i == ' ' or i == '':
			continue
		ps1Content = ps1Content.replace('"' + i + '"', '')

	for i in re.findall(pat2, ps1Content):
		if i == ' ' or i == '':
			continue
		ps1Content = ps1Content.replace("'" + i + "'", '')

	return ps1Content


def allObf(ps1Content):
	# print('Remove_Comments')
	ps1Content = Remove_Comments(ps1Content)
	# print('Resolve_Aliases')
	ps1Content = Resolve_Aliases(ps1Content)
	# print('Find_cmdLet')
	ps1Content = Find_cmdLet(ps1Content)
	# print('Find_NameSpace')
	ps1Content = Find_NameSpace(ps1Content)
	# print('Find_Pipe')
	ps1Content = Find_Pipe(ps1Content)
	# print('Find_PipelineVariable')
	ps1Content = Find_PipelineVariable(ps1Content)
	# print('Find_String')
	ps1Content = Find_String(ps1Content)
	# print('Find_Variable')
	ps1Content = Find_Variable(ps1Content)
	# print('Find_Method')
	ps1Content = Find_Method(ps1Content)
	# print('Find_Func')
	ps1Content = Find_Func(ps1Content)

	return ps1Content



