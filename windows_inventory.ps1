################################
### Script to gather system inventory using WMI
### SOCFortress
### https://www.socfortress.co
### info@socfortress.co
################################
##########
# Script execution triggered by Wazuh Manager, wodles-command, every 24 Hours
# Output converted to JSON and appended to active-responses.log
##########
##########
# Inventory Modules:
# - Basic System Info
# - System Drives Info
# - BIOS Info
# - UEFI Info
# - BitLocker Info
# - Partitions Info
# - Processor(s) Info
# - OS Info
# - Restart Required/Pending
# - Installed Printers Info
# - NICs Info
# - IPv4 Route Table Info
# - Shared Drives Info
# - Installed Software Info
# - Installed HotFixes Info
# - Shared Drives Info
# - System Services Info
# - Local User Accounts
##########
$ErrorActionPreference = "SilentlyContinue"
#Local functions for Querying machine
Function QueryOS ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    [Array]$OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber,Caption, CSNAME, InstallDate, Locale, OSArchitecture, OperatingSystemSKU, OSLanguage,TotalVisibleMemorySize, SerialNumber, Version, ProductType, LastBootUpTime  -Authentication PacketPrivacy -Impersonation Impersonate;Return $OS
    
}

Function QueryBIOS ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    [Array]$BIOS = Get-WmiObject -Class Win32_BIOS -Property SerialNumber  -Authentication PacketPrivacy -Impersonation Impersonate;Return $BIOS
    
}
Function QueryDiskPartition ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    [Array]$Partitions =  Get-WmiObject  -Property Name, Size, PrimaryPartition, BootPartition, Type -Class Win32_DiskPartition -Authentication PacketPrivacy -Impersonation Impersonate;Return $Partitions
    
}
Function QueryBitLocker ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    [Array]$BitLocker =   Get-BitLockerVolume | Select-Object MountPoint, EncryptionMethod, VolumeStatus, VolumeType, ProtectionStatus, LockStatus, EncryptionPercentage, AutoUnlockEnabled, AutoUnlockKeyStored;Return $BitLocker
}
Function QueryPatches ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    [Array]$Patches = get-wmiobject -class Win32_quickfixengineering -Property Description, HotfixID, InstalledOn, InstalledBy, ServicePackInEffect, Status ;Return $Patches
    
}

Function QueryPrinter ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    [Array]$Printers = get-wmiobject -class Win32_Printer -Property CapabilityDescriptions, Caption, Local, Network,Shared, ShareName, Status, TimeOfLastReset,WorkOffline, PortName ;Return $Printers
    
}


Function QueryComputerSystem ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    [Array]$ComputerSystem = get-wmiobject -class Win32_ComputerSystem -Property Name, HypervisorPresent, Manufacturer, Model, UserName ;Return $ComputerSystem
    
}


Function QueryDisk ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    [Array]$Disks = get-wmiobject -class Win32_LogicalDisk -Property Caption, Description, DeviceID, DriveType, FileSystem, Freespace, MediaType, Name, Size, VolumeName ;Return $Disks
    
}

Function QueryApps32bit ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    [Array]$Apps32bit = get-wmiobject -class Win32_InstalledWin32Program -Property Name, Version, Vendor ;Return $Apps32bit
    

}


Function QueryProcessor ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    
    [Array]$Processor = get-wmiobject -class Win32_Processor -Property Name,NumberOfCores,NumberOfLogicalProcessors,Status ;Return $Processor
    

}

Function QueryNetworkAdapter ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
   
    $NIC=@{};$NIC = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Property Description, DefaultIPGateway, DHCPEnabled, DHCPLeaseExpires, DHCPLeaseObtained, DHCPServer, DNSServerSearchOrder, FullDNSRegistrationEnabled, IPAddress, MACAddress -Filter "IPEnabled = True" ;Return $NIC;
    

}

Function QueryIpv4RouteTable ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    [Array]$Ipv4RouteTable = get-wmiobject -class Win32_IP4RouteTable -Property Caption, Destination, Mask, NextHop ;Return $Ipv4RouteTable
    

}

Function QuerySystemServices ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    [Array]$SystemServices = get-wmiobject -class Win32_Service -Property Name, StartMode, State, Status ;Return $SystemServices
    

}
Function QueryLocalUserAccounts ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    [Array]$LocalUserAccounts = get-wmiobject -Class Win32_UserAccount -Filter "LocalAccount=True" -Property Name, FullName, Caption, SID, AccountType ;Return $LocalUserAccounts
    

}
Function ConvertWMIDate ([String]$WMIDate)
{

$WMIDate = [Management.ManagementDateTimeConverter]::ToDateTime($WMIDate)
Return $WMIDate

}

Function PerformDecode ([String]$CodeType,[Int]$Code)
{

Switch ($CodeType){

ProductType
    {
    if($Code -eq 1){$ProductType="Workstation";Return $ProductType}
    elseif ($Code -eq 2){$ProductType="Domain Controller";Return $ProductType}
    elseif ($Code -eq 3){$ProductType="Server";Return $ProductType}
    else {$ProductType="Product code not defined in decode function! Error code 101!";Return $ProductType}
    }
OSLanguage
    {
    if($Code -eq 1030){$OSLanguage="Danish";Return $OSLanguage}
    elseif ($Code -eq 1033){$OSLanguage="English USA";Return $OSLanguage}
    elseif ($Code -eq 1035){$OSLanguage="Finish";Return $OSLanguage}
    elseif ($Code -eq 1044){$OSLanguage="Norwegian Bokmål";Return $OSLanguage}
    elseif ($Code -eq 1053){$OSLanguage="Swedish";Return $OSLanguage}
    elseif ($Code -eq 2057){$OSLanguage="English UK";Return $OSLanguage}
    elseif ($Code -eq 2068){$OSLanguage="Norwegian Nynorsk";Return $OSLanguage}
    else {$OSLanguage="Language code not defined in decode function! Error code 101!";Return $OSLanguage}
    
    }
OperatingSystemSKU
    {
    if($Code -eq 0){$OperatingSystemSKU="PRODUCT_UNDEFINED";Return $OperatingSystemSKU}
    elseif ($Code -eq 1){$OperatingSystemSKU="PRODUCT_ULTIMATE";Return $OperatingSystemSKU}
    elseif ($Code -eq 2){$OperatingSystemSKU="PRODUCT_HOME_BASIC";Return $OperatingSystemSKU}
    elseif ($Code -eq 3){$OperatingSystemSKU="PRODUCT_HOME_PREMIUM";Return $OperatingSystemSKU}
    elseif ($Code -eq 4){$OperatingSystemSKU="PRODUCT_ENTERPRISE";Return $OperatingSystemSKU}
    elseif ($Code -eq 5){$OperatingSystemSKU="PRODUCT_BUSINESS";Return $OperatingSystemSKU}
    elseif ($Code -eq 7){$OperatingSystemSKU="PRODUCT_STANDARD_SERVER";Return $OperatingSystemSKU}
    elseif ($Code -eq 8){$OperatingSystemSKU="PRODUCT_DATACENTER_SERVER";Return $OperatingSystemSKU}
    elseif ($Code -eq 9){$OperatingSystemSKU="PRODUCT_SMALLBUSINESS_SERVER";Return $OperatingSystemSKU}
    elseif ($Code -eq 10){$OperatingSystemSKU="PRODUCT_ENTERPRISE_SERVER";Return $OperatingSystemSKU}
    elseif ($Code -eq 11){$OperatingSystemSKU="PRODUCT_STARTER";Return $OperatingSystemSKU}
    elseif ($Code -eq 12){$OperatingSystemSKU="PRODUCT_DATACENTER_SERVER_CORE";Return $OperatingSystemSKU}
    elseif ($Code -eq 13){$OperatingSystemSKU="PRODUCT_STANDARD_SERVER_CORE";Return $OperatingSystemSKU}
    elseif ($Code -eq 14){$OperatingSystemSKU="PRODUCT_ENTERPRISE_SERVER_CORE";Return $OperatingSystemSKU}
    elseif ($Code -eq 17){$OperatingSystemSKU="PRODUCT_WEB_SERVER";Return $OperatingSystemSKU}
    elseif ($Code -eq 19){$OperatingSystemSKU="PRODUCT_HOME_SERVER";Return $OperatingSystemSKU}
    elseif ($Code -eq 20){$OperatingSystemSKU="PRODUCT_STORAGE_EXPRESS_SERVER";Return $OperatingSystemSKU}
    elseif ($Code -eq 21){$OperatingSystemSKU="PRODUCT_STORAGE_STANDARD_SERVER";Return $OperatingSystemSKU}
    elseif ($Code -eq 22){$OperatingSystemSKU="PRODUCT_STORAGE_WORKGROUP_SERVER";Return $OperatingSystemSKU}
    elseif ($Code -eq 23){$OperatingSystemSKU="PRODUCT_STORAGE_ENTERPRISE_SERVER";Return $OperatingSystemSKU}
    elseif ($Code -eq 24){$OperatingSystemSKU="PRODUCT_SERVER_FOR_SMALLBUSINESS";Return $OperatingSystemSKU}
    elseif ($Code -eq 25){$OperatingSystemSKU="PRODUCT_SMALLBUSINESS_SERVER_PREMIUM";Return $OperatingSystemSKU}
    elseif ($Code -eq 27){$OperatingSystemSKU="PRODUCT_ENTERPRISE_N";Return $OperatingSystemSKU}
    elseif ($Code -eq 28){$OperatingSystemSKU="PRODUCT_ULTIMATE_N";Return $OperatingSystemSKU}
    elseif ($Code -eq 29){$OperatingSystemSKU="PRODUCT_WEB_SERVER_CORE";Return $OperatingSystemSKU}
    elseif ($Code -eq 36){$OperatingSystemSKU="PRODUCT_STANDARD_SERVER_V";Return $OperatingSystemSKU}
    elseif ($Code -eq 37){$OperatingSystemSKU="PRODUCT_DATACENTER_SERVER_V";Return $OperatingSystemSKU}
    elseif ($Code -eq 38){$OperatingSystemSKU="PRODUCT_ENTERPRISE_SERVER_V";Return $OperatingSystemSKU}
    elseif ($Code -eq 39){$OperatingSystemSKU="PRODUCT_DATACENTER_SERVER_CORE_V";Return $OperatingSystemSKU}
    elseif ($Code -eq 40){$OperatingSystemSKU="PRODUCT_STANDARD_SERVER_CORE_V";Return $OperatingSystemSKU}
    elseif ($Code -eq 41){$OperatingSystemSKU="PRODUCT_ENTERPRISE_SERVER_CORE_V";Return $OperatingSystemSKU}
    elseif ($Code -eq 42){$OperatingSystemSKU="PRODUCT_HYPERV";Return $OperatingSystemSKU}
    elseif ($Code -eq 43){$OperatingSystemSKU="PRODUCT_STORAGE_EXPRESS_SERVER_CORE";Return $OperatingSystemSKU}
    elseif ($Code -eq 44){$OperatingSystemSKU="PRODUCT_STORAGE_STANDARD_SERVER_CORE";Return $OperatingSystemSKU}
    elseif ($Code -eq 45){$OperatingSystemSKU="PRODUCT_STORAGE_WORKGROUP_SERVER_CORE";Return $OperatingSystemSKU}
    elseif ($Code -eq 46){$OperatingSystemSKU="PRODUCT_STORAGE_ENTERPRISE_SERVER_CORE";Return $OperatingSystemSKU}
    elseif ($Code -eq 48){$OperatingSystemSKU="PRODUCT_PROFESSIONAL";Return $OperatingSystemSKU}
    elseif ($Code -eq 49){$OperatingSystemSKU="PRODUCT_PROFESSIONAL_N";Return $OperatingSystemSKU}
    elseif ($Code -eq 50){$OperatingSystemSKU="PRODUCT_SB_SOLUTION_SERVER";Return $OperatingSystemSKU}
    elseif ($Code -eq 63){$OperatingSystemSKU="PRODUCT_SMALLBUSINESS_SERVER_PREMIUM_CORE";Return $OperatingSystemSKU}
    elseif ($Code -eq 64){$OperatingSystemSKU="PRODUCT_CLUSTER_SERVER_V";Return $OperatingSystemSKU}
    elseif ($Code -eq 97){$OperatingSystemSKU="PRODUCT_CORE_ARM";Return $OperatingSystemSKU}
    elseif ($Code -eq 101){$OperatingSystemSKU="PRODUCT_CORE";Return $OperatingSystemSKU}
    elseif ($Code -eq 103){$OperatingSystemSKU="PRODUCT_PROFESSIONAL_WMC";Return $OperatingSystemSKU}
    elseif ($Code -eq 104){$OperatingSystemSKU="PRODUCT_MOBILE_CORE";Return $OperatingSystemSKU}
    elseif ($Code -eq 123){$OperatingSystemSKU="PRODUCT_IOTUAP";Return $OperatingSystemSKU}
    elseif ($Code -eq 143){$OperatingSystemSKU="PRODUCT_DATACENTER_NANO_SERVER";Return $OperatingSystemSKU}
    elseif ($Code -eq 144){$OperatingSystemSKU="PRODUCT_STANDARD_NANO_SERVER";Return $OperatingSystemSKU}
    elseif ($Code -eq 147){$OperatingSystemSKU="PRODUCT_DATACENTER_WS_SERVER_CORE";Return $OperatingSystemSKU}
    elseif ($Code -eq 148){$OperatingSystemSKU="PRODUCT_STANDARD_WS_SERVER_CORE";Return $OperatingSystemSKU}
    else {$OperatingSystemSKU="SKU not defined in decode function! Error code 101!";Return $OperatingSystemSKU}

}
 
MediaType
    {
    if($Code -eq 0){$MediaType="Unknown media type";Return $MediaType}
    elseif ($Code -eq 11){$MediaType="Removeable media";Return $MediaType}
    elseif ($Code -eq 12){$MediaType="Fixed disk/drive";Return $MediaType}
    else {$MediaType="Media type not defined in decode function! Error code 101!";Return $MediaType}
    }
DriveType
    {
    if($Code -eq 0){$DriveType="Unknown drive type";Return $DriveType}
    elseif ($Code -eq 1){$DriveType="No root directory";Return $DriveType}
    elseif ($Code -eq 2){$DriveType="Removeable disk";Return $DriveType}
    elseif ($Code -eq 3){$DriveType="Local disk";Return $DriveType}
    elseif ($Code -eq 4){$DriveType="Network disk";Return $DriveType}
    elseif ($Code -eq 5){$DriveType="Compact disk";Return $DriveType}
    elseif ($Code -eq 6){$DriveType="RAM disk";Return $DriveType}
    else {$DriveType="Drive type not defined in decode function! Error code 101!";Return $DriveType}
    }
Default 
    {
    Write-host "Undefined Value in decode switch function"
    }
}
}
#Write inventory output to Active Response File
Function WriteLogFile ([String]$LogFileText)
{
$count = 0
echo  $LogText | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
}
#Inventory Module: Restart. Check if system restart is required
Function checkRestartRequired ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials){
[boolean]$PendingRestart = $false
[boolean]$PendingRestart1 = $false
[boolean]$PendingRestart2 = $false

    $PendingRestart1 = $RestartRequired = Get-ChildItem -Path 'REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\' 
                       $RestartRequired = $RestartRequired.Name 
                        foreach ($RestartRequired in $RestartRequired)
                        {
                            if($RestartRequired -match "Reboot")
                            {
                                $PendingRestart1 = $true
                                Return $PendingRestart1
                            }
                        }
                      
                    
     $PendingRestart2 = $RestartRequired = Get-ChildItem -Path 'REGISTRY::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\' 
                    $RestartRequired = $RestartRequired.Name 
                        foreach ($RestartRequired in $RestartRequired)
                        {
                            if($RestartRequired -match "Reboot")
                            {
                                $PendingRestart1 = $true
                                Return $PendingRestart2
                            }
                        }
if(($PendingRestart1 -eq $true) -or ($PendingRestart2 -eq $true))
{
$PendingRestart = $true
}

return $PendingRestart
   
}
#Inventory Module: Shares.
Function QueryComputerShares ([String]$Machine,[System.Management.Automation.PSCredential]$Credentials)
{
    
    $Shares = @{}; $Shares = get-wmiobject -class win32_share -Property Name,Path,Description ;Return $Shares
    
}
#Main functions and and detailed implementation of script is below:
Try{
$WindowInstallPath = $env:windir
$ScriptStartDate = Get-Date
$TargetMachine = Get-ComputerInfo
$TargetMachine = $TargetMachine.CsName
#######Call for functions
#OS Info
                    $OSinfo = QueryOS -Machine $TargetMachine
                    $OSBuildNumber = $OSinfo.BuildNumber 
                    $OSCaption  = $OSinfo.Caption  
                    $OSCSName    = $OSinfo.CSName 
                    $OSInstallDate = $OSinfo.InstallDate 
                    $OSLastBootUpTime = $OSinfo.LastBootUpTime       
                    $OSLocale = $OSinfo.Locale      # 0409
                    $OSOperatingSystemSKU = $OSinfo.OperatingSystemSKU 
                    $OSOSArchitecture = $OSinfo.OSArchitecture  
                    $OSOSLanguage = $OSinfo.OSLanguage  
                    $OSProductType = $OSinfo.ProductType   
                    $OSSerialNumber = $OSinfo.SerialNumber  
                    $OSTotalVisibleMemorySize = $OSinfo.TotalVisibleMemorySize 
                    $OSVersion = $OSinfo.Version  

                   #Formatting of OS information        
                    $OSTotalVisibleMemorySize  = $OSTotalVisibleMemorySize/1048576
                    $OSTotalVisibleMemorySize = [math]::Round($OSTotalVisibleMemorySize)
                    $OSLastBootUpTime = ConvertWMIDate -WMIDate $OSLastBootUpTime
                    #$OSLastBootUpTime = $OSLastBootUpTime.date
                    $OSInstallDate = ConvertWMIDate -WMIDate $OSInstallDate
                   #Conversion Product Code
                    $OSProductType = PerformDecode -CodeType "ProductType" -Code $OSProductType
                   #Conversion OSLanguage
                    $OSOSLanguage = PerformDecode -CodeType "OSLanguage" -Code $OSOSLanguage
                   #Conversion OperatingSystemSKU
                    $OSOperatingSystemSKU = PerformDecode -CodeType "OperatingSystemSKU" -Code $OSOperatingSystemSKU
                    $LogText = @{inventory_module="operating_system"; os_system_name="$OSCSName"; os_type="$OSCaption"; os_install_date="$OSInstallDate"; os_boot_time="$OSLastBootUpTime"; os_locale="$OSLocale"; os_build_number="$OSBuildNumber"; os_sku="$OSOperatingSystemSKU"; os_architecture="$OSOSArchitecture"; os_lang="$OSOSLanguage"; os_product_type="$OSProductType"; os_sn="$OSSerialNumber"; os_system_memory="$OSTotalVisibleMemorySize"; os_version="$OSVersion"}
                   WriteLogFile -LogFileText $LogText
Remove-Variable  OSinfo,OSBuildNumber,OSCaption,OSCSName,OSInstallDate,OSLastBootUpTime,OSLocale,OSOperatingSystemSKU,OSOSArchitecture,OSOSLanguage,OSProductType,OSSerialNumber,OSTotalVisibleMemorySize,OSVersion,OSBuildNumber,OSCaption,OSCSName,OSInstallDate,OSLastBootUpTime,OSLocale,OSOperatingSystemSKU,OSOSArchitecture,OSOSLanguage,OSProductType,OSSerialNumber,OSTotalVisibleMemorySize,OSVersion -ErrorAction SilentlyContinue
#System Info
                    $ComputerSystemInfo = QueryComputerSystem -Machine $TargetMachine
                    $CSIHypervisorPresent = $ComputerSystemInfo.HypervisorPresent 
                    $CSIManufacturer = $ComputerSystemInfo.Manufacturer  
                    $CSIModel = $ComputerSystemInfo.Model        
                    $CSIName = $ComputerSystemInfo.Name     
                    $CSIUserName = $ComputerSystemInfo.UserName     
                    $LogText = @{inventory_module="computer_info"; system_manufacturer="$CSIManufacturer"; system_model="$CSIModel"; system_owner="$CSIUserName"}
                    WriteLogFile -LogFileText $LogText                   
#Disk information
                    $DiskInfo = QueryDisk -Machine $TargetMachine
         
                     if($DiskInfo.count -ge "1")
                        {
                            foreach($DiskInfo in $DiskInfo)
                            {
                             $DICaption = $DiskInfo.Caption    
                             $DIDescription = $DiskInfo.Description
                             $DIDeviceID = $DiskInfo.DeviceID
                             $DIDriveType = $DiskInfo.DriveType 
                             $DIDriveType = PerformDecode -Code $DIDriveType -CodeType "Drivetype"
                             $DIFileSystem = $DiskInfo.FileSystem
                             $DIFreeSpace = $DiskInfo.FreeSpace
                             $DIMediaType = $DiskInfo.MediaType
                             $DIMediaType = PerformDecode -Code $DIMediaType -CodeType "Mediatype"
                             $DIName = $DiskInfo.Name
                             $DISize = $DiskInfo.Size
                             $DIVolumeName = $DiskInfo.VolumeName
                              #Calculate free space
                                $Freespace = [math]::Round($DIFreeSpace/1gb)
                                $Size = [math]::Round($DISize/1gb)
                                $FreespaceValue = $Freespace.ToString()
                                $SizeValue = $Size.ToString()
                                $FreespaceValue = $FreespaceValue + "GB"
                                $SizeValue = $SizeValue + "GB"
                                $LogText = @{inventory_module="drives"; drive_caption="$DICaption"; drive_description="$DIDescription"; drive_type="$DIDriveType"; drive_filesystem="$DIFileSystem"; drive_volume_name="$DIVolumeName"; drive_size="$SizeValue"; drive_free_space="$FreespaceValue"}
                                WriteLogFile -LogFileText $LogText
                            }
                         }
#BIOS information            
                    $BiosInfo = QueryBIOS -Machine $TargetMachine
                    $BiosInfoValue = $BiosInfo.SerialNumber
                    $LogText = @{inventory_module="bios"; bios_sn="$BiosInfoValue"}
                    WriteLogFile -LogFileText $LogText
                    $ProcessorInfo = QueryProcessor -Machine $TargetMachine
                            foreach($ProcessorInfo in $ProcessorInfo)
                            {
                                $ProcName = $ProcessorInfo.Name
                                $ProcNumCores = $ProcessorInfo.NumberOfCores
                                $ProcNumLogicalProcs = $ProcessorInfo.NumberOfLogicalProcessors
                                $ProcStatus = $ProcessorInfo.Status
                                $LogText = @{inventory_module="processor"; processor_name="$ProcName"; processor_cores="$ProcNumCores"; processor_logical_nbr="$ProcNumLogicalProcs"; processor_status="$ProcStatus"}
                                WriteLogFile -LogFileText $LogText
                                
                            }
#Partitions Information            
$PartitionsInfo = QueryDiskPartition -Machine $TargetMachine
        foreach($PartitionsInfo in $PartitionsInfo)
        {
            $PartitionName = $PartitionsInfo.Name
            $PrimaryPartition = $PartitionsInfo.PrimaryPartition
            $BootPartition = $PartitionsInfo.BootPartition
            $Type = $PartitionsInfo.Type
            $LogText = @{inventory_module="partitions"; partition_name="$PartitionName"; primary_partition="$PrimaryPartition"; boot_partition="$BootPartition"; partition_type="$Type"}
            WriteLogFile -LogFileText $LogText
            
        }
#BitLocker Information            
$BitLockerInfo = QueryBitLocker -Machine $TargetMachine
        foreach($BitLockerInfo in $BitLockerInfo)
        {
            $MountPoint = $BitLockerInfo.MountPoint
            $EncryptionMethod = $BitLockerInfo.EncryptionMethod
            $VolumeStatus = $BitLockerInfo.VolumeStatus
            $VolumeType = $BitLockerInfo.VolumeType
            $ProtectionStatus = $BitLockerInfo.ProtectionStatus
            $LockStatus = $BitLockerInfo.LockStatus
            $EncryptionPercentage = $BitLockerInfo.EncryptionPercentage
            $AutoUnlockEnabled = $BitLockerInfo.AutoUnlockEnabled
            $AutoUnlockKeyStored = $BitLockerInfo.AutoUnlockKeyStored
            $LogText = @{inventory_module="bitlocker"; mount_point="$MountPoint"; encryption_method="$EncryptionMethod"; volume_status="$VolumeStatus"; volume_type="$VolumeType"; protection_status="$ProtectionStatus"; lock_status="$LockStatus"; encryption_percentage="$EncryptionPercentage"; auto_unlock_enabled="$AutoUnlockEnabled"; auto_unlock_key_stored="$AutoUnlockKeyStored"}
            WriteLogFile -LogFileText $LogText
        }

#Pending Restrat information
                    $PendingRestart = checkRestartRequired -Machine $TargetMachine
                        $LogText = @{inventory_module="restart"; restart_pending="$PendingRestart"}
                        WriteLogFile -LogFileText $LogText
#UEFI information
$UEFI = Confirm-SecureBootUEFI
$LogText = @{inventory_module="uefi"; uefi_enabled="$UEFI"}
WriteLogFile -LogFileText $LogText

#Shared Drives information                    
                    $Shares = QueryComputerShares -Machine $TargetMachine
                    if($Shares.Count -ge "1")
                        {
                            foreach($Shares in $Shares)
                            {
                                              $SDescription = $Shares.Description
                                              $SName = $Shares.Name  
                                              $Spath = $Shares.Path  
                                              $LogText = @{inventory_module="shares"; share_name="$SName"; share_description="$SDescription"; share_path="$Spath"} 
                                              WriteLogFile -LogFileText $LogText
                            }
                        }
Remove-Variable PendingRestart,Shares,SName, SDescription, Spath -ErrorAction SilentlyContinue
#Installed Software information
                    $AppsInfo = QueryApps32bit -Machine $TargetMachine
                    if($AppsInfo.count -ge "1")
                        {
                            foreach($AppsInfo in $AppsInfo)
                            {
                                $AppName = $AppsInfo.Name
                                $AppVendor = $AppsInfo.Vendor
                                $AppVersion = $AppsInfo.Version
                                #Write-Host $AppName,$AppVendor,$AppVersion
                                $LogText = @{inventory_module="software"; software_name="$AppName"; software_vendor="$AppVendor"; software_version="$AppVersion"} 
                                WriteLogFile -LogFileText $LogText
                            }
                         }
Remove-Variable AppsInfo,AppName,AppVendor,AppVersion -ErrorAction SilentlyContinue
#HotFix information
                    $PatchInfo = QueryPatches -Machine $TargetMachine
                     if($PatchInfo.count -ge "1")
                        {
                             foreach($PatchInfo in $PatchInfo)
                                {
                                $HFDescription = $PatchInfo.Description
                                $HFHotfixID = $PatchInfo.HotfixID
                                $HFInstalledOn = $PatchInfo.InstalledOn
                                $HFInstalledBy = $PatchInfo.InstalledBy
                                $HFServicePackInEffect = $PatchInfo.ServicePackInEffect
                                $HFStatus = $PatchInfo.Status
                                $LogText = @{inventory_module="hotfix"; hotfix_description="$HFDescription"; hotfix_ID="$HFHotfixID"; hotfix_install_date="$HFInstalledOn"; hotfix_installed_by="$HFInstalledBy"; hotfix_service_pack="$HFServicePackInEffect"; hotfix_status="$HFStatus"} 
                                WriteLogFile -LogFileText $LogText
                                Start-Sleep -Seconds 1
                                }
                        }
Remove-Variable PatchInfo,HFDescription,HFHotfixID,HFInstalledOn, HFInstalledBy, HFServicePackInEffect,HFStatus -ErrorAction SilentlyContinue
#Printers information                   
                    $PrinterInfo = QueryPrinter -Machine $TargetMachine
                    if($PrinterInfo.count -ge "1")
                        {
                             foreach($PrinterInfo in $PrinterInfo)
                                {
                                    $PrinterCapabilityDescriptions = $PrinterInfo.CapabilityDescriptions 
                                    $PrinterCaption = $PrinterInfo.Caption   
                                    $PrinterLocal = $PrinterInfo.Local  
                                    $PrinterNetwork = $PrinterInfo.Network   
                                    $PrinterPortName = $PrinterInfo.PortName    
                                    $PrinterShared = $PrinterInfo.Shared      
                                    $PrinterShareName = $PrinterInfo.ShareName    
                                    $PrinterStatus = $PrinterInfo.Status     
                                    $PrinterTimeOfLastReset = $PrinterInfo.TimeOfLastReset 
                                    $PrinterWorkOffline = $PrinterInfo.WorkOffline
                                    $LogText = @{inventory_module="printers"; printer_name="$PrinterCaption"; printer_capabilities="$PrinterCapabilityDescriptions"; printer_driver="$PrinterLocal"; printer_network_driver="$PrinterNetwork"; printer_port="$PrinterPortName"; printer_is_shared="$PrinterShared"; printer_shared_name="$PrinterShareName"; printer_status="$PrinterStatus"; printer_last_reset="$PrinterTimeOfLastReset"; printer_is_offline="$PrinterWorkOffline"}     
                                    WriteLogFile -LogFileText $LogText
                             }
                            
                       }
Remove-Variable PrinterInfo,PrinterCaption,PrinterCapabilityDescriptions,PrinterLocal,PrinterNetwork,PrinterPortNamePrinterShared,PrinterShareName,PrinterStatus,PrinterTimeOfLastReset,PrinterWorkOffline -ErrorAction SilentlyContinue
#NIC information
                    $NICsInfo = QueryNetworkAdapter -Machine $TargetMachine
                    if($NICsInfo.__PROPERTY_COUNT -ge "1")
                        {
                            foreach($NICsInfo in $NICsInfo)
                            {
                                $NicDescription = $NICsInfo.Description
                                $NicDHCPEnabled = $NICsInfo.DHCPEnabled
                                if($NicDHCPEnabled -eq "True")
                                { 
                                    $NicDHCPLeaseExpires = $NICsInfo.DHCPLeaseExpires
                                    $NicDHCPLeaseExpires =  ConvertWMIDate -WMIDate $NicDHCPLeaseExpires
                                    $NicDHCPLeaseObtained = $NICsInfo.DHCPLeaseObtained
                                    $NicDHCPLeaseObtained = ConvertWMIDate -WMIDate $NicDHCPLeaseObtained
                                    $NicDHCPServer = $NICsInfo.DHCPServer
                                }
                                else
                                {
                                    $NicDHCPLeaseExpires = 'N/A'
                                    $NicDHCPLeaseExpires =  'N/A'
                                    $NicDHCPLeaseObtained = 'N/A'
                                    $NicDHCPLeaseObtained = 'N/A'
                                    $NicDHCPServer = 'N/A'
                                }
                                $NicDNSServerSearchOrder = $NICsInfo.DNSServerSearchOrder
                                $NicFullDNSRegistrationEnabled = $NICsInfo.FullDNSRegistrationEnabled
                                $NicIPAddress = $NICsInfo.IPAddress
                                $NicMACAddress = $NICsInfo.MACAddress
                                $LogText = @{inventory_module="nic"; nic_description="$NicDescription"; nic_dhcp_enabled="$NicDHCPEnabled"; nic_lease_expires_on="$NicDHCPLeaseExpires"; nic_lease_obtained="$NicDHCPLeaseObtained"; nic_dhcp_server="$NicDHCPServer"; nic_dns_servers="$NicDNSServerSearchOrder"; nic_dns_registrarion_enabled="$NicFullDNSRegistrationEnabled"; nic_ip_address="$NicIPAddress"; nic_mac_address="$NicMACAddress"}     
                                WriteLogFile -LogFileText $LogText
                            }
                    
                        }
#IPv4 Route Table information
                    $RouteInfo = QueryIpv4RouteTable -Machine $TargetMachine
                    if($RouteInfo.count -ge "1")
                        {
                             foreach($RouteInfo in $RouteInfo)
                                {
                                    $RouteInfoCaption = $RouteInfoInfo.Caption   
                                    $RouteInfoDestination = $RouteInfo.Destination  
                                    $RouteInfoMask = $RouteInfo.Mask   
                                    $RouteInfoNextHop = $RouteInfo.NextHop    
                                    $LogText = @{inventory_module="route_table"; route_name="$RouteInfoCaption"; route_destination="$RouteInfoDestination"; route_mask="$RouteInfoMask"; route_nexthop="$RouteInfoNextHop"}     
                                    WriteLogFile -LogFileText $LogText
                             }
                            
                       }
Remove-Variable RouteInfoCaption,RouteInfoDestination,RouteInfoMask,RouteInfoNextHop -ErrorAction SilentlyContinue
#System Services information                       
                       $SystemServices = QuerySystemServices -Machine $TargetMachine
                       if($SystemServices.count -ge "1")
                           {
                                foreach($SystemService in $SystemServices)
                                   {
                                       $SystemServiceName = $SystemService.Name   
                                       $SystemServiceStartMode = $SystemService.StartMode  
                                       $SystemServiceState = $SystemService.State   
                                       $SystemServiceStatus = $SystemService.Status    
                                       $LogText = @{inventory_module="system_services"; service_name="$SystemServiceName"; service_start_mode="$SystemServiceStartMode"; service_state="$SystemServiceState"; service_status="$SystemServiceStatus"}     
                                       WriteLogFile -LogFileText $LogText
                                }
                               
                          }
Remove-Variable SystemServiceName,SystemServiceStartMode,SystemServiceState,SystemServiceStatus -ErrorAction SilentlyContinue
#Local User Accounts
                        $LocalUserAccounts = QueryLocalUserAccounts -Machine $TargetMachine
                        if($LocalUserAccounts.count -ge "1")
                            {
                                foreach($LocalUserAccount in $LocalUserAccounts)
                                    {
                                        $LocalUserAccountName = $LocalUserAccount.Name   
                                        $LocalUserAccountFullName = $LocalUserAccount.FullName  
                                        $LocalUserAccountCaption = $LocalUserAccount.Caption   
                                        $LocalUserAccountSID = $LocalUserAccount.SID    
                                        $LocalUserAccountAccountType = $LocalUserAccount.AccountType    
                                        $LogText = @{inventory_module="local_user_accounts"; user_account_name="$LocalUserAccountName"; user_account_fullname="$LocalUserAccountFullName"; user_account_caption="$LocalUserAccountCaption"; user_account_sid="$LocalUserAccountSID"; user_account_type="$LocalUserAccountAccountType"}     
                                        WriteLogFile -LogFileText $LogText
                                }
                                
                        }
Remove-Variable LocalUserAccountName,LocalUserAccountFullName,LocalUserAccountCaption,LocalUserAccountSID,LocalUserAccountAccountType -ErrorAction SilentlyContinue
#Windows Defender Settings
$WindowsDefenderSettings = Get-MpPreference
$LogText = @{inventory_module="windows_defender"; cloud_block_level=$WindowsDefenderSettings.CloudBlockLevel; cloud_extended_timeout=$WindowsDefenderSettings.CloudExtendedTimeout; folder_acc_allowed_apps=$WindowsDefenderSettings.ControlledFolderAccessAllowedApplications; folder_acc_protected_folders=$WindowsDefenderSettings.ControlledFolderAccessProtectedFolders; disable_archive_scanning=$WindowsDefenderSettings.DisableArchiveScanning; disable_auto_exclusions=$WindowsDefenderSettings.DisableAutoExclusions; disable_behavior_monitoring=$WindowsDefenderSettings.DisableBehaviorMonitoring; disable_catchup_full_scan=$WindowsDefenderSettings.DisableCatchupFullScan; disable_catchup_quick_scan=$WindowsDefenderSettings.DisableCatchupQuickScan; disable_email_scanning=$WindowsDefenderSettings.DisableEmailScanning; disable_real_time_monitoring=$WindowsDefenderSettings.DisableRealtimeMonitoring; disable_removable_drive_scanning=$WindowsDefenderSettings.DisableRemovableDriveScanning; disable_network_drives_full_scan_=$WindowsDefenderSettings.DisableScanningMappedNetworkDrivesForFullScan; disable__network_files_scan=$WindowsDefenderSettings.DisableScanningNetworkFiles; disable_script_scanning=$WindowsDefenderSettings.DisableScriptScanning; enable_control_folder_access=$WindowsDefenderSettings.EnableControlledFolderAccess; enable_network_protection=$WindowsDefenderSettings.EnableNetworkProtection; exclusion_extension=$WindowsDefenderSettings.ExclusionExtension; exclusion_path=$WindowsDefenderSettings.ExclusionPath; exclusion_process=$WindowsDefenderSettings.ExclusionProcess; pua_protection=$WindowsDefenderSettings.PUAProtection; real_time_scan_direction=$WindowsDefenderSettings.RealTimeScanDirection; scan_parameters=$WindowsDefenderSettings.ScanParameters; severe_threat_default_action=$WindowsDefenderSettings.SevereThreatDefaultAction; signature_schedule_day=$WindowsDefenderSettings.SignatureScheduleDay; signature_schedule_time=$WindowsDefenderSettings.SignatureScheduleTime; signature_update_catchup_interval=$WindowsDefenderSettings.SignatureUpdateCatchupInterval; signature_update_interval=$WindowsDefenderSettings.SignatureUpdateInterval; submit_samples_content=$WindowsDefenderSettings.SubmitSamplesConsent; ui_lockdown=$WindowsDefenderSettings.UILockdown; unknown_threat_default_action=$WindowsDefenderSettings.UnknownThreatDefaultAction}
WriteLogFile -LogFileText $LogText
Remove-Variable WindowsDefenderSettings
}
Catch 
{}
