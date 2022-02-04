## Intro

Windows Powershell script to collect inventory items and send to Wazuh Manager.

The script is based on WMI-GET calls and all output is appended to Wazuh's active responses log file.


## Windows Inventory - Categories

computer_info

operating_system

processor

bios

drives

uefi

bitlocker

partitions

shares

nic

route_table

printers

software

hotfix

pending restart

system_services

local_user_accounts


## Wazuh Capability:

Wodle Command configured to run periodic inventory colelction.

Wazuh remote commands execution must be enabled on the Windows Agent.

Edit /var/ossec/etc/shared/**_your_windows_group_**/agent.conf and add the remote command:


```
    <wodle name="command">
      <disabled>no</disabled>
      <tag>windows_inventory</tag>
      <command>Powershell.exe -executionpolicy bypass -File "C:\Program Files\Sysinternals\windows_inventory.ps1"</command>
      <interval>24h</interval>
      <ignore_output>yes</ignore_output>
      <run_on_start>yes</run_on_start>
      <timeout>0</timeout>
    </wodle>
    
```

(Change -File param as per your settings)

Wazuh Rules to decode inventory items:


```
<group name="windows,">
 <rule id="205001" level="3">
    <field name="inventory_module">\.+</field>
    <description>Windows System Inventory - $(inventory_module)</description>
    <options>no_full_log</options>
    <group>inventory,</group>
  </rule>
</group>

```
