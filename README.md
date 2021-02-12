# cisco_documentation

Old Automated Documentation Method for Cisco Devices

This is no longer maintained. New processes are in development for documentation.

# Requirements

- python3 (3.9)
- ciscoconfparse
- netmiko
- ntc-templates

# Usage

For CiscoDocumentation

- Update switch_list.txt with a complete list of switches.
  - Device types supported include cisco_ios (ssh), cisco_ios_telnet (telnet), and cisco_s300 (ssh).
- Run the .exe, or run python3.9 ./CiscoDocumentation.py
- Select 'y' to use the switch_list.txt as input.
- This will output the arp tables from the switches, as well as the devices connected to each port, and port statuses to output.csv

For RunCommands

- This is a simple script to run multiple commands on the switches in switch_list.txt
  - Note: RunCommands.py does not use multiprocessing, and RunCommands2.py has not been maintained, but should still be operational.
- Run python3.9 ./RunCommands.py
- Enter commands separated by ~.
  - For example, to configure spanning-tree mode on all switches in switch_list.txt you could run `conf t~spanning-tree mode mst~end~wr`
    
## Updating the Excel Spreadsheet

- Update the ARP sheet with the output from arp_output.txt. Also add the output from arp-scan if there are devices missing (if a device isn't communicating over the l3 switch, or there is no l3 switch in the network, these devices will not exist in the arp table.)
  - If devices don't communicate over the gateway, their arp entries will not exist on the l3 switch. Using nmap beforehand from a separate subnet will populate the arp table on this switch - assuming devices are properly programed with a default gateway.
- Copy the output from output.txt into the SWITCHES sheet. This will update formulas used to the right of the output to look up device information from each sheet.
- Device information should be contained in a sheet named after each l2 network. 
- L2 networks should be named, vlans/ranges assigned on the OVERVIEW sheet.

