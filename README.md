# cisco-documentation

Documentation Method for Cisco Devices using excel.

## Requirements

- python3 (3.9)
- pip
- cisco-documentation

## Installation

```bash
python3.9 -m pip install cisco-documentation
```

## Updating

```bash
pip install --upgrade --upgrade-strategy eager cisco-documentation
```

## Usage

For CiscoDocumentation

- Update switch-list.txt with a complete list of switches.
  - Device types supported include cisco_ios (ssh), cisco_ios_telnet (telnet)
  - Cisco s300 will need additional changes before it will work.
- Optional: Create load-credentials.txt to load the keychain with credentials for all switches. `cisco-documentation --load-creds /dir/to/creds.txt`
- Run cisco-documentation.
```bash
usage: cisco-documentation [-h] [--excel-template] [--switch-list SWITCH_LIST] [--load-creds LOAD_CREDS] [--output-dir OUTPUT_DIR] [--fetch-info] [--parse-info] [--update-wireshark-oui]
                           [--update-excel UPDATE_EXCEL]

optional arguments:
  -h, --help            show this help message and exit
  --excel-template      Create the excel documentation template in the cwd.
  --switch-list SWITCH_LIST
                        Specify the switch list to use to collect documentation.
  --load-creds LOAD_CREDS
                        Load credentials into the keystore from this text document. (switch-ip,username,password)
  --output-dir OUTPUT_DIR
                        Set the output directory for switch configs, arp table output, etc.
  --fetch-info          Fetch information from the switches (outputs to OUTPUT_DIR/output.json)
  --parse-info          Parses stored info from OUTPUT_DIR/output.json and outputs OUTPUT_DIR/output.csv
  --update-wireshark-oui
                        This updates the wireshark oui list to identify vendors based on the device mac address.
  --update-excel UPDATE_EXCEL
                        This is the filename to update the 'SWITCHES' and 'ARP' sheets of the specified workbook automatically. This perminently erases the current 'SWITCHES' worksheet. This
                        only appends values to the 'ARP' sheet.

```

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

## Building and installing from source

```bash
python3.9 -m pip uninstall cisco-documentation -y
rm dist/cisco_documentation-*-py2.py3-none-any.whl
python3.9 setup.py bdist_wheel --universal
python3.9 -m pip install dist/cisco_documentation-*-py2.py3-none-any.whl
# To upload to pypi
twine upload dist/*
```

## Changelog

### 0.0.8
- Fixed an over-indentation of the arp table generation causing large files.
- Changed the arp_output.csv to be tab-delimited for easier copy/paste to excel.

### 0.0.7
- Added better error handling - still writes to output.json if a single connection fails.
- Changed section to support fetching cisco specific information via telnet.

### 0.0.6
- Added config-merge command.
- Added port-descriptions command.
- Made additional functions to re-use more code.
- Added jinja-merge command for templating switch configurations.

### 0.0.5
- Updated readme to fix some outdated information.
- Updated the --help to add some context.
- Updated the wireshark_oui.txt file.
- Added an option to update the wireshark_oui.txt file. 
- Fixed the get_oui_dict function to return the generated oui_dict.
- Added a step for creation of arp_output.csv output with the arp information.
- Removed aiomultiprocess from requirements.
- Added option to update an excel file directly.

