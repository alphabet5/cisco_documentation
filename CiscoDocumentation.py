import netmiko
import textfsm
from csv import reader
import traceback
import pickle
import time
import socket
from copy import deepcopy

def mac_to_bits(mac_address):
    return int(mac_address.replace(':', '').replace('.', ''), 16)


def mac_subnet(mac_address, subnet):
    mac = mac_to_bits(mac_address)
    low = mac_to_bits(subnet.partition('/')[0])
    high = mac_to_bits(subnet.partition('/')[0]) + int('1' * (48 - int(subnet.partition('/')[2])), 2)
    if mac >= low and mac <= high:
        return True
    else:
        return False


def normalize_mac(mac_address):
    return mac_address.upper().replace(":", "").replace(".", "")


def load_wireshark_oui():
    try:
        import requests
        url = 'https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf'
        myfile = requests.get(url)
        open('../../../Downloads/SSH/wireshark_oui_dl.txt', 'wb').write(myfile.content)
        f_in = open('../../../Downloads/SSH/wireshark_oui_dl.txt', 'r')
        oui = filter(None, (line.partition('#')[0].rstrip() for line in f_in))
        oui_dict = dict()
        for line in oui:
            part = line.partition('\t')
            if "IEEE Registration Authority" not in part[2]:
                mac_prefix = part[0].replace(':', '').replace('.', '')
                if len(mac_prefix) == 6:
                    oui_dict[mac_prefix] = part[2].replace('\t', ', ')
                else:
                    if mac_prefix[0:6] not in oui_dict.keys():
                        oui_dict[mac_prefix[0:6]] = dict()
                    oui_dict[mac_prefix[0:6]][part[0]] = part[2].replace('\t', ', ')
    except:
        f_in = open('wireshark_oui.txt', 'r')
        oui = filter(None, (line.partition('#')[0].rstrip() for line in f_in))
        oui_dict = dict()
        for line in oui:
            part = line.partition('\t')
            if "IEEE Registration Authority" not in part[2]:
                mac_prefix = part[0].replace(':', '').replace('.', '')
                if len(mac_prefix) == 6:
                    oui_dict[mac_prefix] = part[2].replace('\t', ', ')
                else:
                    if mac_prefix[0:6] not in oui_dict.keys():
                        oui_dict[mac_prefix[0:6]] = dict()
                    oui_dict[mac_prefix[0:6]][part[0]] = part[2].replace('\t', ', ')
    finally:
        return oui_dict


def oui_lookup(mac_address, oui_dict=None):
    mac_address = mac_address.replace(':', '').replace('.', '')
    if oui_dict is None:
        oui_dict = load_wireshark_oui()
    if mac_address[0:6] in oui_dict.keys():
        if type(oui_dict[mac_address[0:6]]) == str:
            return oui_dict[mac_address[0:6]]
        else:
            for subnet, company in oui_dict[mac_address[0:6]].items():
                if mac_subnet(mac_address, subnet):
                    return company
    else:
        return "(Unknown)"


def normalize_linefeeds(self, a_string):
    """Convert '1m' or '\x1b[0m' or '\x1b[m' or '\x1b[' or '\x1b[K'to '\n, and remove extra '\r's in the text."""
    newline = re.compile(r'(1m|7m\%|\x1b|\[0m|\[J|\[m)|\[K|\[')
    return newline.sub(self.RESPONSE_RETURN, a_string).replace('\r', '')


def get_interface_vlans(config, syntax):
    from ciscoconfparse import CiscoConfParse
    interfaces = list()
    parse = CiscoConfParse(config.splitlines(), syntax=syntax)
    for interface_obj in parse.find_objects('^interface'):
        if not interface_obj.is_virtual_intf:
            interface = {'name': None, 'mode': None, 'access-vlan': None, 'trunk-vlans': None, 'native-vlan': None,
                         'tagged-native-vlan': None}
            interface_name = normalize_interface_names(interface_obj.re_match_typed(r'^interface\s+(\S.+?)$'))
            interface_mode = interface_obj.re_match_iter_typed(r'switchport mode (.*)', recurse=True)
            interface_access_vlan = interface_obj.re_match_iter_typed(r'switchport access vlan (.*)', recurse=True)
            interface_trunk_vlans = interface_obj.re_match_iter_typed(r'switchport trunk allowed vlan.*? (\d.*)',
                                                                      recurse=True).split(',')
            interface_native_vlan = interface_obj.re_match_iter_typed(r'switchport trunk native vlan (\d*)',
                                                                      recurse=True)
            interface_tagged_native_vlan = 'vlan dot1q tag native' in config
            interfaces.append({'name': interface_name,
                               'mode': interface_mode,
                               'access-vlan': interface_access_vlan,
                               'trunk-vlans': interface_trunk_vlans,
                               'native_vlan': interface_native_vlan,
                               'tagged-native-vlan': interface_tagged_native_vlan})
    return interfaces


def get_interface_description(config, syntax):
    from ciscoconfparse import CiscoConfParse
    interfaces = list()
    parse = CiscoConfParse(config.splitlines(), syntax=syntax)
    for interface_obj in parse.find_objects('^interface'):
        if not interface_obj.is_virtual_intf:
            interface = {'name': None, 'description': None}
            interface_name = normalize_interface_names(interface_obj.re_match_typed(r'^interface\s+(\S.+?)$'))
            interface_description = interface_obj.re_match_iter_typed(r'^description\s+(\S.+?)$', recurse=True)
            interfaces.append({'name': interface_name,
                               'description': interface_description})
    return interfaces


def split_interface(interface):
    try:
        num_index = interface.index(next(x for x in interface if x.isdigit()))
        str_part = interface[:num_index]
        num_part = interface[num_index:]
    except StopIteration:
        return ['', '']
    return [str_part, num_part]


def normalize_interface_names(non_norm_int):
    tmp = split_interface(non_norm_int)
    interface_type = tmp[0].lower()
    port = tmp[1]
    interfaces = [
        [["ethernet", "eth"], "Eth"],
        [["fastethernet", " fastethernet", "fa", "interface fastethernet"], "Fa"],
        [["gi", "gigabitethernet", "gigabitethernet", "gi", " gigabitethernet", "interface gigabitethernet"], "Gi"],
        [["tengigabitethernet", "te"], "Te"],
        [["port-channel", "po"], "Po"],
        [["serial"], "Ser"],
    ]
    for int_types in interfaces:
        for names in int_types:
            for name in names:
                if interface_type in name:
                    return_this = int_types[1] + port
                    return return_this
    return "normalize_interface_names Failed"


def update_documentation(device_type, ip, username, password, secret, global_delay, oui_dict=None):
    print("Attempting to connect...")
    if device_type != 'cisco_s300':
        if username != '' and secret == '':
            conn = netmiko.ConnectHandler(device_type=device_type, ip=ip, username=username, password=password,
                                          global_delay_factor=global_delay)  # 2 options cisco_ios_telnet/cisco_ios
        elif username == '' and secret != '':
            conn = netmiko.ConnectHandler(device_type=device_type, ip=ip, password=password, secret=secret,
                                          global_delay_factor=global_delay)  # 2 options cisco_ios_telnet/cisco_ios
        elif username == '' and secret == '':
            conn = netmiko.ConnectHandler(device_type=device_type, ip=ip, password=password,
                                          global_delay_factor=global_delay)  # 2 options cisco_ios_telnet/cisco_ios
        else:
            conn = netmiko.ConnectHandler(device_type=device_type, ip=ip, username=username, password=password,
                                          secret=secret,
                                          global_delay_factor=global_delay)  # 2 options cisco_ios_telnet/cisco_ios
    else:
        conn = netmiko.ConnectHandler(device_type='terminal_server', ip=ip, username=username, password=password,
                                      global_delay_factor=global_delay)
    hostname = conn.strip_ansi_escape_codes(conn.find_prompt())
    if hostname[-1:] == ">":
        conn.enable()  # 2 options cisco_ios_telnet/cisco_ios
    hostname = hostname[:-1]
    print(hostname)

    if device_type != 'cisco_s300':
        conn.send_command('term width 511')
    else:
        conn.send_command_timing('term datadump')
    ip_int_status_cmd = conn.strip_ansi_escape_codes(conn.send_command_timing('sh interface status'))
    mac_address_table_cmd = conn.strip_ansi_escape_codes(conn.send_command_timing('sh mac address-table'))

    if device_type != 'cisco_s300':
        arp_table_cmd = conn.send_command('sh ip arp')
        ip_int_status = textfsm.TextFSM(open('../../../Downloads/SSH/cisco_ios_show_interfaces_status.template')).ParseText(ip_int_status_cmd)
        mac_address_table = textfsm.TextFSM(open('../../../Downloads/SSH/cisco_ios_show_mac-address-table.template')).ParseText(mac_address_table_cmd)
        arp_table = textfsm.TextFSM(open('../../../Downloads/SSH/cisco_ios_show_ip_arp.template')).ParseText(arp_table_cmd)
        try:
            cdp_neighbors = textfsm.TextFSM(open('../../../Downloads/SSH/cisco_ios_show_cdp_neighbors_detail.template')).ParseText(
                conn.send_command('sh cdp neigh detail'))
        except:
            print("CDP Error")
            import traceback
            print(traceback.format_exc())
        try:
            lldp_neighbors = textfsm.TextFSM(open(
                '../../../Downloads/SSH/cisco_ios_show_lldp_neighbors_detail.template')).ParseTextToDicts(
                conn.send_command('sh lldp neigh detail'))
        except:
            print("LLDP Error")
            import traceback
            print(traceback.format_exc())
        interfaces = list()
        for i in ip_int_status:
            # if 'Vlan' not in i:
            interface = dict()
            interface['int'] = normalize_interface_names(i[0])
            interface['ip_address'] = ''
            interface['mode'] = i[4] + '/' + i[5]
            interface['description'] = i[1]
            interface['vlan'] = i[3]
            interface['mac_address'] = list()
            interface['line_protocol'] = i[2]
            interface['neighbor'] = ''
            try:
                int_lldp_check = False
                for lldp_entry in lldp_neighbors:
                    if interface['int'] == normalize_interface_names(lldp_entry['LOCAL_INTERFACE']):
                        print(lldp_entry)
                        interface['neighbor'] = lldp_entry['NEIGHBOR'] + " - " + lldp_entry['NEIGHBOR_INTERFACE']
                        interface['ip_address'] = lldp_entry['MANAGEMENT_IP']
                        int_lldp_check = True
                        break
                if not int_lldp_check:
                    try_lldp_non_det = False
                    for lldp_entry in lldp_neighbors:
                        if lldp_entry['LOCAL_INTERFACE'] == '':
                            try_lldp_non_det = True
                            break
                    if try_lldp_non_det:
                        lldp_neighbors_non_det_cmd = conn.send_command('sh lldp neigh')
                        lldp_neighbors_non_det = textfsm.TextFSM(open(
                            '../../../Downloads/SSH/cisco_ios_show_lldp_neighbors.template')).ParseTextToDicts(lldp_neighbors_non_det_cmd)
                        for lldp_entry in lldp_neighbors_non_det:
                            if normalize_interface_names(lldp_entry['LOCAL_INTERFACE']) == interface['int']:
                                interface['neighbor'] = lldp_entry['NEIGHBOR'] + ' - ' + lldp_entry['NEIGHBOR_INTERFACE']
                                break
            except:
                import traceback
                print("LLDP Error")
                print(traceback.format_exc())
                try:
                    for h in cdp_neighbors:
                        if interface['int'] == normalize_interface_names(str(h[4])):
                            print(h)
                            interface['neighbor'] = h[0] + " - " + h[3]
                            interface['ip_address'] = ''
                            break
                except:
                    print("CDP Error")
                    print(traceback.format_exc())
            try:
                for g in mac_address_table:
                    if interface['vlan'] != 'trunk' and interface['int'] == g[3] and interface['neighbor'] == '':
                        interface['mac_address'].append(g[0])
            except:
                print('There was an error processing mac addresses')
                print(g)
                print(interface)
            interfaces.append(interface)
        # write the arp addresses to the output file.
        for arp in arp_table:
            mac_clean_upper = arp[2].upper().replace(".", "")
            print(arp[0] + '\t' + mac_clean_upper + '\t' + oui_lookup(mac_clean_upper, oui_dict))
            with open('../../../Downloads/SSH/arp_output.txt', 'a') as arp_file:
                arp_file.write(arp[0] + '\t' + mac_clean_upper + '\t' + oui_lookup(mac_clean_upper, oui_dict) + '\n')
        # write the interfaces to the output file.
        for i in interfaces:
            device_number = 0
            if i['mac_address'] == list():
                i['mac_address'] = ['N/A']
            for mac_address in i['mac_address']:
                device_number += 1
                ip_address = ''
                out_line = hostname + '\t' + \
                           ip + '\t' + \
                           i['int'] + '\t' + \
                           str(device_number) + '\t' + \
                           i['description'] + '\t' + \
                           i['line_protocol'] + '\t' + \
                           ip_address + '\t' + \
                           i['neighbor'] + '\t' + \
                           i['mode'] + '\t' + \
                           mac_address.replace('.', '').upper() + '\t' + \
                           i['vlan']
                print(out_line)
                with open('../../../Downloads/SSH/output.txt', 'a') as output_file:
                    output_file.write(out_line + '\n')
    else:
        ip_int_status = textfsm.TextFSM(open('../../../Downloads/SSH/cisco_s300_show_interfaces_status.template')).ParseTextToDicts(
            ip_int_status_cmd)
        mac_address_table = textfsm.TextFSM(open('../../../Downloads/SSH/cisco_s300_show_mac_address_table.template')).ParseTextToDicts(
            mac_address_table_cmd)
        lldp_neighbors = textfsm.TextFSM(open('../../../Downloads/SSH/cisco_s300_show_lldp_neighbors.template')).ParseTextToDicts(
            conn.strip_ansi_escape_codes(conn.send_command_timing('sh lldp neigh')))
        config = conn.strip_ansi_escape_codes(conn.send_command_timing('sh run', delay_factor=2))
        int_vlans = dict()
        for intf in get_interface_vlans(config, 'ios'):
            int_vlans[intf['name']] = intf
        int_descriptions = dict()
        for intf in get_interface_description(config, 'ios'):
            int_descriptions[intf['name']] = intf
        interfaces = list()
        for interface in ip_int_status:
            name = normalize_interface_names(interface['PORT'])
            if int_vlans[name]['mode'] != '':
                mode = int_vlans[name]['mode']
            elif int_vlans[name]['access-vlan'] != '':
                mode = 'access'
            elif int_vlans[name]['trunk-vlans'] != ['']:
                mode = 'trunk'
            else:
                mode = 'access'
            description = int_descriptions[name]['description']
            if mode == 'trunk':
                vlan = ','.join(int_vlans[name]['trunk-vlans'])
            else:
                vlan = int_vlans[name]['access-vlan']
            line_protocol = interface['SPEED'] + '/' + interface['DUPLEX']
            neighbor = ''
            for neighbor_ in lldp_neighbors:
                if name == normalize_interface_names(neighbor_['LOCAL_INTERFACE']):
                    neighbor = neighbor_['NEIGHBOR'] + " - " + neighbor_['NEIGHBOR_INTERFACE']
            mac_address = list()
            for mac_entry in mac_address_table:
                if name == normalize_interface_names(mac_entry['DESTINATION_PORT']) and mode != 'trunk' and neighbor == '':
                    mac_address.append(normalize_mac(mac_entry['DESTINATION_ADDRESS']))

            interfaces.append(deepcopy({'int': name,
                                        'description': description,
                                        'line_protocol': line_protocol,
                                        'neighbor': neighbor,
                                        'mode': mode,
                                        'vlan': vlan,
                                        'mac_address': mac_address
                                        }))
        # write the arp addresses to the output file.
        # for arp in arp_table:
        #     mac_clean_upper = arp[2].upper().replace(".", "")
        #     print(arp[0] + '\t' + mac_clean_upper + '\t' + oui_lookup(mac_clean_upper, oui_dict))
        #     with open('arp_output.txt', 'a') as arp_file:
        #         arp_file.write(arp[0] + '\t' + mac_clean_upper + '\t' + oui_lookup(mac_clean_upper, oui_dict) + '\n')
        # write the interfaces to the output file.
        for i in interfaces:
            device_number = 0
            if i['mac_address'] == list():
                i['mac_address'] = ['N/A']
            for mac_address in i['mac_address']:
                device_number += 1
                ip_address = ''
                try:
                    out_line = hostname + '\t' + \
                               ip + '\t' + \
                               str(i['int']) + '\t' + \
                               str(device_number) + '\t' + \
                               str(i['description']) + '\t' + \
                               str(i['line_protocol']) + '\t' + \
                               ip_address + '\t' + \
                               str(i['neighbor']) + '\t' + \
                               str(i['mode']) + '\t' + \
                               mac_address.replace('.', '').upper() + '\t' + \
                               str(i['vlan'])
                except:
                    import traceback
                    print(traceback.format_exc())
                    breakpoint()
                print(out_line)
                with open('../../../Downloads/SSH/output.txt', 'a') as output_file:
                    output_file.write(out_line + '\n')


if __name__ == '__main__':
    # load dictionary containing company mac address prefixes.
    oui_dict = load_wireshark_oui()
    global_delay = ""  # input("Input global delay based on connection speed:")
    if global_delay == "":
        global_delay = 1
    else:
        try:
            global_delay = float(global_delay)
        except:
            global_delay = 1
    multiple_devices = input("Use switch_list.txt? (y/n):")
    if multiple_devices == 'y':
        device_error_list = ""
        switch_list = {}
        with open('../../../Downloads/SSH/switch_list.txt', 'r') as f:
            r = reader(f)
            next(r, None)
            # erases the output file, and opens it to write.
            open('../../../Downloads/SSH/output.txt', 'w').close()
            open('../../../Downloads/SSH/arp_output.txt', 'w').close()
            for row in r:
                device_type, ip, username, password, secret = row
                print(ip)
                # Verify network device is available
                for i in range(10):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex(
                        (ip, 22 if device_type == 'cisco_ios' or device_type == 'cisco_s300' else 23))
                    sock.close()
                    if result == 0:
                        break
                if result == 0:
                    update_documentation(device_type, ip, username, password, secret, global_delay, oui_dict)
                else:
                    device_error_list += "DEVICE " + ip + " IS NOT AVAILABLE ON THE NETWORK\n"
                    print("DEVICE " + ip + " IS NOT AVAILABLE ON THE NETWORK\n")
            print(device_error_list)

    else:
        device_type = input("Device type: (cisco_ios, cisco_ios_telnet, cisco_s300): ") or "cisco_ios"
        ip = input("Switch IP address:")  # 192.168.99.1
        username = input("Username:")  # 'cybertrol'
        password = input("Password:")  # 'AlmAdmin_123!'
        secret = input("Enable Secret:")
        output_file = open('../../../Downloads/SSH/output.txt', 'w')
        arp_file = open('../../../Downloads/SSH/arp_output.txt', 'w')
        update_documentation(device_type, ip, username, password, secret, global_delay, oui_dict)
