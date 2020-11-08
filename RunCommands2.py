import netmiko
from csv import reader
import traceback
from joblib import Parallel, delayed
import socket
import time
import os


def is_open(ip,port):
   s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   try:
      s.connect((ip, int(port)))
      s.shutdown(2)
      return True
   except:
      return False


def run_command(input_dict):
    device_type = input_dict['device_type']
    ip = input_dict['ip']
    username = input_dict['username']
    password = input_dict['password']
    secret = input_dict['secret']
    timing = input_dict['timing']
    output = [ip]
    if device_type == 'cisco_ios':
        port = 22
    else:
        port = 23
    if not is_open(ip,port):
        return output.append("port " + str(port) + " isn't open")
    try:
        if username!='' and secret=='':
            conn = netmiko.ConnectHandler(device_type=device_type, ip=ip, username=username, password=password, global_delay_factor=0)  # 2 options cisco_ios_telnet/cisco_ios
        elif username=='' and secret!='':
            conn = netmiko.ConnectHandler(device_type=device_type, ip=ip, password=password, secret=secret, global_delay_factor=0)  # 2 options cisco_ios_telnet/cisco_ios
        elif username=='' and secret=='':
            conn = netmiko.ConnectHandler(device_type=device_type, ip=ip, password=password, global_delay_factor=0)  # 2 options cisco_ios_telnet/cisco_ios
        else:
            conn = netmiko.ConnectHandler(device_type=device_type, ip=ip, username=username, password=password, secret=secret, global_delay_factor=0) #2 options cisco_ios_telnet/cisco_ios
        hostname = conn.find_prompt()
        if hostname[-1:] == ">":
            conn.enable()
        conn.send_command('term no width')
        if type(command) == list:
            for i in command:
                output.append(i)
                if i == "conf t":
                    conn.config_mode()
                elif i == "end":
                    conn.exit_config_mode()
                else:
                    output.append(conn.send_command_timing(i,delay_factor=timing))
        else:
            command_output = conn.send_command_timing(command,delay_factor=timing)#,expect_string=".")

            #conn.send_command("clear counters", expect_string="\[confirm\]")
            #conn.send_command("\n", expect_string="#")
            output.append(command_output)
    except:
        output.append(traceback.format_exc())
    return output


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    start_time = time.time()
    print(start_time)
    print("Your Current Netmiko Version:" + netmiko.__version__)
    timing = ""
    #timing = input("Input timing modifier:")
    if timing == "":
        timing = 1
    else:
        timing = float(timing)
    command = input("Input command to run:")
    if "~" in command:
        command = command.split("~")
    switch_list = []
    with open('../../../Downloads/SSH/switch_list_saputo.txt', 'r') as f:
        r = reader(f)
        next(r, None)
        for row in r:
            device_type, ip, username, password, secret = row
            switch_list.append({'device_type':device_type,'ip':ip,'username':username,'password':password,'secret':secret,'timing':timing})
    results = Parallel(n_jobs=len(switch_list), verbose=0, backend="threading")(map(delayed(run_command), switch_list))

    for x in results:
        if type(x) == list:
            for y in x:
                print(y)
        else:
            print(x)

    print(time.time() - start_time)