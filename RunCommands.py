import netmiko
from csv import reader
import traceback


def run_command(device_type, ip, username, password, secret, timing):
    conn = netmiko.ConnectHandler(device_type=device_type, ip=ip, username=username, password=password, secret=secret, global_delay_factor=0)
    hostname = conn.find_prompt()
    if hostname[-1:] == ">":
        conn.enable()
    conn.send_command('term no width')
    if type(command) == list:
        for i in command:
            print(i)
            if i == "conf t":
                conn.config_mode()
            elif i == "end":
                conn.exit_config_mode()
            else:
                if timing == "":
                    print(conn.send_command(i))  # _timing(i, delay_factor=timing))
                else:
                    print(conn.send_command_timing(i, delay_factor=timing))#_timing(i, delay_factor=timing))

    else:
        command_output = conn.send_command_timing(command)#,expect_string=".")
        with open('log.txt', 'a') as f:
            f.write(command_output + '\r\n')
        print(command_output)


if __name__ == '__main__':
    print(netmiko.__version__)
    timing = input("Input timing modifier:")
    if timing == "":
        pass
    else:
        timing = float(timing)
    command = input("Input command to run:")
    if "~" in command:
        command = command.split("~")
    with open('log.txt', 'w') as f:
        f.write('')
    switch_list = {}
    with open('switch_list.txt', 'r') as f:
        r = reader(f)
        next(r, None)
        for row in r:
            device_type, ip, username, password, secret = row
            print(ip)
            for _ in range(10):
                try:
                    run_command(device_type, ip, username, password, secret, timing)
                    break
                except:
                    print(traceback.format_exc())
                    pass
