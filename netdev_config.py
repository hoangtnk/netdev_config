
#!/usr/bin/env python3
#
# Network devices configuration

from collections import OrderedDict

import sys
import re
import os
import threading
import subprocess

try:
    from netmiko import ConnectHandler, ssh_exception   
except ImportError:
    print("\nNetmiko module needs to be installed on your system.")
    print("Download it from https://pypi.python.org/pypi/netmiko/1.1.0")
    print("\nClosing program...\n")
    sys.exit()

try:
    from colorama import init, deinit, Fore, Style
except ImportError:
    print("\nColorama module needs to be installed on your system.")
    print("Download it from https://pypi.python.org/pypi/colorama")
    print("\nClosing program...\n")
    sys.exit()


# Edit this dictionary to suit your environment
devices_dict = (("A-SW-01", "192.0.2.1"),
                ("A-SW-02", "192.0.2.2"),
                ("D-SW-01", "192.0.2.3"),
                ("D-SW-02", "192.0.2.4"),
                ("CORE-SW-01", "192.0.2.5"),
                ("CORE-SW-02", "192.0.2.6"))


devices_dict = OrderedDict(devices_dict)
all_devices_output = {}  # dictionary containing all devices output
devices_ip = []  # list containing devices IP
devices_name = []  # list containing devices name
commands_list = []  # list containing commands to be executed


def reset_data():
   
    """ Reset data in global variables """
   
    global all_devices_output
    global devices_ip
    global devices_name
    global commands_list
   
    all_devices_output = {}
    devices_ip = []
    devices_name = []
    commands_list = []


def in_devices_dict(dev):
   
    """ Check if a device's name given by user is in the dictionary """
   
    for key in devices_dict.keys():
        if dev.lower() in key.lower():
            return True
    return False


def get_device_ip(dev):
   
    """ Getting device's IP based on its name in the dictionary """
   
    for key, value in devices_dict.items():
        if dev.lower() in key.lower():
            devices_name.append(key)
            devices_ip.append(value)


def get_info():
   
    """ Getting information about devices list and commands list """
   
    global devices_ip
    global devices_name
    global commands_list
    global cmd_file
   
    while True:
        devices = input(Style.RESET_ALL + Fore.RESET + "\n* Enter device name separated by comma, or a file containing device name: ")
        if os.path.isfile(devices):
            with open(devices, "r") as f:
                devices_name = f.read().split("\n")[:-1]
            devices_ip = [devices_dict[dev] for dev in devices_name]
            break         
        else:
            if (",") in devices:
                temp = devices.split(",")
                for dev in temp:
                    if in_devices_dict(dev):
                        get_device_ip(dev)                 
                    else:
                        print(Style.BRIGHT + Fore.RED + "\nDevice %s not found!" % dev)
                if len(devices_ip) > 0:
                    break
            else:
                if "/" in devices:
                    print(Style.BRIGHT + Fore.RED + "\nFile %s not found!" % devices)               
                else:
                    if in_devices_dict(devices):
                        get_device_ip(devices)
                        break
                    else:
                        print(Style.BRIGHT + Fore.RED + "\nDevice %s not found!" % devices)

    if choice == "1":
        commands = input(Style.RESET_ALL + Fore.RESET + "\n* Enter commands separated by comma: ")
        commands_list = commands.split(",")
       
    elif choice == "2":
        while True:
            cmd_file = input(Style.RESET_ALL + Fore.RESET + "\n* Enter command file name and extension: ")
            if os.path.isfile(cmd_file):
                break
            else:
                print(Style.BRIGHT + Fore.RED + "\nFile %s not found! Please recheck!" % cmd_file)
   

def isnum(num):
   
    """ Check if a given string is a number """
   
    if num == "":
        return False
   
    for _num in num:
        if _num not in "0123456789":
            return False
    return True


def open_ssh_conn(ip):
   
    """ Open SSH connection to device """
   
    global all_devices_output
   
    juniper_devices = ["10.199.252.2", "10.199.250.33", "10.199.250.202", "10.199.250.182", "10.199.250.162", "10.199.250.178"]
    each_device_output = {}
   
    try:
        if ip not in juniper_devices:
            net_connect = ConnectHandler(device_type="cisco_ios", ip=ip, username="pyscripts", password="x@kalM0jsEM93pkXYl&B")
        else:
            net_connect = ConnectHandler(device_type="juniper_junos", ip=ip, username="pyscripts", password="x@kalM0jsEM93pkXYl&B")
       
        if choice == "1":
            for cmd in commands_list:
                output = net_connect.send_command(cmd)
                each_device_output[cmd] = output + "\n"
            all_devices_output[ip] = each_device_output
       
        elif choice == "2":
            net_connect.send_config_from_file(config_file=cmd_file)
       
        elif choice == "3":
            output = net_connect.send_command("show interfaces status | include notconnect")  # find unused ports by including "notconnect" keyword in "show interfaces status" command
            unused_ports = [tup[0] for tup in re.findall(r"((Fa|Gi)\d/\d+)(.+)notconnect", output)]
            if len(unused_ports) > 0:
                for port in unused_ports:
                    net_connect.send_config_set(config_commands=["interface " + port, "shutdown"])
                print(Style.BRIGHT + Fore.GREEN + "+ %s (%s): " % (devices_name[devices_ip.index(ip)], ip), end="")
                print(Style.RESET_ALL + Fore.RESET + "Total %d ports have been shutdown (" % len(unused_ports) + ", ".join(unused_ports) + ")\n")
            else:
                print(Style.BRIGHT + Fore.GREEN + "+ %s (%s): " % (devices_name[devices_ip.index(ip)], ip), end = "")
                print(Style.RESET_ALL + Fore.RESET + "No unused ports\n")
       
        elif choice == "4":
            output = net_connect.send_command("show interfaces status | include disabled")  # find disabled ports by including "disabled" keyword in "show interfaces status" command
            disabled_ports = [tup[0] for tup in re.findall(r"((Fa|Gi)\d/\d+)(.+)disabled", output)]
            if len(disabled_ports) > 0:
                for port in disabled_ports:
                    net_connect.send_config_set(config_commands=["interface " + port, "shutdown", "no shutdown"])
                print(Style.BRIGHT + Fore.GREEN + "+ %s (%s): " % (devices_name[devices_ip.index(ip)], ip), end="")
                print(Style.RESET_ALL + Fore.RESET + "%d ports have been enabled (" % len(disabled_ports) + ", ".join(disabled_ports) + ")\n")
            else:
                print(Style.BRIGHT + Fore.GREEN + "+ %s (%s): " % (devices_name[devices_ip.index(ip)], ip), end = "")
                print(Style.RESET_ALL + Fore.RESET + "No disabled ports\n")
       
        net_connect.disconnect()   
       
    except ssh_exception.NetMikoAuthenticationException:
        print(Style.BRIGHT + Fore.RED + "+ %s (%s): Authentication failed\n" % (devices_name[devices_ip.index(ip)], ip))
   
    except ssh_exception.NetMikoTimeoutException:
        print(Style.BRIGHT + Fore.RED + "+ %s (%s): No response/Connection refused\n" % (devices_name[devices_ip.index(ip)], ip))
   
    except ValueError as exc:
        print(Style.BRIGHT + Fore.RED + "+ %s (%s): %s" % (devices_name[devices_ip.index(ip)], ip, str(exc)))
   
   
def create_threads():
   
    """ Create threads to SSH to multiple devices simultaneously """
   
    threads = []
    for ip in devices_ip:
        th = threading.Thread(target=open_ssh_conn, args=(ip,))  
        th.start()
        threads.append(th)
       
    for th in threads:
        th.join()


def option1():
   
    """ Handling option 1 in user menu """
   
    print("\nConnecting to devices. Please wait...\n")
    create_threads()
   
    if len(all_devices_output) > 0:  # only print output if the output dictionary is not empty
        print(Style.RESET_ALL + Fore.RESET + "DONE for collecting devices output!")
       
        # Printing device menu and command menu
        print("\n\nDEVICES:                          COMMANDS:\n")
        if len(devices_name) > len(commands_list):
            for index, cmd in enumerate(commands_list):
                print(Style.BRIGHT + Fore.CYAN + "[%d] %s                    [%d] %s" % (index + 1, devices_name[index], index + 1, cmd))
               
            for index in range(len(commands_list), len(devices_name)):
                print("[%d] %s" % (index + 1, devices_name[index]))
        else:
            for index, dev in enumerate(devices_name):
                print(Style.BRIGHT + Fore.CYAN + "[%d] %s                    [%d] %s" % (index + 1, dev, index + 1, commands_list[index]))
           
            for index in range(len(devices_name), len(commands_list)):
                print("                                  [%d] %s" % (index + 1, commands_list[index]))
           
        print(Style.RESET_ALL + Fore.RESET + "\n\n- To choose which output to see, please specify device number and command number separated by comma.")
        print("\n- Example: Enter 2,1 if you want to see output of command 1 on device 2.")
        print("\n- Alternatively, specifying 'a' if you want to see all (so 2,a would be to see output of all commands on device 2).")
        print("\n- Press 'e' to exit to main menu, or 'q' to exit the program.\n")
        while True:
            output_choice = input(Style.RESET_ALL + Fore.RESET + "\n* Enter your choice: ")
            if output_choice == "e":
                break
           
            if output_choice == "q":
                print(Style.BRIGHT + Fore.RED + "\nClosing program...\n")
                deinit()
                sys.exit()
           
            if "," not in output_choice:
                print(Style.BRIGHT + Fore.RED + "\nInvalid input! Please recheck!")
            else:
                dev_num = output_choice.split(",")[0]
                cmd_num = output_choice.split(",")[1]
                try:
                    if isnum(dev_num) and isnum(cmd_num):
                        if devices_ip[int(dev_num) - 1] in all_devices_output:  # only print output of a specific device if it's present in the returned dictionary
                            print(Style.BRIGHT + Fore.GREEN + "\n+ Device %s (%s/%s) - Command %s (%s):\n" % (dev_num, devices_name[int(dev_num) - 1], devices_ip[int(dev_num) - 1], cmd_num, commands_list[int(cmd_num) - 1]))
                            print(Style.RESET_ALL + Fore.RESET + all_devices_output[devices_ip[int(dev_num) - 1]][commands_list[int(cmd_num) - 1]])
                        else:
                            print(Style.BRIGHT + Fore.RED + "\nSorry! No information available for device %s (%s/%s)" % (dev_num, devices_name[int(dev_num) - 1], devices_ip[int(dev_num) - 1]))
               
                    elif dev_num == "a" and isnum(cmd_num):
                        for index, dev in enumerate(devices_ip):
                            if dev in all_devices_output:
                                print(Style.BRIGHT + Fore.GREEN + "\n+ Device %s (%s/%s) - Command %s (%s):\n" % (index + 1, devices_name[index], dev, cmd_num, commands_list[int(cmd_num) - 1]))
                                print(Style.RESET_ALL + Fore.RESET + all_devices_output[dev][commands_list[int(cmd_num) - 1]])     
                            else:
                                print(Style.BRIGHT + Fore.RED + "\nSorry! No information available for device %s (%s/%s)" % (index + 1, devices_name[index], dev))
               
                    elif isnum(dev_num) and cmd_num == "a":
                        if devices_ip[int(dev_num) - 1] in all_devices_output:
                            for index, cmd in enumerate(commands_list):
                                print(Style.BRIGHT + Fore.GREEN + "\n+ Device %s (%s/%s) - Command %s (%s):\n" % (dev_num, devices_name[int(dev_num) - 1], devices_ip[int(dev_num) - 1], index + 1, cmd))
                                print(Style.RESET_ALL + Fore.RESET + all_devices_output[devices_ip[int(dev_num) - 1]][cmd])
                        else:
                            print(Style.BRIGHT + Fore.RED + "\nSorry! No information available for device %s (%s/%s)" % (dev_num, devices_name[int(dev_num) - 1], devices_ip[int(dev_num) - 1]))
               
                    elif dev_num == "a" and cmd_num == "a":
                        for index_dev, dev in enumerate(devices_ip):
                            if dev in all_devices_output:
                                for index_cmd, cmd in enumerate(commands_list):
                                    print(Style.BRIGHT + Fore.GREEN + "\n+ Device %s (%s/%s) - Command %s (%s):\n" % (index_dev + 1, devices_name[index_dev], dev, index_cmd + 1, cmd))
                                    print(Style.RESET_ALL + Fore.RESET + all_devices_output[dev][cmd])
                            else:
                                print(Style.BRIGHT + Fore.RED + "\nSorry! No information available for device %s (%s/%s)" % (index_dev + 1, devices_name[index_dev], dev))
               
                    else:
                        print(Style.BRIGHT + Fore.RED + "\nInvalid input! Please recheck!")
               
                except IndexError:
                    print(Style.BRIGHT + Fore.RED + "\nThe numbers you specified are out of range! Please recheck!")
           
                except KeyError:
                    print(Style.BRIGHT + Fore.RED + "\nKeyError encountered!")
    reset_data()
   

def option2():
   
    """ Handling option 2 in user menu """
   
    print("\nConnecting to devices. Please wait...\n")
    create_threads()
    reset_data()
    print(Style.RESET_ALL + Fore.RESET + "DONE! Commands have been sent successfully to devices!\n")
   

def option3():
   
    """ Handling option 3 in user menu """
   
    global devices_ip
    global devices_name
   
    with open("/home/hoangtnk/PythonFiles/access_sw.txt", "r") as f:
        devices_name = f.read().split("\n")[:-1]
    devices_ip = [devices_dict[dev] for dev in devices_name]
   
    print("\nThis will SHUTDOWN all unused (notconnect) ports on all access switches!\n")
    while True:
        shut_choice = input("Are you sure you want to continue? (y/n) ")
        print("")
        if shut_choice == "y":
            create_threads()
            reset_data()
            print(Style.RESET_ALL + Fore.RESET + "DONE!\n")
            break
       
        elif shut_choice == "n":
            reset_data()
            break
       
        else:
            continue


def option4():
   
    """ Handling option 4 in user menu """
   
    global devices_ip
    global devices_name
   
    with open("/home/hoangtnk/PythonFiles/access_sw.txt", "r") as f:
        devices_name = f.read().split("\n")[:-1]
    devices_ip = [devices_dict[dev] for dev in devices_name]
   
    print("\nThis will ENABLE all disabled (admin down and err-disabled) ports on all access switches!\n")
    while True:
        enable_choice = input("Are you sure you want to continue? (y/n) ")
        print("")
        if enable_choice == "y":
            create_threads()
            reset_data()
            print(Style.RESET_ALL + Fore.RESET + "DONE!\n")
            break
       
        elif enable_choice == "n":
            reset_data()
            break
       
        else:
            continue


def option5():
   
    """ Handling option 5 in user menu """
   
    # Printing notification and example file format
    print("\n\nNOTE:")
    print("\n- Only extended ACL is supported.")
    print("\n- If there are more than one ACL in the file, they MUST be separated by '!' character.")
    print("\n- Example of file format:")
    print("\nip access-list extended VLAN100\n permit tcp any 10.199.0.0 0.0.255.255 eq 22\n deny ip any any\n!")
    print("ip access-list extended VLAN200\n permit ip host 10.199.0.99 10.0.0.0 0.255.255.255\n deny ip any any\n!")
    print("ip access-list extended VLAN300\n permit ip any 10.0.0.0 0.255.255.255")
   
    while True:
        ios_acl_file = input(Style.RESET_ALL + Fore.RESET + "\n\n* Enter a file containing IOS ACL format: ")
        if os.path.isfile(ios_acl_file):
            break
        else:
            print(Style.BRIGHT + Fore.RED + "\nFile %s not found! Please recheck!" % ios_acl_file)
   
    print("\nWhich Junos syntax do you want to convert to?")
    print(Style.BRIGHT + Fore.CYAN + "\n 1 - Use a series of 'set' commands")
    print(" 2 - Use the traditional syntax (with '{ }' characters)")
   
    while True:
        format_choice = input(Style.RESET_ALL + Fore.RESET + "\n* Enter your choice: ")
        if (format_choice == "1") or (format_choice == "2"):
            break
        else:
            print(Style.BRIGHT + Fore.RED + "\nInvalid input! Please try again!")   
   
    print("\nConverting...\n")
    converted_file = "/home/hoangtnk/PythonFiles/converted_acl.txt"
   
    # Erase content from "converted_acl.txt" file before starting
    if os.path.isfile(converted_file):
        open(converted_file, "w").close()
       
    with open(ios_acl_file, "r") as f:
        content = f.read()
        if "!" not in content:
            proc = subprocess.Popen(["aclconv", "-j", ios_acl_file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            output = proc.communicate()[0]
            if format_choice == "1":
                output = output.replace("\n", "")  # remove '\n' character to extract info with regex easier
                try:
                    filter_name = re.search(r" filter (.+?) ", output).group(1)
                except AttributeError:
                    print(Style.BRIGHT + Fore.RED + "\nAttributeError encountered! Please check out the file at %s for more information.\n" % converted_file)
                    return
                for i in range(len(re.findall(r" term ", output))):
                    output_set = ""
                    term_name = "T" + str(i + 1)
                    each_term = re.search(r" term %s (.+?)then (.+?)\s+(.+?);" % term_name, output).group()  # match the content of each term in ACL
                    src_ip = re.search(r"(.+?)source-address (.+?)(\d+.\d+.\d+.\d+/\d+);", each_term)
                    if src_ip is not None:
                        output_set = output_set + "set firewall family inet filter %s term %s from source-address %s\n" % (filter_name, term_name, src_ip.group(3))
                   
                    dst_ip = re.search(r"(.+?)destination-address (.+?)(\d+.\d+.\d+.\d+/\d+);", each_term)
                    if dst_ip is not None:
                        output_set = output_set + "set firewall family inet filter %s term %s from destination-address %s\n" % (filter_name, term_name, dst_ip.group(3))
                   
                    protocol = re.search(r"(.+?)protocol (.+?);", each_term)
                    if protocol is not None:
                        output_set = output_set + "set firewall family inet filter %s term %s from protocol %s\n" % (filter_name, term_name, protocol.group(2))
                   
                    src_port = re.search(r"(.+?)source-port (\d+);", each_term)
                    if src_port is not None:
                        output_set = output_set + "set firewall family inet filter %s term %s from source-port %s\n" % (filter_name, term_name, src_port.group(2))
                   
                    dst_port = re.search(r"(.+?)destination-port (\d+);", each_term)
                    if dst_port is not None:
                        output_set = output_set + "set firewall family inet filter %s term %s from destination-port %s\n" % (filter_name, term_name, dst_port.group(2))
                   
                    output_set = output_set + "set firewall family inet filter %s term %s then count %s\n" % (filter_name, term_name, term_name)
                    action = re.search(r"(.+?)then (.+?)\s+(.+?);", each_term)
                    if action is not None:
                        if action.group(3) == "reject":  # replace 'reject' action by 'discard' because 'discard' will drop packets without generating ICMP unreachable, which will not harm switch's CPU
                            output_set = output_set + "set firewall family inet filter %s term %s then discard\n" % (filter_name, term_name)
                        else:
                            output_set = output_set + "set firewall family inet filter %s term %s then %s\n" % (filter_name, term_name, action.group(3))
                   
                    with open(converted_file, "a") as f:
                        f.write(output_set)
            else:
                with open(converted_file, "a") as f:
                    f.write(output)
            print("DONE! Please check out the file at %s to see the result.\n" % converted_file)
        else:
            temp_file = "/home/hoangtnk/PythonFiles/temp.txt"
            if format_choice == "1":
                for elem in content.split("!\n"):
                    with open(temp_file, "w") as f:
                        f.write(elem)
                    proc = subprocess.Popen(["aclconv", "-j", temp_file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
                    output = proc.communicate()[0]
                    output = output.replace("\n", "")  # remove '\n' character to extract info with regex easier
                    try:
                        filter_name = re.search(r" filter (.+?) ", output).group(1)
                    except AttributeError:
                        print(Style.BRIGHT + Fore.RED + "\nAttributeError encountered! Please check out the file at %s for more information.\n" % converted_file)
                        return
                    for i in range(len(re.findall(r" term ", output))):
                        output_set = ""
                        term_name = "T" + str(i + 1)
                        each_term = re.search(r" term %s (.+?)then (.+?)\s+(.+?);" % term_name, output).group()  # match the content of each term in ACL
                        src_ip = re.search(r"(.+?)source-address (.+?)(\d+.\d+.\d+.\d+/\d+);", each_term)
                        if src_ip is not None:
                            output_set = output_set + "set firewall family inet filter %s term %s from source-address %s\n" % (filter_name, term_name, src_ip.group(3))
                   
                        dst_ip = re.search(r"(.+?)destination-address (.+?)(\d+.\d+.\d+.\d+/\d+);", each_term)
                        if dst_ip is not None:
                            output_set = output_set + "set firewall family inet filter %s term %s from destination-address %s\n" % (filter_name, term_name, dst_ip.group(3))
                   
                        protocol = re.search(r"(.+?)protocol (.+?);", each_term)
                        if protocol is not None:
                            output_set = output_set + "set firewall family inet filter %s term %s from protocol %s\n" % (filter_name, term_name, protocol.group(2))
                   
                        src_port = re.search(r"(.+?)source-port (\d+);", each_term)
                        if src_port is not None:
                            output_set = output_set + "set firewall family inet filter %s term %s from source-port %s\n" % (filter_name, term_name, src_port.group(2))
                   
                        dst_port = re.search(r"(.+?)destination-port (\d+);", each_term)
                        if dst_port is not None:
                            output_set = output_set + "set firewall family inet filter %s term %s from destination-port %s\n" % (filter_name, term_name, dst_port.group(2))
                   
                        output_set = output_set + "set firewall family inet filter %s term %s then count %s\n" % (filter_name, term_name, term_name)
                        action = re.search(r"(.+?)then (.+?)\s+(.+?);", each_term)
                        if action is not None:
                            if action.group(3) == "reject":  # replace 'reject' action by 'discard' because 'discard' will drop packets without generating ICMP unreachable, which will not harm switch's CPU
                                output_set = output_set + "set firewall family inet filter %s term %s then discard\n" % (filter_name, term_name)
                            else:
                                output_set = output_set + "set firewall family inet filter %s term %s then %s\n" % (filter_name, term_name, action.group(3))
                   
                        with open(converted_file, "a") as f:
                            f.write(output_set)
                    with open(converted_file, "a") as f:
                        f.write("\n\n")
            else:
                for elem in content.split("!\n"):
                    with open(temp_file, "w") as f:
                        f.write(elem)
                    proc = subprocess.Popen(["aclconv", "-j", temp_file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
                    output = proc.communicate()[0]
                    with open(converted_file, "a") as f:
                        f.write(output + "\n\n")
            os.unlink(temp_file)  # delete temp file after finishing
            print("DONE! Please check out the file at %s to see the result.\n" % converted_file)


def option6():
   
    """ Handling option 6 in user menu """
   
    # Printing notification and example file format
    print("\n\nNOTE:")
    print("\n- If there are more than one ACL in the file, they MUST be separated by '!' character.")
    print("\n- Example of file format:")
    print("\nfirewall {\nreplace:\n        filter VLAN100 {")
    print("            term T1 {\n                from {\n                    destination-address {\n                        10.199.100.0/24;\n                    }\n                }\n                then accept;\n            }")
    print("            term T2 {\n                then discard;\n            }\n      }\n}\n!")
    print("firewall {\nreplace:\n        filter VLAN200 {")
    print("            term T1 {\n                from {\n                    source-address {\n                        10.199.172.0/22;\n                    }\n                }\n                then discard;\n            }")
    print("            term T2 {\n                then accept;\n            }\n      }\n}")
   
    while True:
        junos_acl_file = input(Style.RESET_ALL + Fore.RESET + "\n\n* Enter a file containing Junos ACL format: ")
        if os.path.isfile(junos_acl_file):
            break
        else:
            print(Style.BRIGHT + Fore.RED + "\nFile %s not found! Please recheck!" % junos_acl_file)
   
    print("\nConverting...\n")
    converted_file = "/home/hoangtnk/PythonFiles/converted_acl.txt"
   
    # Erase content from "converted_acl.txt" file before starting
    if os.path.isfile(converted_file):
        open(converted_file, "w").close()
       
    with open(junos_acl_file, "r") as f:
        content = f.read()
        if "!" not in content:
            proc = subprocess.Popen(["aclconv", "-i", junos_acl_file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            output = proc.communicate()[0]
            with open(converted_file, "a") as f:
                f.write(output)
            print("DONE! Please check out the file at %s to see the result.\n" % converted_file)
        else:
            temp_file = "/home/hoangtnk/PythonFiles/temp.txt"
            num = 0  # used to increase the access-list number. Otherwise, it will be all 100
            for elem in content.split("!\n"):
                with open(temp_file, "w") as f:
                    f.write(elem)
                proc = subprocess.Popen(["aclconv", "-i", temp_file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
                output = proc.communicate()[0]
                output_list = output.split("\n")
                for i in range(len(output_list)):
                    output_list[i] = output_list[i].replace("access-list 100", "access-list " + str(100 + num))
                output = "\n".join(output_list)
                with open(converted_file, "a") as f:
                    f.write(output + "\n\n")
                num += 1
            os.unlink(temp_file)  # delete temp file after finishing
            print("DONE! Please check out the file at %s to see the result.\n" % converted_file)   
   
   
def print_menu():
   
    """ Print out a menu with options for user to choose """
   
    global choice
   
    while True:
        print(Style.RESET_ALL + Fore.RESET + "\nPlease choose an option:\n")
        print(Style.BRIGHT + Fore.CYAN + " 1 - Run commands from terminal (suitable for viewing device's info)")
        print(" 2 - Run commands from file (suitable for configuring devices)")
        print(" 3 - Shutdown unused ports on access switches")
        print(" 4 - Enable disabled ports on access switches")
        print(" 5 - Convert IOS ACL to Junos ACL")
        print(" 6 - Convert Junos ACL to IOS ACL")
        print(" 0 - Exit")
   
        choice = input(Style.RESET_ALL + Fore.RESET + "\n* Enter your choice: ")
        if choice == "1":
            get_info()
            option1()
           
        elif choice == "2":
            get_info()
            option2()
       
        elif choice == "3":
            option3()
       
        elif choice == "4":
            option4()
       
        elif choice == "5":
            option5()
       
        elif choice == "6":
            option6()
       
        elif choice == "0":
            print(Style.BRIGHT + Fore.RED + "\nClosing program...\n")
            deinit()
            sys.exit()
   
        else:
            print(Style.BRIGHT + Fore.RED + "\nInvalid input! Please try again!\n")


def main():
   
    """ Main function """
   
    try:
        init()
        print_menu()
        deinit()
       
    except KeyboardInterrupt:
        print(Style.BRIGHT + Fore.RED + "\n\nProgram aborted by user. Closing...\n")
        deinit()
        sys.exit()


if __name__ == "__main__":
    main()
