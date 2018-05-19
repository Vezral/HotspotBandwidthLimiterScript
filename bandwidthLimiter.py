import argparse
import subprocess
import netifaces
import ipaddress
import re
import socket
import struct


# code to convert netmask ip to cidr number
def netmask_to_cidr(netmask):
    return str(sum([bin(int(x)).count('1') for x in netmask.split('.')]))


# remove all rule
def clear_all_rule(interface):
    subprocess.run(["tcdel", "--device", interface, "-a"])


# convert string ip address to long
def ip2long(ip):
    return struct.unpack("!L", socket.inet_aton(ip))[0]


# show all current rules
def show_all_rule(interface):
    result = subprocess.run(["tcshow", "--device", interface], stdout=subprocess.PIPE)
    result = result.stdout.decode("utf-8")
    download_result = re.findall(r"dst-network=(.*?)/.*?\"rate\":.*?\"(.*?)\"", result, re.DOTALL)
    upload_result = re.findall(r"src-network=(.*?)/.*?\"rate\":.*?\"(.*?)\"", result, re.DOTALL)
    download_result.sort(key=lambda x: ip2long(x[0]))
    upload_result.sort(key=lambda x: ip2long(x[0]))
    i = 0
    total = 0
    print("{:<24} {:<24} {:<24}".format("IP Address", "Download Speed (KBps)", "Upload Speed (KBps)"))
    for ip_address, download_speed in download_result:
        while True:
            if i < len(upload_result):
                if ip2long(ip_address) < ip2long(upload_result[i][0]):
                    print("{:<24} {:<24.2f} {:<24}".format(ip_address, float(download_speed[:-1])/8, "Unlimited"))
                    total += 1
                    break
                elif ip2long(ip_address) == ip2long(upload_result[i][0]):
                    print("{:<24} {:<24.2f} {:<24.2f}".format(ip_address, float(download_speed[:-1])/8, float(upload_result[i][1][:-1])/8))
                    i += 1
                    total += 1
                    break
                else:
                    print("{:<24} {:<24} {:<24.2f}".format(upload_result[i][0], "Unlimited", float(upload_result[i][1][:-1])/8))
                    i += 1
                    total += 1
            else:
                print("{:<24} {:<24.2f} {:<24}".format(ip_address, float(download_speed[:-1])/8, "Unlimited"))
                total += 1
                break
    for j in range(i, len(upload_result)):
        print("{:<24} {:<24} {:<24.2f}".format(upload_result[j][0], "Unlimited", float(upload_result[j][1][:-1])/8))
        total += 1
    print("Total hosts: {}".format(total))


# return all live host in network
def get_all_connected_host(interface):
    result = subprocess.run(["arp", "--device", interface], stdout=subprocess.PIPE)
    result = result.stdout.decode("utf-8")
    host_list = []
    for index, ip_address in enumerate(result.splitlines()):
        if index == 0:
            continue
        else:
            host_list.append(ip_address.split()[0])
    host_list.sort(key=lambda x: ip2long(x))
    return host_list


# limit download
def limit_download_speed(interface, ip, download_speed):
    subprocess.run(["tcset", "--device", interface, "--rate", str(download_speed) + "Kbps", "--direction", "outgoing", "--network", ip, "--change"])


# remove limit on download
def remove_download_speed_limit(interface, ip):
    subprocess.run(["tcdel", "--device", interface, "--direction", "outgoing", "--network", ip])


# limit upload
def limit_upload_speed(interface, ip, upload_speed):
    subprocess.run(["tcset", "--device", interface, "--rate", str(upload_speed) + "Kbps", "--direction", "incoming", "--src-network", ip, "--change"])


# remove limit on upload
def remove_upload_speed_limit(interface, ip):
    subprocess.run(["tcdel", "--device", interface, "--direction", "incoming", "--src-network", ip])


parser = argparse.ArgumentParser()
parser.add_argument("-i", "--device", help="select interface to restrict bandwidth")
parser.add_argument("-ip", "--ip", help="specify which IP address to throttle")
parser.add_argument("-d", "--download", type=float, help="limit download speed (in KBps)")
parser.add_argument("-u", "--upload", type=float, help="limit upload speed (in KBps)")
group = parser.add_mutually_exclusive_group()
group.add_argument("-s", "--show", action="store_true", help="show all established rules")
group.add_argument("-c", "--clear", action="store_true", help="clear all bandwidth limits")
group.add_argument("-g", "--get", action="store_true", help="get all connected devices in LAN")

args = parser.parse_args()

# check if interface is specified and exist in PC
if args.device is None:
    parser.error("Please define an interface (--device <interface>)")
elif args.device not in netifaces.interfaces():
    parser.error("Invalid interface.")


# get ip address and netmask of device
device_interface = netifaces.ifaddresses(args.device)[netifaces.AF_INET][0]
ip_address = device_interface['addr']
netmask = netmask_to_cidr(device_interface['netmask'])


# validity check
if (args.show or args.clear or args.get) and (args.ip or args.download or args.upload):
    parser.error("-s, -c, -g are standalone arguments")
elif (args.show or args.clear or args.get) is False:
    if args.ip is None:
        parser.error("Must include IP when throttling (0.0.0.0 for global throttling)")
    elif args.ip is not None:
        try:
            ip_network = ipaddress.ip_interface(args.ip+"/"+netmask).network
            if args.ip != "0.0.0.0":
                check_ip_in_subnet = filter(lambda x: str(x) == ip_address, ip_network.hosts())
                if next(check_ip_in_subnet, None) is None:
                    parser.error("IP not in subnet")
        except ValueError:
            parser.error("Invalid IP format")
        finally:
            if args.download is None and args.upload is None:
                parser.error("Include either -d or -u argument (or both) with -ip")


if args.clear:
    clear_all_rule(args.device)
    exit(0)


if args.show:
    show_all_rule(args.device)
    exit(0)


if args.get:
    host_list = get_all_connected_host(args.device)
    for host in host_list:
        if host == ip_address:
            print("{} - This PC".format(host))
        else:
            print(host)
    print("Total hosts: {}".format(len(host_list)))
    exit(0)


# limit download speed if option given
if args.download is not None:
    download_speed_in_Kbps = args.download * 8
    if args.ip == '0.0.0.0':
        if int(download_speed_in_Kbps) == 0:
            for ip in get_all_connected_host(args.device):
                if ip != ip_address:
                    remove_download_speed_limit(args.device, ip)
        else:
            for ip in get_all_connected_host(args.device):
                if ip != ip_address:
                    limit_download_speed(args.device, ip, download_speed_in_Kbps)
    else:
        if int(download_speed_in_Kbps) == 0:
            remove_download_speed_limit(args.device, args.ip)
        else:
            limit_download_speed(args.device, args.ip, download_speed_in_Kbps)


# limit upload speed if option given
if args.upload is not None:
    upload_speed_in_Kbps = args.upload * 8
    if args.ip == '0.0.0.0':
        if int(upload_speed_in_Kbps) == 0:
            for ip in get_all_connected_host(args.device):
                if ip != ip_address:
                    remove_upload_speed_limit(args.device, ip)
        else:
            for ip in get_all_connected_host(args.device):
                if ip != ip_address:
                    limit_upload_speed(args.device, ip, upload_speed_in_Kbps)
    else:
        if int(upload_speed_in_Kbps) == 0:
            remove_upload_speed_limit(args.device, args.ip)
        else:
            limit_upload_speed(args.device, args.ip, upload_speed_in_Kbps)
