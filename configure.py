#!/usr/bin/env python3

import json
import re


def input_intensity():
    print("Please input scan intensity from 0 to 5 where:")
    print("\t 0 - paranoid")
    print("\t 1 - sneaky")
    print("\t 2 - polite")
    print("\t 3 - normal")
    print("\t 4 - aggressive")
    print("\t 5 - insane")
    print("Scan intensity affects time needed to perform scan and amount of load it puts on network.")
    print("While \"paranoid\" and \"sneaky\" mode may be useful for avoiding IDS alerts, they will take an extraordinarily long time to scan thousands of machines or ports.")
    while True:
        intensity = input("Selected scan intensity(0 - 5): ")
        if int(intensity) >= 0 and int(intensity) <= 5:
            return intensity


def validatePortsInput(port):
    if (port.isnumeric()):
        return True
    else:
        match = re.match(r"^[0-9]+\-[0-9]+$", port)
        if (match == None):
            return False
        return True

def input_ports():
    print("Please specify ports you want to scan.")
    print("You can specify pots as range(e.g. 22-80) and specify concrete ports using comma(e.g. 22,5900). This options can be combined.")
    print("\tLeave empty scan all ports (1 – 65535)")
    print("\tType \"fast\" to scan 100 most common ports.")
    while True:
        ports = input("Input ports range: ")
        ports = ''.join(ports.split())
        if len(ports) == 0:
            return "all"
        elif ports.lower() == "fast":
            return "fast"
        else:
            try:
                for port in ports.split(','):
                    if not validatePortsInput(port):
                        raise ValueError("That is not a valid input!")
                return ports
            except ValueError as ve:
                print(ve)
                continue


def validate_ip_part(ipPart, canBeRange):
    if not canBeRange and not ipPart.isnumeric():
        return False

    if re.match(r"^[0-9]+\-?[0-9]*$", ipPart) == None:
        return False

    ipParts = ipPart.split("-")
    for i in ipParts:
        if not i.isnumeric or int(i) < 0 or int(i) > 255:
            return False
    if len(ipParts) == 2 and int(ipParts[0]) >= int(ipParts[1]):
        return False

    return True

def validate_ip_range(ipRange):
    try:
        partCanBeRange = "/" not in ipRange
        
        ipRangeParts = ipRange.split(".")
        if len(ipRangeParts) != 4:
            return False

        if not partCanBeRange:
            ipMask = int(ipRangeParts[3].split("/")[1])
            if ipMask < 0 or ipMask > 32:
                return False
        
        for i in range(4):
            current = ipRangeParts[i]
            if i == 3 and not partCanBeRange:
                current = current.split("/")[0]
            if not validate_ip_part(current, partCanBeRange):
                return False
        
        return True

    except Exception as ex:
        print(ex)
        return False

def input_ip_ranges():
    print("Please specify ip ranges you want to scan.")
    print("Ip ranges can be specified in multiple ways:")
    print("\t* 192.168.0.0/24")
    print("\t* 192.168.0.1-255")
    print("\t* 192.168.0.24 (as a single address)")
    ipList = set()
    while True:
        ip = input("Input ip range: ")
        ip = ''.join(ip.split())
        if len(ip) == 0 and len(ipList) != 0:
            return ipList
        elif len(ip) == 0 or not validate_ip_range(ip):
            print("Rejected!")
            continue
        else:
            ipList.add(ip)


def input_output_telegram_api():
    return input("Please input telegram api key(empty for no output through bot): ")

def input_output_webhook_url():
    return input("Please input url for output through webhook(empty for no output through webhook): ")


data = {
    "scanConfig": {
        "intensity": "5",
        "ports": "22",
        "ipList": []
    },
    "tgBot": {
        "apiKey": ""
    },
    "webhook": {
        "addr": ""
    }
}

data["scanConfig"]["intensity"] = input_intensity()
data["scanConfig"]["ports"] = input_ports()
data["scanConfig"]["ipList"] = list(input_ip_ranges())

while True:
    data["tgBot"]["apiKey"] = input_output_telegram_api()
    if (data["tgBot"]["apiKey"] == ""):
        print("No bot api key specified!")
        continue
    break

with open("config.json", "w") as write_file:
    json.dump(data, write_file, indent=4)

print("Done!")