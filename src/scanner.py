
#!/usr/bin/env python3

import json
import time
import subprocess

# Scans provided IP range with params
# IP range and params will be taken from config

class Scanner:
    def __init__(self, config_path):
        config = {}
        with open(config_path, "r") as config_file:
            config = json.load(config_file)
        self.ports = config["scanConfig"]["ports"]
        self.intensity = config["scanConfig"]["intensity"]
        self.ip_list = config["scanConfig"]["ipList"]
        self.terminate = False

    def __build_scan_commands(self):
        t_arg = "-T" + str(self.intensity)

        port_arg = self.ports
        if port_arg == "fast":
            port_arg = "-F"
        elif port_arg == "all":
            port_arg = "-p1-65535"
        else:
            port_arg = "-p" + self.ports

        commands = []
        output_files = []
        for scan_num in range(len(self.ip_list)):
            output_file = "/tmp/scanResults" + str(scan_num)
            command = ["nmap", "-sV", "--open", t_arg, "-R", "--script=vulners/vulners.nse", "-oX", output_file, port_arg, self.ip_list[scan_num]]
            commands.append(command)
            output_files.append(output_file)
        print(commands)
        return commands, output_files
    
    def run_scans(self):
        commands, output_files = self.__build_scan_commands()
        self.terminate = False

        process_list = []
        for command in commands:
            process_list.append(subprocess.Popen(command, shell=False))
        
        for proc in process_list:
            while proc.poll() is None:
                if self.terminate:
                    proc.kill()
                else:
                    time.sleep(0.1)
        
        return output_files