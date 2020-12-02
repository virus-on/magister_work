#!/usr/bin/env python3

import subprocess
import time


class PDFOutput:
    def __init__(self, title_template_file, template_file, output_file):
        self.title_template_file = title_template_file
        self.template_file = template_file
        self.output_file = output_file


    def __build_title(self, data):
        fin = open(self.title_template_file, "rt")
        title_content = fin.read()
        fin.close()

        title_content = title_content.replace("%hostscan_number%", str(data["num_hosts"]))
        title_content = title_content.replace("%scan_time%", time.strftime('%H hours %M minutes %S seconds', time.gmtime(max(data["time_for_scan"]))) )
        title_content = title_content.replace("%critical_vlun_num%", str(data["critical_issues"]))
        title_content = title_content.replace("%high_vlun_num%", str(data["high_issues"]))
        title_content = title_content.replace("%medium_vlun_num%", str(data["medium_issues"]))
        title_content = title_content.replace("%low_vlun_num%", str(data["low_issues"]))

        if len(data["hosts"]) == 0:
            title_content = title_content.replace("%affected_hosts%", "None")
        else:
            ip_list = ""
            for ip in data["hosts"]:
                ip_list += "  - " + ip + "\n"
            title_content = title_content.replace("%affected_hosts%", ip_list)
        
        return title_content


    def __build_content_instance(self, template_str, ip, details):
        template_str = template_str.replace("%host_ip%", ip)

        if details["ip_critical_issue"] > 0:
            template_str = template_str.replace("%ip_critical_vlun_num%", '  - Critical: **{0}**\n'.format(details["ip_critical_issue"]))
        else:
            template_str = template_str.replace("%ip_critical_vlun_num%", "")
        if details["ip_high_issue"] > 0:
            template_str = template_str.replace("%ip_high_vlun_num%", '  - High: **{0}**\n'.format(details["ip_high_issue"]))
        else:
            template_str = template_str.replace("%ip_high_vlun_num%", "")
        if details["ip_medium_issue"] > 0:
            template_str = template_str.replace("%ip_medium_vlun_num%", '  - Medium: **{0}**\n'.format(details["ip_medium_issue"]))
        else:
            template_str = template_str.replace("%ip_medium_vlun_num%", "")
        if details["ip_low_issue"] > 0:
            template_str = template_str.replace("%ip_low_vlun_num%", '  - Low: **{0}**\n'.format(details["ip_low_issue"]))
        else:
            template_str = template_str.replace("%ip_low_vlun_num%", "")

        cve_list_str = ""
        for cve in details:
            if "CVE" in cve:
                concrete_cve_str = "  - {}\n".format(cve)
                concrete_cve_str += "    - Rating: {0}[{1}]\n".format(details[cve]["rating"], details[cve]["cvss"])
                concrete_cve_str += "    - Protocol: {0}\n".format(details[cve]["protocol"])
                if "service" in details[cve]:
                    concrete_cve_str += "    - Affected Software: {0}\n".format(details[cve]["service"])
                cve_list_str += concrete_cve_str
        template_str = template_str.replace("%cve_details%", cve_list_str)

        return template_str


    def __build_content(self, data):
        fin = open(self.template_file, "r")
        template_content_body = fin.read()
        fin.close()

        content = ""
        for ip in data["hosts"]:
            content += self.__build_content_instance(template_content_body, ip, data["hosts"][ip])
        
        return content


    def build_output_doc(self, data):
        content = self.__build_title(data)
        content += self.__build_content(data)
        md_file = self.output_file + ".md"
        fin = open(md_file, "wt")
        fin.write(content)
        fin.close()
        command = ["mdpdf", "-o", self.output_file, "--header", "{date},,{page}", md_file]
        proc = subprocess.Popen(command, shell=False)
        proc.wait()
        return self.output_file
        