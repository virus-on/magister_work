#!/usr/bin/env python3

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

# Get's list of xml scans, process it and recombine into output data structure
# This data structure can be used for report generation

class XMLScanProcessor:
    def __init__(self):
        self.cve_tree = {}


    def add_scan_file(self, xml_file_path):
        xml_tree = ET.ElementTree(file=xml_file_path)
        xml_root = xml_tree.getroot()

        if not "low_issues" in self.cve_tree:
            self.cve_tree["low_issues"] = 0
        if not "medium_issues" in self.cve_tree:
            self.cve_tree["medium_issues"] = 0
        if not "high_issues" in self.cve_tree:
            self.cve_tree["high_issues"] = 0
        if not "critical_issues" in self.cve_tree:
            self.cve_tree["critical_issues"] = 0

        if not "hosts" in self.cve_tree:
            self.cve_tree["hosts"] = {}

        for stats in xml_root.iter("nmaprun"):
            out_start_time = int(stats.attrib["start"])
            for finish in stats.iter("finished"):
                out_finish_time = int(finish.attrib["time"])

        out_time_for_scan = out_finish_time - out_start_time
        if "time_for_scan" in self.cve_tree:
            self.cve_tree["time_for_scan"].append(out_time_for_scan)
        else:
            self.cve_tree["time_for_scan"] = [out_time_for_scan]

        # for every host
        for host in xml_root.iterfind('.//host'):
            # update number of scanned hosts
            if "num_hosts" in self.cve_tree:
                self.cve_tree["num_hosts"] = self.cve_tree["num_hosts"] + 1
            else:
                self.cve_tree["num_hosts"] = 1

            # get ip
            for addr_elem in host.iter("address"): 
                out_host_ip = addr_elem.attrib["addr"]
            
            # for every port of a host
            for port in host.iterfind('.//port'):
                # try extract service name and version
                for service_elem in port.iter("service"):
                    out_service_name = ""
                    if "product" in service_elem.attrib:
                        out_service_name = (service_elem.attrib.get("product", "") + " " + service_elem.attrib.get("version", "")).strip()
                    out_protocol_name = service_elem.attrib.get("name", "")
                
                for cve in port.iterfind('.//table/table'):
                    vun_type = cve.findtext("./elem[@key='type']")
                    # only CVE
                    if not 'cve' in vun_type:
                        continue

                    if not out_host_ip in self.cve_tree["hosts"]:
                        self.cve_tree["hosts"][out_host_ip] = {}
                        self.cve_tree["hosts"][out_host_ip]["ip_low_issue"] = 0
                        self.cve_tree["hosts"][out_host_ip]["ip_medium_issue"] = 0
                        self.cve_tree["hosts"][out_host_ip]["ip_high_issue"] = 0
                        self.cve_tree["hosts"][out_host_ip]["ip_critical_issue"] = 0

                    out_cvss = float(cve.findtext("./elem[@key='cvss']"))
                    if out_cvss > 8.9:
                        out_cvss_text_rating = "critical"
                        self.cve_tree["critical_issues"] += 1
                        self.cve_tree["hosts"][out_host_ip]["ip_critical_issue"] += 1
                    elif out_cvss > 6.9:
                        out_cvss_text_rating = "high"
                        self.cve_tree["high_issues"] += 1
                        self.cve_tree["hosts"][out_host_ip]["ip_high_issue"] += 1
                    elif out_cvss > 3.9:
                        out_cvss_text_rating = "medium"
                        self.cve_tree["medium_issues"] += 1
                        self.cve_tree["hosts"][out_host_ip]["ip_medium_issue"] += 1
                    elif out_cvss > 0:
                        out_cvss_text_rating = "low"
                        self.cve_tree["low_issues"] += 1
                        self.cve_tree["hosts"][out_host_ip]["ip_low_issue"] += 1
                    else:
                        out_cvss_text_rating = "none"
                    out_cve_id = cve.findtext("./elem[@key='id']")
                        
                    self.cve_tree["hosts"][out_host_ip][out_cve_id] = {
                            "cvss": out_cvss,
                            "rating": out_cvss_text_rating,
                            "service": out_service_name,
                            "protocol": out_protocol_name }