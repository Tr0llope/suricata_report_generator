import ipaddress, re

class SuricataJsonParser ():
    def __init__ (self, data, output_file):
        self.data = data
        self.output_file = output_file

        # Regex patterns to check if an IP address is private
        self.private_ip_pattern_A_class = re.compile(r"^(10\.)")
        self.private_ip_pattern_B_class = re.compile(r"^(172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)")
        self.private_ip_pattern_C_class = re.compile(r"^(192\.168\.)")

    def get_private_ip_addresses(self):
        private_ip_list = []
        for i in range(len(self.data)):
            if self.data[i]["event_type"] != "stats":
                obj = self.data[i]
                
                # Check if there is an unknowed private IP address
                if self.is_private_ip_address(obj["src_ip"], self.private_ip_pattern_A_class, self.private_ip_pattern_B_class, self.private_ip_pattern_C_class) and obj["src_ip"] not in private_ip_list:
                    current_ip = obj["src_ip"]
                elif self.is_private_ip_address(obj["dest_ip"], self.private_ip_pattern_A_class, self.private_ip_pattern_B_class, self.private_ip_pattern_C_class) and obj["dest_ip"] not in private_ip_list:
                    current_ip = obj["dest_ip"]
                else:
                    continue
                
                # Check if the private IP address is already in the list in order to avoid duplicates
                if current_ip not in private_ip_list and obj["event_type"] == "smb": # If we have a smb request, we can guess the OS
                        private_ip_list.append(current_ip)
                        network_netmask = self.get_network_netmask(current_ip, self.private_ip_pattern_A_class, self.private_ip_pattern_B_class, self.private_ip_pattern_C_class)
                        probable_os = self.guess_os(obj["smb"]["dialect"])
                        self.output_file.write("{}".format(current_ip) + " "*(17-len(current_ip)) +"{} ".format(network_netmask) + " "*(29-len(network_netmask)) +"{}\n".format(probable_os))
                elif current_ip not in private_ip_list and obj["event_type"] == "flow": # If we have a flow request, we can't guess the OS but can have a private IP address
                    private_ip_list.append(current_ip)
                    network_netmask = self.get_network_netmask(current_ip, self.private_ip_pattern_A_class, self.private_ip_pattern_B_class, self.private_ip_pattern_C_class)
                    self.output_file.write("{}".format(current_ip) + " "*(17-len(current_ip)) +"{}\n".format(network_netmask))
        
    def get_domain_names(self):
        domain_names = [] # List of unique domain names

        # Regex pattern to check if a domain name is a windows domain name
        pattern_windows_domain_name = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:microsoft\.com|windows\.com|windowsupdate\.com|msftncsi\.com)\b")

        for obj in self.data:
            if obj.get("event_type") == "dns" and obj.get("dns", {}).get("type") == "query": # Check if the object is a DNS query
                domain_name = obj["dns"]["rrname"]
                if domain_name not in domain_names:
                    if pattern_windows_domain_name.match(domain_name):
                        domain_names.append(domain_name)

        # Sort the domain names and print them in two columns
        if domain_names:
            domain_names = sorted(domain_names)
            count = 0
            l = 0
            for domain_name in domain_names:
                if count % 2 == 0:
                    l = len(domain_name)
                    self.output_file.write("{}".format(domain_name))
                else:
                    self.output_file.write(" "*(70-l) + "{}\n".format(domain_name))
                count += 1
            if len(domain_names) % 2 != 0:
                self.output_file.write("\n")
        else:
            self.output_file.write("No domain names found.\n\n")
        

    
    def get_users_from_smb_kerberos_requests(self):
        users = [] # List of unique users

        for entry in self.data:
            if entry.get("event_type") == "smb" :
                smb_request = entry["smb"]
                
                # Check if the SMB request contains a kerberos field
                if smb_request.get("kerberos"):
                    user = smb_request["kerberos"]["snames"][0]
                    if user not in users:
                        users.append(user)

        if users:
            users = sorted(users)
            self.output_file.write("Here are the extracted users from kerberos requests through smb protocol:\n\n")
            for user in users:
                if user=="cifs":
                    user="cifs (Common Internet File System)"
                self.output_file.write(f"* {user}\n")
        else:
            self.output_file.write("No users found. \n\n")

    # Ressources: https://www.it-connect.fr/quelle-version-du-protocole-smb-utilisez-vous/
    # We can guess the OS of the client thanks to the dialect used by SMB.
    def guess_os(self, dialect):
        if dialect == "2.??":
            return "Windows 7 or Windows Server 2008 R2"
        elif dialect == "3.11":
            return "Windows 10 or Windows Server 2016"
        elif dialect == "NT LM 0.12":
            return "Windows XP or Windows Server 2003"
        else:
            return "Unknown"
    
    # Get the network and the netmask of a private IP address
    def get_network_netmask(self, ip, private_ip_pattern_A_class, private_ip_pattern_B_class, private_ip_pattern_C_class):
        ip_format = ipaddress.ip_address(ip)
        if private_ip_pattern_A_class.match(ip):
            return "10.0.0.0/8 (255.0.0.0)"
        elif private_ip_pattern_B_class.match(ip):
            return "172.16.0.0/12 (255.240.0.0)"
        elif private_ip_pattern_C_class.match(ip):
            return "192.168.0.0/16 (255.255.0.0)"

    # Check if an IP address is private
    def is_private_ip_address(self, ip, private_ip_pattern_A_class, private_ip_pattern_B_class, private_ip_pattern_C_class):
        if private_ip_pattern_A_class.match(ip) or private_ip_pattern_B_class.match(ip) or private_ip_pattern_C_class.match(ip):
            return True
        return False

    # get all the tcp/ip services that have been used  
    def get_tcp_ip_services(self):
        services = []
        for i in range(len(self.data)):
            if self.data[i]["event_type"] != "stats":
                obj = self.data[i]
                if obj["event_type"] == "flow" and obj.get("app_proto"):
                    if obj["app_proto"] not in services and obj["app_proto"] != "failed": # Services are the field app_proto of the flow requests
                        services.append(obj["app_proto"])
                        self.output_file.write("* {}\n".format(obj["app_proto"]))
    
    # get all the signatures that have been alerted
    def get_alerted_signatures(self):
        signatures = []
        for i in range(len(self.data)):
            if self.data[i]["event_type"] == "alert":
                obj = self.data[i]
                if obj["alert"]["signature"] not in signatures:
                    signatures.append(obj["alert"]["signature"])
                    self.output_file.write("* {}\n".format(obj["alert"]["signature"]))
    
    # get informations about malwares detected: signature, family, severity, IOC
    def get_detected_malwares(self):
        impacted_ip = []
        signatures = []
        for i in range(len(self.data)):
            if self.data[i]["event_type"] == "alert":
                obj = self.data[i]
                if self.is_private_ip_address(obj["src_ip"], self.private_ip_pattern_A_class, self.private_ip_pattern_B_class, self.private_ip_pattern_C_class) and obj["src_ip"] not in impacted_ip:
                    impacted_ip.append(obj["src_ip"])
                
                if obj.get("alert", {}).get("signature") and obj['alert']['signature'] not in signatures:
                        signatures.append(obj['alert']['signature'])
                        if obj["alert"]["signature"].split(" ")[1] == "MALWARE":
                            if obj.get("alert", {}).get("metadata", {}).get("malware_family") :
                                self.output_file.write(f"* signature: {obj['alert']['signature']}\n\n")
                                self.output_file.write(f"   * family: {obj['alert']['metadata']['malware_family'][0]}\n")
                            if obj.get("alert", {}).get("metadata", {}).get("signature_severity") :
                                self.output_file.write("   * severity: {}\n".format(obj["alert"]["metadata"]["signature_severity"][0]))
                            if obj.get("http", {}).get("hostname") :
                                self.output_file.write(f"   * (IOC) ip source: {obj['src_ip']} ip destination: {obj['dest_ip']} hostname: {obj['http']['hostname']}\n\n|\n\n")
                            else:
                                self.output_file.write(f"   * (IOC) ip source: {obj['src_ip']} ip destination: {obj['dest_ip']}\n\n|\n\n")
        self.output_file.write("Internal IP addresses impacted by malware: {}\n\n|\n\n".format(impacted_ip))
    
    # get all the hashes of files that have been detected as malwares 
    def get_hashes_of_detected_malwares(self):
        hashes = []
        self.output_file.write("Hashes of detected malwares:\n\n")
        for i in range(len(self.data)):
            if self.data[i]["event_type"] == "alert":
                obj = self.data[i]
                if obj.get("alert", {}).get("signature") :
                    if obj["alert"]["signature"].split(" ")[1] == "MALWARE":
                        if obj.get("tls", {}).get("ja3", {}).get("hash"):
                            if obj["tls"]["ja3"]["hash"] not in hashes:
                                    hashes.append(obj["tls"]["ja3"]["hash"])
                                    
                                    self.output_file.write(f"* {obj['alert']['signature']}\n")
                                    self.output_file.write("   * ja3: {}\n".format(obj["tls"]["ja3"]["hash"]))
                                    self.output_file.write("   * ja3s: {}\n".format(obj["tls"]["ja3s"]["hash"]))
                                    self.output_file.write("   * fingerprint: {}\n".format(obj["tls"]["fingerprint"]))

        if len(hashes) == 0:
            self.output_file.write("No hashes found.\n\n")
                        


                
                