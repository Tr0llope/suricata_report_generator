import ipaddress, re

class SuricataJsonParser ():
    def __init__ (self, data, output_file):
        self.data = data
        self.output_file = output_file
        self.private_ip_pattern_A_class = re.compile(r"^(10\.)")
        self.private_ip_pattern_B_class = re.compile(r"^(172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)")
        self.private_ip_pattern_C_class = re.compile(r"^(192\.168\.)")

    def new_get_private_ip_addresses(self):
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

                if current_ip not in private_ip_list and obj["event_type"] == "smb":
                        private_ip_list.append(current_ip)
                        network_netmask = self.get_network_netmask(current_ip, self.private_ip_pattern_A_class, self.private_ip_pattern_B_class, self.private_ip_pattern_C_class)
                        probable_os = self.guess_os(obj["smb"]["dialect"])
                        self.output_file.write("{}".format(current_ip) + " "*(17-len(current_ip)) +"{} ".format(network_netmask) + " "*(29-len(network_netmask)) +"{}\n".format(probable_os))
                elif current_ip not in private_ip_list and obj["event_type"] == "flow":
                    private_ip_list.append(current_ip)
                    network_netmask = self.get_network_netmask(current_ip, self.private_ip_pattern_A_class, self.private_ip_pattern_B_class, self.private_ip_pattern_C_class)
                    self.output_file.write("{}".format(current_ip) + " "*(17-len(current_ip)) +"{}\n".format(network_netmask))


    # def get_ip_addresses(self):
    #     ip_list = []
    #     for i in range(len(self.data)):
    #         if self.data[i]["event_type"] != "stats":
    #             obj = self.data[i]
    #             if obj["src_ip"] not in ip_list:
    #                 ip_list.append(obj["src_ip"])
    #             if obj["dest_ip"] not in ip_list:
    #                 ip_list.append(obj["dest_ip"])

    #     private_ip_pattern_A_class = re.compile(r"^(10\.)")
    #     private_ip_pattern_B_class = re.compile(r"^(172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)")
    #     private_ip_pattern_C_class = re.compile(r"^(192\.168\.)")

    #     private_ip_addresses = self.get_private_ip_addresses(ip_list, private_ip_pattern_A_class, private_ip_pattern_B_class, private_ip_pattern_C_class)
    #     if len(private_ip_addresses) > 0:
    #         for ip in private_ip_addresses:
    #             network_netmask = self.get_network_netmask(ip, private_ip_pattern_A_class, private_ip_pattern_B_class, private_ip_pattern_C_class)
                
    #             self.output_file.write("{}".format(ip) + " "*(17-len(ip)) +"{}\n".format(network_netmask))
        
    def get_domain_names(self):
        domain_names = []

        for obj in self.data:
            if obj.get("event_type") == "dns" and obj.get("dns", {}).get("type") == "query":
                domain_name = obj["dns"]["rrname"]
                if domain_name not in domain_names:
                    domain_names.append(domain_name)

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
        return domain_names
        

    
    def get_users_from_smb_kerberos_requests(self):
        users = []
        dialects = []

        for entry in self.data:
            if entry.get("event_type") == "smb" :
                smb_request = entry["smb"]
                # if smb_request["dialect"] not in dialects:
                #     dialects.append(smb_request["dialect"])
                
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
        # if dialects:
        #     dialects = sorted(dialects)
        #     self.output_file.write("Here are the extracted dialects from smb requests:\n\n")
        #     for dialect in dialects:
        #         self.output_file.write(f"* {dialect} ({self.guess_os(dialect)})\n")
        #     self.output_file.write("\n")

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
        
    # def get_private_ip_addresses(self, ip_list, private_ip_pattern_A_class, private_ip_pattern_B_class, private_ip_pattern_C_class):
    #     private_ip_addresses = []
    #     for ip in ip_list:
    #         if private_ip_pattern_A_class.match(ip) or private_ip_pattern_B_class.match(ip) or private_ip_pattern_C_class.match(ip):
    #             private_ip_addresses.append(ip)
    #     return private_ip_addresses
    
    def get_network_netmask(self, ip, private_ip_pattern_A_class, private_ip_pattern_B_class, private_ip_pattern_C_class):
        ip_format = ipaddress.ip_address(ip)
        if private_ip_pattern_A_class.match(ip):
            return "10.0.0.0/8 (255.0.0.0)"
        elif private_ip_pattern_B_class.match(ip):
            return "172.16.0.0/12 (255.240.0.0)"
        elif private_ip_pattern_C_class.match(ip):
            return "192.168.0.0/16 (255.255.0.0)"

    def is_private_ip_address(self, ip, private_ip_pattern_A_class, private_ip_pattern_B_class, private_ip_pattern_C_class):
        if private_ip_pattern_A_class.match(ip) or private_ip_pattern_B_class.match(ip) or private_ip_pattern_C_class.match(ip):
            return True
        return False
    
    def get_tcp_ip_services(self):
        services = []
        for i in range(len(self.data)):
            if self.data[i]["event_type"] != "stats":
                obj = self.data[i]
                if obj["event_type"] == "flow" and obj.get("app_proto"):
                    if obj["app_proto"] not in services and obj["app_proto"] != "failed":
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
    
    # get informations about malwares detected: name, type, family, etc.
    def get_detected_malwares(self):
        impacted_ip = []
        for i in range(len(self.data)):
            if self.data[i]["event_type"] == "alert":
                obj = self.data[i]
                if self.is_private_ip_address(obj["src_ip"], self.private_ip_pattern_A_class, self.private_ip_pattern_B_class, self.private_ip_pattern_C_class) and obj["src_ip"] not in impacted_ip:
                    impacted_ip.append(obj["src_ip"])
                if obj.get("alert", {}).get("metadata", {}).get("former_category") :
                    if 'MALWARE' in obj["alert"]["metadata"]["former_category"]:
                        self.output_file.write("* {}\n\n".format(obj))
                        if obj.get("alert", {}).get("metadata", {}).get("malware_family") :
                            self.output_file.write("   * family: {}\n".format(obj["alert"]["metadata"]["malware_family"][0]))
                        if obj.get("alert", {}).get("metadata", {}).get("signature_severity") :
                            self.output_file.write("   * severity: {}\n".format(obj["alert"]["metadata"]["signature_severity"][0]))
                        if obj.get("http", {}).get("hostname") :
                            self.output_file.write("* IOC: {} hostname: {}\n\n".format(obj["src_ip"], obj["http"]["hostname"]))
        self.output_file.write("Internal IP addresses impacted by malware: {}\n\n|\n\n".format(impacted_ip))
        


                
   # get hostname and ip for each malware alert                 
    def get_indicators_of_compromise(self):
        self.output_file.write("todo\n\n")
        indicators = []
        for i in range(len(self.data)):
            if self.data[i]["event_type"] == "alert":
                obj = self.data[i]
                