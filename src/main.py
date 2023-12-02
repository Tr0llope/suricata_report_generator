import sys, json, os
from Report import ReportBuilder

# Create the report file with the same name as the input file in the reports directory
def create_output_file(file_name):
    try:
        extract_file_name = file_name.split("/")[-1].split(".")[0]
        output_file_name = "report_" + extract_file_name + ".rst"

        file_path = os.path.join("reports", output_file_name)
        f = open(file_path, "w")
        
        return f
    except Exception as e:
        print("Error: {}".format(e))

# Load the json data from the input file in memory
def load_json_data(file_name):
    try:
        data = []
        with open(file_name) as f:
            for json_object in f:
                try:
                    data.append(json.loads(json_object))
                except ValueError:
                    continue
            return data
    except Exception as e:
        print("Error: {}".format(e))

# With the option -pdf as argument of the command line, the report will be converted to pdf
def rst_file_to_pdf(file_name):
    try:
        os.system("rst2pdf {} -o {}".format(file_name, file_name.split(".")[0] + ".pdf"))
    except Exception as e:
        print("Error: {}".format(e))
    
    
if __name__ == "__main__":
    # Check if the input file is specified
    if len(sys.argv) < 2:
        print("Usage: python main.py <file_name> [-options]")
    else:
        # open the input file and load the json data
        file_name = sys.argv[1]
        output_file = create_output_file(file_name)
        data = load_json_data(file_name)
        
        # Create the report
        report = ReportBuilder(data, output_file)
        report.introduction(file_name.split("/")[-1])
        report.set_time()
        report.set_ip_addresses_info()
        report.set_domain_names_info()
        report.set_users_info()
        report.set_tcp_ip_services_info()
        report.set_alerted_signatures()
        report.set_detected_malwares()
        
        output_file.close()

        # Convert the report to pdf if the option -pdf is specified
        try:
            if sys.argv[2] == "-pdf":
                rst_file_to_pdf(output_file.name)
        except:
            pass