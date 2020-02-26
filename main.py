# Usage: python main.py --file <file> --apikey <apikey>
import requests
import sys
import argparse
from time import sleep
from prettytable import PrettyTable


# This function submits a file to Virus Total for analysis.
def api_call_upload(file, api_key, vt_url):
    try:
        # Attempt to open and read file as file_data, if error occurs exit program with error shown as the proper syntax
        # was not used or file does not exist.
        try:
            file_data = open(file, "rb")
        except IOError:
            sys.exit("There was an error opening the file {}".format(file))
        ''' 
        Send a file to Virus Total for analysis using v3 of it's api. v3 specifies the apikey must be sent as the 
        header "X-Apikey". Apikey used is the one used in argument --apikey, if this apikey is not valid an exception
        will be thrown and the program will exit with that error displayed. Rerun the program with a proper apikey.
        '''
        post_response = requests.post(vt_url + "files",
                                      files={"file": file_data}, headers={"X-Apikey": api_key})
        # Cleaning up file handle
        file_data.close()
        response = post_response.json()
        # If post api successful but api returned error, break out of program and print error
        if "error" in response:
            sys.exit(response)
        # If file uploaded successfully, but no response given then exit with error.
        vt_id = response.get("data").get("id")
        if vt_id == "None":
            sys.exit("File was uploaded successfully to Virus Total, but something with wrong with the "
                     "response: {}".format(str(response)))
        return vt_id
    except Exception as f:
        sys.exit("api_call_upload failed " + str(f))


# Function for getting the analysis back from Virus Total
def api_call_analysis(vt_id, api_key, vt_url):
    try:
        # Send a get API request, if the status is "queued" wait 20 seconds and check again.
        counter = 0
        while True:
            response = requests.get(vt_url + "analyses/{}".format(vt_id), headers={"X-Apikey": api_key})
            file_report = response.json()
            status = str(file_report.get("data").get("attributes").get("status"))
            # Print statement gives the user indication of activity and status of get request
            print("Status of Virus Total submission is: {}".format(status))
            if status == "completed":
                return file_report
            counter += 1
            '''
            # If the program takes longer than 15 minutes exit and show the status. 200 == success, api up. 
            # 404 == error, api down or there is an issue with your network / host. Time = (counter * sleep(secs)), 
            # first run (counter = 0) does not sleep and performs get api request immediately,
            '''
            if counter == 40:
                sys.exit("Virus total has taken 15 minutes to process, the api returned a " + str(response))
            # This is set for 20 seconds to not go over Virus Total public api limit of 4 requests per minute. Adjust
            # if you have an premium apikey and adjust counter accordingly.
            sleep(20)
    except Exception as f:
        sys.exit("api_call_analysis failed " + str(f))


# Print out hashes from the report in a table
def print_hashes(hashes):
    basic_info_table = PrettyTable()
    basic_info_table.field_names = ["name", "md5", "sha1", "sha256"]
    basic_info_table.add_row([hashes.get("name"), hashes.get("md5"), hashes.get("sha1"),
                              hashes.get("sha256")])
    print("Hashes:\n" + str(basic_info_table) + "\n\n")


# Print out statistical information from the report in a table
def print_stats(stats):
    stats_table = PrettyTable()
    stats_table.field_names = ["confirmed-timeout", "failure", "harmless", "malicious", "suspicious", "timeout",
                               "type-unsupported", "undetected"]
    stats_table.add_row(
        [stats.get("confirmed-timeout"), stats.get("failure"), stats.get("harmless"), stats.get("malicious"),
         stats.get("suspicious"), stats.get("timeout"), stats.get("type-unsupported"), stats.get("undetected")])
    print("Stats:\n" + str(stats_table))


def main():
    # --file and --apikey are required arguments to be passed through the program. A Virus Total apikey may be generated
    # by registering an account https://www.virustotal.com
    vt_url = "https://www.virustotal.com/api/v3/"
    parser = argparse.ArgumentParser(description="This program submits a file specified by the argument --file to "
                                                 "Virus Total. Apikey is required and can be obtained by "
                                                 "registering a Virus Total account.")
    parser.add_argument("--file", help="--file <file.exe> to specify file to analyze on Virus Total", required=True)
    parser.add_argument("--apikey", help="--apikey <apikey> to specify apikey to submit to Virus Total api",
                        required=True)
    args = parser.parse_args()

    # Example of api call for posting an file on Virus Total for analysis, and getting the basic report back.
    vt_id = api_call_upload(args.file, args.apikey, vt_url)
    file_report = api_call_analysis(vt_id, args.apikey, vt_url)

    # Print data received into tables, .get used to pull information from dictionary
    # .get returns "None" if nothing is found
    hashes = file_report.get("meta").get("file_info")
    print_hashes(hashes)
    stats = file_report.get("data").get("attributes").get("stats")
    print_stats(stats)


if __name__ == "__main__":
    main()
