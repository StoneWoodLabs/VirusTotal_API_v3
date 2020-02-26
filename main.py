import requests
import sys
from time import sleep
from prettytable import PrettyTable
import argparse


def api_call_upload(file, api_key, vt_url):
    try:
        try:
            file_data = open(file, "rb")
        except IOError:
            print("There was an error opening the file {}".format(file))
        post_response = requests.post(vt_url + "files",
                                      files={"file": file_data}, headers={"X-Apikey": api_key})
        file_data.close()
        response = post_response.json()
        vt_id = response.get("data").get("id")
        return vt_id
    except Exception as f:
        sys.exit(f)


def api_call_analysis(vt_id, api_key, vt_url):
    try:
        while True:
            file_report = requests.get(vt_url + "analyses/{}".format(vt_id), headers={"X-Apikey": api_key})
            file_report = file_report.json()
            status = str(file_report.get("data").get("attributes").get("status"))
            print("Status of Virus Total submission is: {}".format(status))
            if status == "completed":
                return file_report
            sleep(20)
    except Exception as f:
        sys.exit(f)


def print_hashes(hashes):
    basic_info_table = PrettyTable()
    basic_info_table.field_names = ["name", "md5", "sha1", "sha256"]
    basic_info_table.add_row([hashes.get("name"), hashes.get("md5"), hashes.get("sha1"),
                              hashes.get("sha256")])
    print("Hashes:\n" + str(basic_info_table) + "\n\n")


def print_stats(stats):
    stats_table = PrettyTable()
    stats_table.field_names = ["confirmed-timeout", "failure", "harmless", "malicious", "suspicious", "timeout",
                               "type-unsupported", "undetected"]
    stats_table.add_row(
        [stats.get("confirmed-timeout"), stats.get("failure"), stats.get("harmless"), stats.get("malicious"),
         stats.get("suspicious"), stats.get("timeout"), stats.get("type-unsupported"), stats.get("undetected")])
    print("Stats:\n" + str(stats_table))


def main():
    vt_url = "https://www.virustotal.com/api/v3/"
    parser = argparse.ArgumentParser(description="This program submits a file specified by the argument --file to "
                                                 "Virus Total. Apikey is required and can be obtained by "
                                                 "registering a Virus Total account.")
    parser.add_argument("--file", help="--file <file.exe> to specify file to analyze on Virus Total", required=True)
    parser.add_argument("--apikey", help="--apikey <apikey> to specify apikey to submit to Virus Total api",
                        required=True)
    args = parser.parse_args()
    vt_id = api_call_upload(args.file, args.apikey, vt_url)
    file_report = api_call_analysis(vt_id, args.apikey, vt_url)
    hashes = file_report.get("meta").get("file_info")
    print_hashes(hashes)
    stats = file_report.get("data").get("attributes").get("stats")
    print_stats(stats)


if __name__ == "__main__":
    main()
