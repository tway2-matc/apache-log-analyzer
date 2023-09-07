#!/usr/bin/env python3
#author: Tighearnan Way, tway2@madisoncollege.edu
#This is a python script that reads a file of apache access logs, and analyzes them

import subprocess
import argparse
import requests

def main():
    #describes what the script will do
    print("This is a script that reads and analyzes apache logs.\n\n") 

    #creates a parser
    parser = argparse.ArgumentParser(description="A new parser for our script")

    #adds the filename as an argument
    parser.add_argument("-f", "--filename", dest="filename", required=True, type=str, help="Enter an Apache File Name to progress")
    filename = parser.parse_args().filename

    #analyzes the file and saves the results to a variable
    analysisString = IPAddressCount(filename)
    #opens the analysis file and writes the appropraite information
    with open("apache-analysis.txt", "w") as apacheAnalysis:
        apacheAnalysis.write(analysisString)

    #parses the string to make a list of the entries
    analysisList = analysisString.split("\n")

    #saves the last ip address as a variable and prints it
    #[-2], because the list has an empty string at the end of it
    lastIP = analysisList[-2].split(" ")[-1]
    print(lastIP)

    #looks up the IP and prints Bitdefender's categorization
    ipInfo = IPLookUp(lastIP)
    print(f"Bitdefender category: {ipInfo['data']['attributes']['last_analysis_results']['BitDefender']['result']}")
    #print(f"IP City:         {ipInfo['city']}")
    #print(f"IP Organization: {ipInfo['org']}")


#looks through the file and finds the 5 ips with the highest access counts and returning them as a string
def IPAddressCount(apache_log_file_name): 
    #runs the commands to get the required information
    fileCat = subprocess.run(f"cat {apache_log_file_name} | cut -d ' ' -f1 | sort -n | uniq -c | sort -n | tail -n5",stdout=subprocess.PIPE,shell=True)
    #saves it to a string and returns it
    fileString = fileCat.stdout.decode()
    return fileString

#looks up the ip address on virus total and returns the json
def IPLookUp(IPAddress):
    #gets api key and saves it to a dictionary
    with open("/home/student/.credentials-vt","r") as credentials:
        headerVariable = { 
                "X-Apikey": credentials.read()[8:-1]
            }
    address = f"https://virustotal.com/api/v3/ip_addresses/{IPAddress}"
    print(address)
    #gets the information and returns it as a json
    response = requests.get(address, headers=headerVariable)
    return response.json()

if __name__ == "__main__":
    main()