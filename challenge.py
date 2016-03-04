import json
import datetime
import re
import urllib
from urllib2 import urlopen
import urllib2
import postfile

data = []
option = 0

def askUserForInput():
    userInputList = list()
    question = raw_input("Do you want to search by IP, port, url, file, domain or connection type? ")
    if question.lower() == "ip":
        global option
        option = 1;
        while True:
            inputList = raw_input("Please Enter IP or Quit: ")
            if inputList.lower() == "quit":
                return userInputList
            userInputList.append(inputList)
    elif question.lower() == "port":
        global option
        option = 2
        while True:
            inputList = raw_input("Please Enter port or Quit: ")
            if inputList.lower() == "quit":
                return userInputList
            userInputList.append(inputList)
    elif question.lower() == "url":
        global option
        option = 3
        while True:
            inputList = raw_input("Please Enter url or Quit: ")
            if inputList.lower() == "quit":
                return userInputList
            userInputList.append(inputList)
    elif question.lower() == "file":
        global option 
        option = 4
        while True:
            inputList = raw_input("Please Enter File path or Quit: ")
            if inputList.lower() == "quit":
                return userInputList
            userInputList.append(inputList)
    elif question.lower() == "domain":
        global option
        option = 5
        while True:
            inputList = raw_input("Please Enter a domain or Quit: ")
            if inputList.lower() == "quit":
                return userInputList
            userInputList.append(inputList)
    elif question.lower() == "connection type":
        global option
        option = 6
        while True:
            inputList = raw_input("Please enter a connection type or quit: ")
            if inputList.lower() == "quit":
                return userInputList
            userInputList.append(inputList)
    else:
        print "ERROR: No matching user input"
        return

def googleSafeBrowsing(input):
    for url in input:
        encoded_url = urllib.quote_plus(url)
        request_URL = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=demo-app&key=AIzaSyCzfGJHemwR01jYtt_pYHQrtyOgrTM-Yaw&appver=1.0.0&pver=3.1&url="
        request_URL+= encoded_url
        content = urllib2.urlopen(request_URL).read()
        print url
        if not content :
            print "Results: ok"
        else:
            print "Results:",content
        print "Source: Google Safe Browsing Lookup"
        print "-------------------------------------------"

def virusTotalURL(input):
    for url in input:
        #Request Reports
        api_key = "3e60acbae95913aa8b36c40c74e2e909150366465cce9e886fcd448d85a72a17"
        request_URL = "https://www.virustotal.com/vtapi/v2/url/scan"
        parameters = {"url": url,
                      "apikey": api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(request_URL, data)
        response = urllib2.urlopen(req)
        req_json = response.read()
        #Recieve Reports
        recieve_url = "http://www.virustotal.com/vtapi/v2/url/report"
        recieve_param = {"resource": url, "apikey": api_key}
        recieve_data = urllib.urlencode(recieve_param)
        recieve_req = urllib2.Request(recieve_url, recieve_data)
        recieve_response = urllib2.urlopen(recieve_req)
        json_recieve = recieve_response.read()
        parsed_json = json.loads(json_recieve)
        print parsed_json['url']
        print parsed_json['scan_date']
        print "Positives: ",parsed_json['positives']
        for test in parsed_json['scans']:
            print test + ": " + parsed_json['scans'][test]['result']
        print "Source: VirusTotal"    
        print "--------------------------------------------"

def virusTotalIP(input):
    for ip in input:
        print ip
        api_key = "3e60acbae95913aa8b36c40c74e2e909150366465cce9e886fcd448d85a72a17"
        vtIP_url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
        vtIP_param = {"ip": ip, 'apikey': api_key}
        response = urllib.urlopen('%s?%s' % (vtIP_url, urllib.urlencode(vtIP_param))).read()
        response_dict = json.loads(response)
        if response_dict['verbose_msg'] == 'Missing IP address':
            print "IP Address Not Found"
            print "Source: Virus Total"
            print "--------------------------------------------"
        else:
            print response_dict['verbose_msg']
            for index in range(len(response_dict['resolutions'])):
                print "Last Resolved:", response_dict['resolutions'][index]['last_resolved'] + \
                ", Host Name:", response_dict['resolutions'][index]['hostname']
            print "Detected URLs"
            for i in range(len(response_dict['detected_urls'])):
                print "URL:", response_dict['detected_urls'][i]['url'] + \
                ", Positives:", response_dict['detected_urls'][i]['positives'], \
                ", Total:", response_dict['detected_urls'][i]['total'], \
                ", Scan Date:", response_dict['detected_urls'][i]['scan_date']
            print "Source: Virus Total"
            print "--------------------------------------------"
        

def virusTotalFile(input):
    for file in input:
        #Request File Scan
        api_key = "3e60acbae95913aa8b36c40c74e2e909150366465cce9e886fcd448d85a72a17"
        host = "www.virustotal.com"
        selector = "https://www.virustotal.com/vtapi/v2/file/scan"
        fields = [("apikey", api_key)]
        file_to_send = open(file, "rb").read()
        files = [("file", file, file_to_send)]
        json_request = postfile.post_multipart(host, selector, fields, files)
        json_loads = json.loads(json_request)
        scan_id = json_loads['scan_id']
        #Recieve File Scan
        url = "https://www.virustotal.com/vtapi/v2/file/report"
        parameters = {"resource": scan_id, "apikey": api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json_response = response.read()
        parsed_json = json.loads(json_response)
        print file
        print "Positives:", parsed_json['positives']
        print "Total:", parsed_json['total']
        for scan in parsed_json['scans']:
            print "Name:",scan, "Detected:", parsed_json['scans'][scan]["detected"], \
            "Version:", parsed_json['scans'][scan]["version"], "Result:", \
            parsed_json['scans'][scan]["result"]
        print "Source: VirusTotal"
        print"--------------------------------------------"

def virusTotalDomain(input):
    for domain in input:
        api_key = "3e60acbae95913aa8b36c40c74e2e909150366465cce9e886fcd448d85a72a17"    
        domain_url = "https://www.virustotal.com/vtapi/v2/domain/report"
        domain_para = {"domain": domain, "apikey": api_key}
        domain_response = urllib.urlopen('%s?%s' % (domain_url, urllib.urlencode(domain_para))).read()
        domain_dict = json.loads(domain_response)
        print "Domain:", domain
        print domain_dict['verbose_msg']
        for index in range(len(domain_dict['resolutions'])):
            print "Last Resolved:", domain_dict['resolutions'][index]['last_resolved'], \
            "IP Address:", domain_dict['resolutions'][index]['ip_address']
        for i in range(len(domain_dict['detected_urls'])):
            print "URL:", domain_dict['detected_urls'][i]['url'], \
            "Positives:", domain_dict['detected_urls'][i]['positives'], \
            "Total:", domain_dict['detected_urls'][i]['total'], \
            "Scan Date:", domain_dict['detected_urls'][i]['scan_date']
        print "Source: Virus Total"
        print "---------------------------------------------"


def phishTank(input):
    for url in input:
        request_url = "http://checkurl.phishtank.com/checkurl/"
        #encoded_url = urllib.quote_plus(url)
        app_key = "ac7dc510c331a3a667ba3d1c4074b30a4b17c72d8857198f65aaa14f864b3437"
        pt_params = {"url": url, "format": "json", "app_key": app_key}
        pt_data = urllib.urlencode(pt_params)
        pt_req = urllib2.Request(request_url, pt_data)
        pt_response = urllib2.urlopen(pt_req)
        json_pt_response = pt_response.read()
        parsed_pt_json = json.loads(json_pt_response)
        print parsed_pt_json['results']['url']
        print parsed_pt_json['results']['in_database']
        print "Source: PhishTank" 
        print "--------------------------------------------"

def malwr(input):
    for path in input:
        request_url = "https://malwr.com/api/analysis/add/"
        malwr_key = "7af76e795e67495ba68226ac7d5a77ed"
        malwr_params = {"api_key": malwr_key, "file": path}
        malwr_data = urllib.urlencode(malwr_params)
        malwr_req = urllib2.Request(request_url, malwr_data)
        malwr_response = urllib2.urlopen(malwr_req)
        json_malwr_response = malwr_response.read()
        parsed_malwr_json = json.loads(json_malwr_response)
        print parsed_malwr_json

def DShieldIP(input):
    for ip in input:
        request_url = "http://isc.sans.edu/api/ip/" + ip + "?json"
        DShield_Response = urlopen(request_url)
        json_DShield = json.load(DShield_Response)
        print "IP Searched:", json_DShield['ip']['network']
        print "Attacks:", json_DShield['ip']['attacks']
        print "Max Risk:",json_DShield['ip']['maxrisk']
        print "Source: DShield"
        print "--------------------------------------------"

def DShieldPort(input):
    for port in input:
        request_url = "http://isc.sans.edu/api/port/" + port + "?json"
        DShield_Response = urlopen(request_url)
        json_DShield_Port = json.load(DShield_Response)
        print "Port Searched:",json_DShield_Port['data']['portin']
        print "Date:", json_DShield_Port['data']['date']
        print "Name:", json_DShield_Port['services']['udp']['name']
        print "Service:", json_DShield_Port['services']['udp']['service']
        print "Source: DShield"
        print "---------------------------------------------"

def printData(data):
    for key in data:
        if key == 'victimIP' or key == 'attackerIP' or key == 'connectionType' or key == 'victimPort' or key == 'attackerPort':
            print key + " : " + str(data[key])

def printStuff(jsonData, userInput):
    obj = json.loads(jsonData['payload'])
    for uIn in userInput:
        print uIn
        for key in obj:
            if str(obj[key]) == uIn:
                printData(obj)
                time = re.split(r"[-T:.+]", jsonData['timestamp']['$date'])
                print "Date:",str(datetime.date(int(time[0]), int(time[1]), int(time[2])))
                print "---------------------------------------------"

with open("honeypot.json") as f:
        for line in f:
            data.append(json.loads(line))

userInputs = askUserForInput()

if option == 1:
    for jsonData in data:
        printStuff(jsonData, userInputs)
    DShieldIP(userInputs)
    virusTotalIP(userInputs)

elif option == 2:
    for jsonData in data:
        printStuff(jsonData, userInputs)
    DShieldPort(userInputs)

elif option == 3:
    phishTank(userInputs)
    virusTotalURL(userInputs)
    googleSafeBrowsing(userInputs)

elif option == 4:
    virusTotalFile(userInputs)

elif option == 5:
    virusTotalDomain(userInputs)

elif option == 6:
    for jsonData in data:
        printStuff(jsonData, userInputs)


#virusTotalDomain(userInputs)
#virusTotalIP(userInputs)
#malwr(userInputs)
#phishTank(userInputs)
#for jsonData in data:
    #printStuff(jsonData, userInputs)
#googleSafeBrowsing(userInputs)
