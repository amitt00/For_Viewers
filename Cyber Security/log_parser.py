import pandas as pd
import re
from datetime import datetime
from tqdm import tqdm
import requests
import time
import matplotlib.pyplot as plt
import json
import os
import sys

def log_reader(filename):
    # open the log file and read its content
    try:
        with open(filename, 'r') as f:
            log = f.read()
        # define the regex pattern to match the start of each log line with the IP address
        pattern = r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \d+\.\d+\.\d+\.\d+ .*'
        # use the findall function from the re module to extract all matching lines
        matches = re.findall(pattern, log, flags=re.MULTILINE)
        return matches
    except Exception as e:
        print("Error in reading file :",e)

def virustotal_check(api_key,df=pd.DataFrame()):
        filename='report.json'
        if not os.path.isfile(filename):
            # Open the file in write mode and create it if it doesn't exist
            with open('Result.json', 'w') as file:
                # Write an empty list as the initial content
                json.dump([], file)
        for col in ["src_ip",'dstip','URL']:
            print("[+] Processing ",col," in logs ")
            count=0
            for index,value in tqdm(enumerate(df[col].unique()[:1])):
                    for key_index,key in enumerate(api_key):
                        try:
                            if col!="URL":
                                r= requests.get("https://virustotal.com/api/v3/ip_addresses/%s" %value, headers={'User-agent': 'Mozila/5.0 (X11; Ubuntu; Linux x86_64) Gecko/20100101', 'x-apikey': '%s' %key}).json()
                                break
                            else:
                                r= requests.get("https://www.virustotal.com/api/v3/urls/report", headers={'User-agent': 'Mozila/5.0 (X11; Ubuntu; Linux x86_64) Gecko/20100101', 'x-apikey': '%s' %key},data={"url":value}).json()
                                break
                        except Exception as e:
                            print("Limit exceeded for API:",key)
                            if key_index<len(api_key):
                                print("\nUsing Api:",api_key[key_index+1])
                            break
                    print("Report fetched")
                    dict_web   =r["data"]["attributes"]["last_analysis_results"]
                    report_data=r["data"]["attributes"]["last_analysis_stats"]
                    # report_keys=report_data.keys()
                    # report_values=report_data.values()
                    report_data.update({"ip/url":value})
                    print(report_data)
                    total_engine=sum([int(i) for i in report_data.values() if len(str(i))<4])
                    count+=1
                    tagg=[]
                    if report_data["malicious"] >0:
                        tagg.append("malicious")
                    elif report_data["suspicious"] >0:
                        tagg.append("suspicious")

                    for tags in tagg:
                            eng_name=[]
                            for i in dict_web:
                                    if dict_web[i]["category"] == tags:
                                        eng_name.append(dict_web[i]["engine_name"])
                            report_data.update({str(tags)+"_ScanningService":eng_name})
                         #   text="The %s was rated for " %value + str(tags)+ "  on  " + str(report_data[tags])+ " engine out of  " + str(total_engine)+ " engines. the engines which reported this are  " +str(eng_name)[1:-1]+ " .\n"
                         #   report_data.update({"Report":text})

                    with open(filename,"a") as f:
                        json.dump(report_data,f)
                        f.write("\n")
                        f.close()
                    time.sleep(0.5)
                    break                                         ###### comment to turn off(sample mode)
            print("Processed ",count," values in column :",col)

def log_parser(filename,save_file=True):
    logs=log_reader(filename)
    extracted_values = []
    for i in logs:
            port             = re.findall(r'\s\d{2,4}\s-\s',i)[0].replace("-","").replace(" ","")
            partition        = re.split(r'\s\d{2,4}\s-\s',i)
            part1 ,part2     = partition[0],partition[1]
            date_time         = re.findall(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',part1)[0]
            src_ip           = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',part1)[0]
            part11           = re.split(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s',part1)[-1]
            request,endpoint = part11.split(" ")[:2]
            dstip            = re.findall(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',part2)[0].replace(" ","")
            part21           = re.sub(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s',"",part2)
            try:
              part22           = re.findall(r'\d{3}\s\d+\s\d+\s\d{3}',part21)[0]
              Status,Error,Duration,Size=part22.strip().split(" ")
            except:
              part22           = " ".join(part21.strip().split(" ")[-4:])
              Status,Error,Duration,Size=part21.strip().split(" ")[-4:]
            part23=re.sub(r'\d{3}\s\d+\s\d+\s\d{3}',"",part21)
            Status,Error,Duration,Size=part22.strip().split(" ")
            try:
               URL=re.findall(r'http.*\s',part23)[0].strip()
               UserAgent=part23.replace(URL,"")
            except:
               UserAgent,URL= part23.strip(),"-"
            extracted_values.append({
                "datetime": date_time,
                "src_ip": src_ip,
                "request": request,
                "port": port,
                "endpoint": endpoint,
                "dstip": dstip,
                "UserAgent": UserAgent,
                "URL": URL,
                "Status": Status,
                "Error": Error,
                "Duration": Duration,
                "Size": Size
            })
    final_df = pd.DataFrame(extracted_values)
    print("Logs read:",len(logs),"\nAfter Parsing:",final_df.shape[0])
    if save_file:
        filename = "CreatedAt_"+str(datetime.now())[5:-7].replace(" ",'T').replace("-","_").replace(":","_")
        final_df.to_csv(filename+".csv")
        print(final_df["src_ip"].nunique(),final_df["dstip"].nunique(),final_df["URL"].nunique())
        return final_df

if len(sys.argv)<2:
     print("[x] Run with filename : < python3 file.py xyz.log  >")
     sys.exit(1)

filename=sys.argv[1]
try:
  final_df=log_parser(filename)
except Exception as e:
    print("Error in reading log file: ",e)

api_key=[] # Add API within <- given list ex: ["jghrdghlhrgreliohjgp","seggegegeggwgewggegw"]
try:
    virustotal_check(api_key,final_df)
except Exception as e:
    print("Error in virustotal: ",e)
