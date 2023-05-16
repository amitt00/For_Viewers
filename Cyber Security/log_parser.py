import pandas as pd
import re
from datetime import datetime
from tqdm import tqdm

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

def log_parser(filename,save_file=True):
    logs=log_reader(filename)
    extracted_values = []
    for i in tqdm(logs):
        try:
            port             = re.findall(r'\s\d{2,4}\s-\s',i)[0].replace("-","").replace(" ","")
            partition        = re.split(r'\s\d{2,4}\s-\s',i)
            part1 ,part2     = partition[0],partition[1]
            date_time         = re.findall(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}',part1)[0]
            src_ip           = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',part1)[0]
            part11           = re.split(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s',part1)[-1]
            request,endpoint = part11.split(" ")[:2]
            dstip            = re.findall(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',part2)[0].replace(" ","")
            part21           = re.sub(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s',"",part2)
            rest             = re.findall( r"(?P<user_agent>.+)\s+(?P<url>.+)\s+(?P<status>\d+)\s+(?P<error>\d+)\s+(?P<duration>\d+)\s+(?P<size>\d+)",part21)
            UserAgent,URL,Status,Error,Duration,Size=rest[0][0],rest[0][1],rest[0][2],rest[0][3],rest[0][4],rest[0][5]
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
        except Exception as e:
            print("Error in below log : ",e)
            print(i)
            continue
    final_df = pd.DataFrame(extracted_values)
    print("Logs read:",len(logs),"\nAfter Parsing:",final_df.shape[0])
    if save_file:
        filename = "CreatedAt_"+str(datetime.now())[5:-7].replace(" ",'T').replace("-","_").replace(":","_")
        final_df.to_csv(filename+".csv")
    return final_df

print("Enter file name:")
filename=str(input())
print("Save output:(Y/N)")
SAVE_FLAG=str(input())
if SAVE_FLAG not in ['Y','N']:
    print("Try again")
if  SAVE_FLAG=="Y":
    log_parser(filename)
else :
    print(log_parser(filename,save_file=True)).head(25)