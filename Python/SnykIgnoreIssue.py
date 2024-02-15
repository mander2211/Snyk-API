'''Intending for this script to be partially standalone.  Does still need the snyk class for a few calls'''

import requests as req
import json
import time
import tqdm
import Snyk

###################################################
#MUST CHECK VALUES BEFORE RUNNING
ORG_ID = "" #aka org GUID
ORG_NAME = "" #arbitrary
ISSUE_FILENAME = f"{ORG_NAME}_Issues.json"
ISSUE = "" #Key for vuln, title for code

#Enable ISSUE_TYPE depending on code or vuln
#ISSUE_TYPE = "code"
ISSUE_TYPE = "package_vulnerability"

IGNORE_REASON = "" #will be displayed in gui
IGNORE_TYPE = "temporary-ignore" #Possible values: "not-vulerable","wont-fix","temporary-ignore"
IGNORE_TO_DATE = "2024-03-01"
#####################################################

#Build Ignore Request body from Env Variables
def BuildIgnoreRequest():
    requestDict = {}
    #requestDict["ignorePath"] = ''
    requestDict["reason"] = IGNORE_REASON
    requestDict["reasonType"] = IGNORE_TYPE
    requestDict["disregardIfFixable"] = False
    requestDict["expires"] = IGNORE_TO_DATE
    return requestDict 

#Create a new issues list specific for the Ignore Process
def Get_OrgIssuesToFile(conn):
    json_object = json.dumps(conn.Get_ProjectIssues(ORG_ID),indent=4,sort_keys=True)
    with open(ISSUE_FILENAME, "w") as outfile:
            outfile.write(json_object)

#Main Driver - Ignore Issue based off of initialized values above
def Ignore():
    print("Pulling Ignore Info...")
    conn = Snyk.SnykConnection()
    Get_OrgIssuesToFile(conn)
    #Open File
    file = open(ISSUE_FILENAME)
    j = json.load(file)
    counter = 0
    print("Processing Ignores...")
    #Open Issue File and loop through
    for i in tqdm.tqdm(range(len(j["data"])),position=0,leave=True,colour="green",desc="Ignoring"):
        #determine where to look for the issue in the json reponse
        if ISSUE_TYPE == "code":
            issueNameLocation = j["data"][i]["attributes"]["title"]
        else:
            issueNameLocation = j["data"][i]["attributes"]["key"]    
        #if not ignored, not resolved, and is the issue in question
        if j["data"][i]["attributes"]["ignored"] == False and issueNameLocation == ISSUE and j["data"][i]["attributes"]["status"] != "resolved":
            proj = j["data"][i]["relationships"]["scan_item"]["data"]["id"]
            org = j["data"][i]["relationships"]["organization"]["data"]["id"]
            issueId = j["data"][i]["attributes"]["key"]
            reqBody = BuildIgnoreRequest()
            #force a loop till all the ignore creation calls are done.
            while True:
                try:
                    conn.Post_Ignore(reqBody,org,proj,issueId)
                    time.sleep(.25)
                    counter += 1
                except:
                    continue
                break
    #close file
    file.close()
    print(f"Count: {counter}")   

#*****************************
#*****************************
#*****************************
#Control main driver func here    
if __name__ == "__main__":
    if ORG_ID == "" or ISSUE == "":
        print("Please populate ORG ID and the other constants above")
    else:
        Ignore()
#*****************************
#*****************************
#*****************************