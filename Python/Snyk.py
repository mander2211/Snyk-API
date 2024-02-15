import requests as req
import time
import os
import json
import pandas
import xlsxwriter
import tqdm
import os

class SnykConnection:
    ORGS_FILENAME = ".\\Snyk_Ignores\\artifacts\\Snyk_Orgs.json"
    IGNORES_XLSXFILENAME = ".\\Snyk_Ignores\\Snyk_Ignores.xlsx"
    STALE_PROJECTS_FILENAME = ".\\Snyk_Stale_Projects\\Snyk_Stale_Projects.xlsx"
    
    def __init__(self):
        self.api_key = input("Enter User API KEY: ")
        self.BASE_PATH_v3 = "https://api.snyk.io/"
        self.BASE_PATH_v1 = "https://api.snyk.io/v1"
        self.version = "2023-11-27~beta"
        self.headers = {'Authorization' : 'token ' + self.api_key}
        self.params = {'version' : self.version , 'limit': 100, 'meta.latest_issue_counts': "true"}
        self.hoursStaleThreshold = 72
    
    #Post Ignore 
    def Post_Ignore(self,reqBody,orgId,projectId,issueId):
        response = req.post(self.BASE_PATH_v1+ f"/org/{orgId}/project/{projectId}/ignore/{issueId}",headers=self.headers,json=reqBody)
        return response.json()
    
    #return all orgs for a given API key user    
    def Get_Orgs(self):
        response = req.get(self.BASE_PATH_v3+"/rest/orgs",params=self.params,headers=self.headers)
        json = response.json()
    
        #this is the first call to the API. Check response for error issue
        if "code" in json:
            if json["code"] != "200":
                print(f"Please verify correct API Key used.  Error Message: {json}")
                exit()
                
        #make a copy to iterate through    
        copy = json.copy()
        while "next" in copy['links']:
            nextlink = copy["links"]["next"]
            nextResponse = req.get(self.BASE_PATH_v3+nextlink,headers=self.headers)
            time.sleep(.25)
            try:
                copy = nextResponse.json()
            except:
                print(nextResponse)
            for i in range(len(copy["data"])):
                json["data"].append(copy["data"][i])
                
        return json
    
    #return json of all projects in give org
    #args string 
    def Get_Projects(self,org_id):
        time.sleep(.25)
        response = req.get(self.BASE_PATH_v3+f"/rest/orgs/{org_id}/projects",params=self.params,headers=self.headers)
        json = response.json()

        #make a copy to iterate through
        copy = json.copy()
        while "next" in copy['links']:
            nextlink = copy["links"]["next"]
            nextResponse = req.get(self.BASE_PATH_v3+nextlink,headers=self.headers)
            time.sleep(.25)
            try:
                copy = nextResponse.json()
            except:
                print(nextResponse)
            for i in range(len(copy["data"])):
                json["data"].append(copy["data"][i])
    
        return json
    
    #For a given org, get all the issues in that org, ignored and all
    #Args: string
    def Get_ProjectIssues(self,org_id):
        response = req.get(self.BASE_PATH_v3+'/rest/orgs/%s/issues'%(org_id),params=self.params,headers=self.headers)
        json = response.json()
    
        #this is the first call to the API. Check response for error issue
        if "code" in json:
            if json["code"] != "200":
                print(f"Please verify correct API Key used.  Error Message: {json}")
                exit()
    
        #make a copy to iterate through
        copy = json.copy()
        #API doesn't give you all the data in one go, gotta loop through a next link to get the next few results.
        while "next" in copy['links']:
            nextlink = copy["links"]["next"]
            nextResult = req.get(self.BASE_PATH_v3+nextlink,headers=self.headers)
            time.sleep(.5)
            #Was getting random 403s, adding a try catch to roll back and retry without failing out
            try:
                copy = nextResult.json()
            except:
                print(nextResult)
            if copy["links"]["next"] == copy["links"]["self"]:
                break
            #if all is good with the call, append that x copy back onto the parent json j
            for i in range(len(copy["data"])):
                json["data"].append(copy["data"][i])
            
        return json
    
    #Call and retrieve all ignores for a given project
    #Args: string, string
    def Get_ProjectIgnores(self,org_id,project_id):
        response = req.get(self.BASE_PATH_v1+f"/org/{org_id}/project/{project_id}/ignores",headers=self.headers)
        json = response.json()
             
        return json
    
    #project metadata about when the project was last updated
    def Get_ProjectMeta(self,org_id):
        response = req.get(self.BASE_PATH_v3+f"/rest/orgs/{org_id}/projects",params=self.params,headers=self.headers)
        json = response.json()
        
        #make a copy to iterate through        
        copy = json.copy()
        while "next" in copy["links"]:
            nextlink = copy["links"]["next"]
            nextResponse = req.get(self.BASE_PATH_v3+nextlink,headers=self.headers)
            time.sleep(.25)
            try:
                copy = nextResponse.json()
            except:
                print(nextResponse)
            for i in range(len(copy["data"])):
                json["data"].append(copy["data"][i])
        
        
        return json
    
    #detect and write to disk any projects not updated within the instance threshhold.
    def DetectStaleProjects(self):
        print(f"Current Stale Threshold Set at {self.hoursStaleThreshold} hours")
        print("Pulling Project Metadata...")
        
        #create a folder for files being processed
        newpath = ".\\Snyk_Stale_Projects"
        if not os.path.exists(newpath):
            os.makedirs(newpath)
            
        #pandas excel writer, could have also used openpyxl        
        excelWriter = pandas.ExcelWriter(self.STALE_PROJECTS_FILENAME,engine='xlsxwriter')
        
        #Create your object for DF later
        name = [];id = [];last_updated = [];org = []
        prj = {'Name': name, 'ID': id, "Last_Updated" : last_updated, "ORG" : org}
        
        count = 0
        #var for comparison
        nowEST = pandas.Timestamp.now(tz="US/Eastern")
        
        #Loop through orgs and call for project metadata
        orgsJson = self.Get_Orgs()
        for i in tqdm.tqdm(range(len(orgsJson["data"])),position=0,leave=True,colour="green",desc="Orgs"):
            projectsJson = self.Get_ProjectMeta(orgsJson["data"][i]["id"])
            #loop through projects and convert UTC to EST
            for k in tqdm.tqdm(range(len(projectsJson["data"])),position=1,leave=False,colour="red",desc="Projects"):
                lastScanned = projectsJson["data"][k]["meta"]["latest_issue_counts"]["updated_at"]
                lastScanned = lastScanned.replace("T", " ")
                lastScanned = lastScanned.rsplit(".")
                lastScannedEST = pandas.Timestamp.tz_convert(pandas.to_datetime(lastScanned[0],format='%Y-%m-%d %H:%M:%S',utc=True),"US/Eastern")
                #If time delta is greater than 72 hours, log it in the dict obj
                if (nowEST-lastScannedEST).total_seconds() / 3600> self.hoursStaleThreshold:
                    count += 1
                    name.append(projectsJson["data"][k]["attributes"]["name"])
                    id.append(projectsJson["data"][k]["id"])   
                    last_updated.append(lastScannedEST.strftime('%Y-%m-%d %H:%M:%S'))
                    org.append(orgsJson["data"][i]["attributes"]["name"])
            
            #still inside the org loop, convert the dict to dataframe and xlsx file.  Then clear the dict for another go round.        
            df = pandas.DataFrame(prj)
            #each org gets its own sheet
            df.to_excel(excelWriter,orgsJson["data"][i]["attributes"]["name"][:30]) 
            name.clear();id.clear();last_updated.clear();org.clear()
            
        excelWriter.close()          
        print(f"Count: {count}")
    
    #create org and project files
    def Create_OrgAndProjectFile(self):
        print("Pulling Orgs...")
        
        #create a folder for files being processed
        newpath = ".\\Snyk_Ignores\\artifacts"
        if not os.path.exists(newpath):
            os.makedirs(newpath)
            
        projCounter = 0
        #Get all orgs and loop
        orgsJson = self.Get_Orgs()
        for i in tqdm.tqdm(range(len(orgsJson["data"])),position=0,leave=True,colour="green",desc="Orgs"):
            #get all projects in given org
            projectsJson = self.Get_Projects(orgsJson["data"][i]["id"])
            projects = []
            orgsJson["data"][i].update({"projects": projects})
            #loop through projects and add name, id to main org json
            for k in tqdm.tqdm(range(len(projectsJson["data"])),position=0,leave=False,colour="red",desc="Projects"):
                projectDict = {"name":projectsJson["data"][k]["attributes"]["name"],"id":projectsJson["data"][k]["id"]}
                orgsJson["data"][i]["projects"].append(projectDict)
                projCounter += 1
        print(f"Found a total of {projCounter} projects across {len(orgsJson["data"])} orgs")   
        #write full file
        json_object = json.dumps(orgsJson,indent=4,sort_keys=True)
        with open(self.ORGS_FILENAME, "w") as outfile:
                outfile.write(json_object)
                
    #Call get projectIssues() and write all issues for a given org
    #Args: string, string
    def Create_IssuesJson(self,org_id,org_name):
        orgIssues = self.Get_ProjectIssues(org_id)
        json_object = json.dumps(orgIssues,indent=4,sort_keys=True)
        with open(f".\\Snyk_Ignores\\artifacts\\{org_name}_Issues.json", "w") as outfile:
            outfile.write(json_object)
        return orgIssues

    #Create Ignore File for all ignores in a given project
    #To be used inisde loop
    #Args:Fully created Json with orgs/project dict, empty ignoresJson dict, current iterator int     
    def Create_IgnoresJson(self,orgsJson,ignoresJson,i):
        ignoresJson["data"].append({"orgid":orgsJson["data"][i]["id"],"orgname":orgsJson["data"][i]["attributes"]["name"],"projects":[]})
        for k in tqdm.tqdm(range(len(orgsJson["data"][i]["projects"])),position=1,leave=False,colour="red",desc="Projects"):
            projIgnores = self.Get_ProjectIgnores(orgsJson["data"][i]["id"],orgsJson["data"][i]["projects"][k]["id"])
            ignoresJson["data"][i]["projects"].append({"id":orgsJson["data"][i]["projects"][k]["id"],"name":orgsJson["data"][i]["projects"][k]["name"],"ignores":projIgnores})
            
        json_object = json.dumps(ignoresJson["data"][i],indent=4,sort_keys=True)
        with open(f".\\Snyk_Ignores\\artifacts\\{orgsJson["data"][i]["attributes"]["name"]}_Ignores.json", "w") as outfile:
            outfile.write(json_object)

    #Concatenate the ignore information into issue information in new file.
    #Args: string, json, json, index inside ORG.json file
    def ConcatIgnoreAndIssueFiles(self,org_name,issueJson,ignoreJson,i):
        #Loop through issueJson
        #if ignored, find it in Ignore json and import reason
            #if ignored, and cant find it - its a security policy ignore
        for k in range(len(issueJson["data"])):
            if issueJson["data"][k]["attributes"]["ignored"] == True:
                issueKey = issueJson["data"][k]["attributes"]["key"]
                projKey = issueJson["data"][k]["relationships"]["scan_item"]["data"]["id"]
                for j in range(len(ignoreJson["data"][i]["projects"])):
                    if projKey == ignoreJson["data"][i]["projects"][j]["id"]: 
                        if issueKey in ignoreJson["data"][i]["projects"][j]["ignores"]:
                            issueJson["data"][k]["attributes"].update({"ignore_info":ignoreJson["data"][i]["projects"][j]["ignores"][issueKey]})
                        else:
                            issueJson["data"][k]["attributes"].update({"ignore_info":"Ignored by Policy"})
        #Once done, write to final file
        json_object = json.dumps(issueJson,indent=4,sort_keys=True)
        with open(f".\\Snyk_Ignores\\artifacts\\{org_name}_Concat.json", "w") as outfile:
            outfile.write(json_object)
        
        
    #create ignores and issues files for all orgs (Must use PullSnykOrgs.py first)    
    def Pull_SnykIssuesAndIgnoreInfo(self):
        print("Pulling Snyk Issues...")
        
        #create a folder for files being processed
        newpath = ".\\Snyk_Ignores\\artifacts"
        if not os.path.exists(newpath):
            os.makedirs(newpath)
            
        orgfile = open(self.ORGS_FILENAME)
        orgsJson = json.load(orgfile)
        data = []
        ignoresJson = {"data":data}
        
        #Loop through orgs
        for i in tqdm.tqdm(range(len(orgsJson["data"])),position=0,leave=True,colour="green",desc="Orgs"):
            org_name = orgsJson["data"][i]["attributes"]["name"]
            org_id = orgsJson["data"][i]["id"]
            issuesJson = self.Create_IssuesJson(org_id,org_name)
            time.sleep(.15)
            self.Create_IgnoresJson(orgsJson,ignoresJson,i)
            time.sleep(.15) 
            self.ConcatIgnoreAndIssueFiles(org_name,issuesJson,ignoresJson,i)
            
        orgfile.close()

    #convert concatenate file ignore info to CSV (Must use ConcatIgnoreAndIssueFiles() first)
    @classmethod
    def BuildExcel(cls):
        print(f"Building Excel...")
        
        #create a folder for files being processed
        newpath = ".\\Snyk_Ignores\\artifacts"
        if not os.path.exists(newpath):
            os.makedirs(newpath)
            
        orgfile = open(cls.ORGS_FILENAME)
        orgsJson = json.load(orgfile)
        
        #Initialize all CSV Column headers
        count = 0
        orgs = [];projects = [];issues = [];keys = [];reasons = [];created = [];ignoredBy = [];httpLink = []
        columns = {'Org': orgs, 'Project': projects, "Issue" : issues, "Issue_Key" : keys, "Ignore_Reason" : reasons, "Created" : created, "Created_By": ignoredBy, "HTTP_Link" : httpLink}
        
        #pandas excel writer, could have also used openpyxl        
        excelWriter = pandas.ExcelWriter(cls.IGNORES_XLSXFILENAME,engine='xlsxwriter')
        
        #Loop through orgs
        for i in tqdm.tqdm(range(len(orgsJson["data"])),position=0,leave=True,colour="green",desc="Orgs"):
            #Grab name of concat file
            org_name = orgsJson["data"][i]["attributes"]["name"]
            issuesConcat = open(f".\\Snyk_Ignores\\artifacts\\{org_name}_Concat.json")
            
            #clean up naming to match http link use
            org_name = org_name.strip()
            org_name = org_name.replace(" ","-")
            
            #Open Concat file and loop through ignored issues
            j = json.load(issuesConcat)
            for i in range(len(j["data"])):
                if j["data"][i]["attributes"]["ignored"] == True:
                    #Build dict
                    orgs.append(j["data"][i]["relationships"]["organization"]["data"]["id"])
                    projects.append(j["data"][i]["relationships"]["scan_item"]["data"]["id"])
                    issues.append(j["data"][i]["attributes"]["type"])
                    keys.append(j["data"][i]["attributes"]["key"])
                    #Try blocks are for variance in ignore info brought over from ignores file
                    #Some start with "*" element, some dont, and some only have a string for policy ingore
                    try:
                        reasons.append(j["data"][i]["attributes"]["ignore_info"][0]["*"]["reason"])
                        created.append(j["data"][i]["attributes"]["ignore_info"][0]["*"]["created"])
                        ignoredBy.append(j["data"][i]["attributes"]["ignore_info"][0]["*"]["ignoredBy"]["name"])
                    except KeyError:
                        reasons.append(j["data"][i]["attributes"]["ignore_info"][0]["reason"])
                        created.append(j["data"][i]["attributes"]["ignore_info"][0]["created"])
                        ignoredBy.append(j["data"][i]["attributes"]["ignore_info"][0]["ignoredBy"]["name"])
                    except TypeError:
                        reasons.append(j["data"][i]["attributes"]["ignore_info"])
                        created.append("n/a")
                        ignoredBy.append("Policy")
                    httpLink.append(f"https://app.snyk.io/org/{org_name.lower()}/project/{j["data"][i]["relationships"]["scan_item"]["data"]["id"]}#issue-{j["data"][i]["attributes"]["key"]}")
                    count += 1
            
            #Excel writer and each org to a sheet
            df = pandas.DataFrame(columns)
            df.to_excel(excelWriter,org_name[:30])
            orgs.clear();projects.clear();issues.clear();keys.clear();reasons.clear();created.clear();ignoredBy.clear();httpLink.clear()
        
        print(f"Count: {count}")
        excelWriter.close()
        