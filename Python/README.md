# SnykAPI


To Run Any py Script:
-Need Python3 installed
    https://www.python.org/

-Needed modules to run py scripts
    pandas
    xlsxwriter
    tqdm
    requests
    json
    -Run modules installed via powershell or VScode terminal 
        "pip install {module}"

-Run Scripts via terminal
    python3 {script}

*******************************************
Snyk.py - My Snyk related connection and class methods.

PullSnykIgnores.py - Pulls Orgs, then issues and ignores, finally building an Excel. Uses Snyk Class.  Will ask for API KEY instead of having one hardcoded.

SnykIgnoreIssue.py - Self Sufficient Script.  This uses info provided in the constants to go and ignore a given issue in a given org.  Uses Snyk Class minimally

DetectSnykStaleProjects.py - Builds an Excel of all projects within each Org that hasn't been updated / scanned in a specific amount of time. Default: 72 hours.  Uses Snyk Class 

*******************************************

