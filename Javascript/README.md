# SnykAPI

To Run Any py Script:
-Need Node.js installed
https://nodejs.org/en

-Needed modules to run js scripts
node-fetch
prompt (future enhancment)
-Run modules installed via terminal
"npm install {module}"

-Run JS via terminal
node {script}

---

ReviewIgnoreByPolicy.js - Group level policy can auto ignore vulnerabilities that have "no known exploit" If an exploit IS found, this script aims to bring visibility while Snyk is working on an internal solution

IgnoreWholeProject.js - Given an issues file from the v3 Rest API get issues call, go and ignore all issues in a given project.

Snyk.js - Starting class creation.

---

To Do's: Very minimal web front end to fire off whatever script / job flow to snyk.
