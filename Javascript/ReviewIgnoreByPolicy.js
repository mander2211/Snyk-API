import fs from "node:fs/promises";
import fetch from "node-fetch";
import prompt from "prompt";
import { URLSearchParams } from "node:url";

//API Key
const keyPrompt = await prompt.get("API Key");
const apiKey = keyPrompt["API Key"];

const headers = {
  Authorization: `token ${apiKey}`,
};
const params = {
  version: "2023-11-27~beta",
  limit: 100,
};
const basepathv1 = "https://api.snyk.io/v1";
const basepathv3 = "https://api.snyk.io";

const GetOrgs = async () => {
  try {
    const data = await fetch(`${basepathv3}/rest/orgs?` + new URLSearchParams(params), {
      method: "GET",
      headers: headers,
    });
    //console.log(data);
    const fullOrgJson = await data.json();
    const orgArray = fullOrgJson.data.map((org) => {
      return org.id;
    });
    // console.log(orgArray);
    return orgArray;
  } catch (err) {
    console.log(err);
  }
};

const GetProjects = async (orgID) => {
  try {
    let data;
    while (true) {
      data = await fetch(
        `${basepathv3}/rest/orgs/${orgID}/projects?version=2023-11-27~experimental&limit=100`,
        {
          method: "GET",
          headers: headers,
        }
      );
      if (data.ok) break;
    }

    let projectsJson = await data.json();
    const projectArray = projectsJson.data.map((proj) => {
      return proj.id;
    });

    let newData;
    while ("next" in projectsJson.links) {
      while (true) {
        newData = await fetch(`${basepathv3}${projectsJson.links.next}`, {
          method: "GET",
          headers: headers,
        });
        if (newData.ok) break;
      }

      projectsJson = await newData.json();
      projectArray.push(
        ...projectsJson.data.map((proj) => {
          return proj.id;
        })
      );
    }
    return projectArray;
  } catch (err) {
    console.log(err);
  }
};

//Write orgs and project IDs to a file for visibility
const BuildOrgsAndProjectsFile = async () => {
  const orgsArray = await GetOrgs();
  let orgFile = {
    data: [],
  };
  const length = orgsArray.length;
  for (let i = 0; i < length; i++) {
    let orgID = orgsArray[i];
    let projectArray = await GetProjects(orgID);
    orgFile.data[i] = {
      Org: orgsArray[i],
      projects: projectArray,
    };
    console.log(`Org #: ${i + 1}`);
  }
  await fs.writeFile("Orgs.json", JSON.stringify(orgFile, null, 2));
};

//All issues not including code findings
const GetIssues = async () => {
  try {
    let file = await fs.readFile("Orgs.json", "utf8");
    let orgs = JSON.parse(file);
    let orgsArray = [];
    let orgLength = orgs.data.length;
    for (let i = 0; i < orgLength; i++) {
      orgsArray.push(orgs.data[i].Org);
    }

    console.log(orgsArray);
    let data;
    while (true) {
      data = await fetch("https://api.snyk.io/v1/reporting/issues/latest?page=1&perPage=1000", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `token ${apiKey}`,
        },
        body: JSON.stringify({
          filters: {
            orgs: orgsArray,
          },
        }),
      });
      console.log("Getting page 1");
      if (data.ok) break;
    }

    let issuesJson = await data.json();
    let totalResults = issuesJson.total;
    let page = 1;
    console.log(`Grabbing a total of ${totalResults} issues`);

    let newData;
    while (page * 1000 < totalResults) {
      while (true) {
        newData = await fetch(`${basepathv1}/reporting/issues/latest?page=${page}&perPage=1000`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `token ${apiKey}`,
          },
          body: JSON.stringify({
            filters: {
              orgs: orgsArray,
            },
          }),
        });
        console.log(`Getting page: ${page + 1}`);
        if (newData.ok) break;
      }
      let issuesJsonMore = await newData.json();
      issuesJson.results.push(...issuesJsonMore.results);
      page++;
    }

    //lets loop through our big issue file
    const problem = {
      count: 0,
      issueID: [],
    };
    for (let r = 0; r < issuesJson.results.length; r++) {
      try {
        if (issuesJson.results[r].issue.isIgnored) {
          if (
            issuesJson.results[r].issue.ignored[0].ignoredBy.name ===
              "Ignored by Security Policy" &&
            issuesJson.results[r].issue.exploitMaturity !== "no-known-exploit"
          ) {
            problem.count++;
            problem.issueID.push(issuesJson.results[r].issue.id);
          }
        }
      } catch (err) {
        //do nothing skip over
      }
    }
    //Generic printout of all issues in the current report
    await fs.writeFile("POCIssues.json", JSON.stringify(issuesJson, null, 4));
    //Problem file contains all ignored by policy issues that have a known exploit!
    if (problem.issueID.length > 0) {
      await fs.writeFile("ProblemFile.json", JSON.stringify(problem, null, 2));
    }
  } catch (err) {
    console.log(err);
  }
};

async function mainModule() {
  try {
    await BuildOrgsAndProjectsFile();
    await GetIssues();
  } catch (error) {
    console.log(error);
  }
}

mainModule();
