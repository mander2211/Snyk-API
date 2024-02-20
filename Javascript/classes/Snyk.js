import fs from "node:fs/promises";
import fetch from "node-fetch";
import prompt from "prompt";
import { setTimeout as sleep } from "node:timers/promises";

class Snyk {
  static ARTIFACTS_PATH = "../artifacts/";
  static BASE_PATH_v3 = "https://api.snyk.io";
  static BASE_PATH_v1 = "https://api.snyk.io/v1";
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.headers = {
      "Content-Type": "application/json",
      Authorization: `token ${apiKey}`,
    };
    this.hoursStaleThreshold = 72;
    this.version = "2023-11-27~beta";
  }

  async PostIgnore({
    reason,
    reasonType = "temporary-ignore",
    ignoreUntil,
    orgGuid,
    projectGuid,
    problemID,
  }) {
    let response;
    while (true) {
      response = await fetch(
        `${BASE_PATH_v1}/org/${orgGuid}/project/${projectGuid}/ignore/${problemID}`,
        {
          method: "POST",
          headers: this.headers,
          body: JSON.stringify({
            reason: reason,
            reasonType: reasonType,
            disregardIfFixable: false,
            expires: ignoreUntil,
          }),
        }
      );
      sleep(200);
      if (response.ok) {
        break;
      } else {
        console.log(`${response.status}: ${response.statusText}`);
      }
    }
  }

  async GetOrgs() {
    const data = await fetch(`${Snyk.BASE_PATH_v3}/rest/orgs?version=2023-11-27~beta&limit=100`, {
      method: "GET",
      headers: this.headers,
    });
    //console.log(data);
    const fullOrgJson = await data.json();
    const orgArray = fullOrgJson.data.map((org) => {
      return org.id;
    });
    // console.log(orgArray);
    return orgArray;
  }

  async GetProjects(orgID) {
    let data;
    while (true) {
      data = await fetch(
        `${Snyk.BASE_PATH_v3}/rest/orgs/${orgID}/projects?version=2023-11-27~beta&limit=100`,
        {
          method: "GET",
          headers: this.headers,
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
        newData = await fetch(`${Snyk.BASE_PATH_v3}${projectsJson.links.next}`, {
          method: "GET",
          headers: this.headers,
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
  }

  async BuildOrgsAndProjectsFile() {
    const orgsArray = await this.GetOrgs();
    let orgFile = {
      data: [],
    };
    const length = orgsArray.length;
    for (let i = 0; i < length; i++) {
      let orgID = orgsArray[i];
      let projectArray = await this.GetProjects(orgID);
      orgFile.data[i] = {
        Org: orgsArray[i],
        projects: projectArray,
      };
      console.log(`Org #: ${i + 1}`);
    }
    await fs.writeFile("Orgs.json", JSON.stringify(orgFile, null, 2));
  }

  async GetAllVulnerabilities() {
    let file;
    try {
      file = await fs.readFile("Orgs.json", "utf8");
    } catch (err) {
      if (err.code == "ENOENT") {
        await this.BuildOrgsAndProjectsFile();
        file = await fs.readFile("Orgs.json", "utf8");
      }
    }
    let orgs = JSON.parse(file);
    let orgsArray = [];
    let orgLength = orgs.data.length;
    for (let i = 0; i < orgLength; i++) {
      orgsArray.push(orgs.data[i].Org);
    }

    console.log(orgsArray);
    let data;
    while (true) {
      data = await fetch(`${Snyk.BASE_PATH_v1}/reporting/issues/latest?page=1&perPage=1000`, {
        method: "POST",
        headers: this.headers,
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
        newData = await fetch(
          `${Snyk.BASE_PATH_v1}/reporting/issues/latest?page=${page}&perPage=1000`,
          {
            method: "POST",
            headers: this.headers,
            body: JSON.stringify({
              filters: {
                orgs: orgsArray,
              },
            }),
          }
        );
        console.log(`Getting page: ${page + 1}`);
        if (newData.ok) break;
      }
      let issuesJsonMore = await newData.json();
      issuesJson.results.push(...issuesJsonMore.results);
      page++;
    }
    //Generic printout of all issues in the current report
    await fs.writeFile("AllVulns.json", JSON.stringify(issuesJson, null, 4));
  }
}

export { Snyk };
