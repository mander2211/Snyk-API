import fetch from "node-fetch";
import prompt from "prompt";
import fs from "node:fs/promises";
import { setTimeout as sleep } from "node:timers/promises";

//API Key
const keyPrompt = await prompt.get("API Key");
const apiKey = keyPrompt["API Key"];

//based on file generated from the v3 rest api call to /issues
const filename = "RestaurantControlCenterTeam_Issues.json";
const projectGUID = "";
const orgGUID = "";
const ignoreReason = "Ignore Reason ---";
const ignoreUntil = "2024-04-08";

const basepathv1 = "https://api.snyk.io/v1";

const ignore = async () => {
  try {
    let file = await fs.readFile(filename, "utf8");
    let orgs = JSON.parse(file);

    let count = 0;
    for (let i = 0; i < orgs.data.length; i++) {
      if (
        !orgs.data[i].attributes.ignored &&
        orgs.data[i].relationships.scan_item.data.id == projectGUID
      ) {
        count++;
        let problemID = orgs.data[i].attributes.problems[0].id;
        console.log(problemID);
        let response;
        while (true) {
          response = await fetch(
            `${basepathv1}/org/${orgGUID}/project/${projectGUID}/ignore/${problemID}`,
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Authorization: `token ${apiKey}`,
              },
              body: JSON.stringify({
                reason: ignoreReason,
                reasonType: "temporary-ignore",
                disregardIfFixable: false,
                expires: ignoreUntil,
              }),
            }
          );
          sleep(250);
          if (response.ok) {
            break;
          } else {
            console.log(response.status);
          }
        }
      }
    }
    console.log(count);
  } catch (err) {
    console.log(err);
  }
};

ignore();
