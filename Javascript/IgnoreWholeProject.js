import prompt from "prompt";
import fs from "node:fs/promises";
import { Snyk } from "./classes/Snyk.js";

//API Key
const keyPrompt = await prompt.get("API Key");
const apiKey = keyPrompt["API Key"];

//based on file generated from the v3 rest api call to /issues
const filename = "RestaurantControlCenterTeam_Issues.json";
const projectGUID = "";
const orgGUID = "";
const ignoreReason = "Ignore Reason ---";
const ignoreUntil = "2024-04-08";

const conn = new Snyk(apiKey);

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

        await conn.PostIgnore({
          reason: ignoreReason,
          ignoreUntil: ignoreUntil,
          orgGuid: orgGUID,
          projectGuid: projectGUID,
          problemID: problemID,
        });
      }
    }
    console.log(count);
  } catch (err) {
    console.log(err);
  }
};

ignore();
