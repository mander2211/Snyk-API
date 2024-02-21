import prompt from "prompt";
import fs from "node:fs/promises";
import { Snyk } from "./classes/SnykUtil.js";

//API Key
const keyPrompt = await prompt.get("API Key");
const apiKey = keyPrompt["API Key"];

//based on file generated from the v3 rest api call to /issues
const filename = "RestaurantControlCenterTeam_Issues.json";
const projectGUID = "";
const orgGUID = "";
const ignoreReason = "Ignore Reason ---";
const ignoreUntil = "2024-04-08";

//snyk connection object
const conn = new Snyk(apiKey);

await conn.BuildOrgsAndProjectsFile();
await conn.GetAllVulnerabilities();
