//xlsx readfile has cjs module only
import { createRequire } from "module";
const require = createRequire(import.meta.url);
const xlsx = require("xlsx");
import fs from "node:fs/promises";

const workbook = xlsx.readFile("./ignores.xlsx");
//console.log(workbook.Sheets["KFC-Help-Desk"]);

//await fs.writeFile("sheets.json", JSON.stringify(workbook, null, 2));
//await fs.writeFile("sheetHelpDesk.json", JSON.stringify(workbook.Sheets["KFC-Help-Desk"], null, 2));
for (let i in workbook.Sheets["KFC-Help-Desk"]) {
  console.log(workbook.Sheets["KFC-Help-Desk"][i].v);
}

console.log(workbook.Sheets["KFC-Help-Desk"].B1.v);
