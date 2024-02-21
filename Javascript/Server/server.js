import cors from "cors";
import express from "express";

const port = 3000;
const app = express();
app.use(cors());

app.get("/", (req, res) => {
  res.send("hello world");
});

app.listen(port, () => {
  console.log(`Listening on port: ${port}`);
});
