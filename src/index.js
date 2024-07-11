const express = require("express");
const cors = require("cors");
const ENV = require("./config/config");
const routerApi = require("./routes");
const app = express();
const path = require('path');

app.use(express.static(path.join(__dirname, 'public')));

const port = ENV.port || 3000;

app.use(express.json());
app.use(cors());

app.get("/", (req, res) => {
  res.send("Hello World");
});

routerApi(app);

app.listen(port, () => {
  console.log(`server listening at http://localhost:${port}`);
});
