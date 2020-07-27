let express = require("express");
let bodyParser = require("body-parser");
let cons = require("consolidate");
let nosql = require("nosql").load("database.nosql");
let cors = require("cors");

let app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine("html", cons.underscore);
app.set("view engine", "html");
app.set("views", "files/protectedResource");
app.set("json spaces", 4);

app.use("/", express.static("files/protectedResource"));
app.use(cors());

let resource = {
  name: "Protected Resource",
  description: "This data has been protected by OAuth 2.0",
};

let getAccessToken = function (req, res, next) {
  // check the auth header first
  let auth = req.headers["authorization"];
  let inToken = null;
  if (auth && auth.toLowerCase().indexOf("bearer") == 0) {
    inToken = auth.slice("bearer ".length);
  } else if (req.body && req.body.access_token) {
    // not in the header, check in the form body
    inToken = req.body.access_token;
  } else if (req.query && req.query.access_token) {
    inToken = req.query.access_token;
  }

  console.log("Incoming token: %s", inToken);
  console.log("We found a matching token: %s", inToken);
  req.access_token = inToken;
  next();
  return;
};

app.options("/resource", cors());
app.post("/resource", cors(), getAccessToken, function (req, res) {
  if (req.access_token) {
    res.json(resource);
  } else {
    res.status(401).end();
  }
});

let server = app.listen(9002, "localhost", function () {
  let host = server.address().address;
  let port = server.address().port;

  console.log("OAuth Resource Server is listening at http://%s:%s", host, port);
});
