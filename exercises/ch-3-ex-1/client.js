let express = require("express");
let request = require("sync-request");
let url = require("url");
let qs = require("qs");
let querystring = require("querystring");
// template engine with underscore
let cons = require("consolidate");
let randomstring = require("randomstring");
// util library(Probably not necessary)
let __ = require("underscore");
__.string = require("underscore.string");

let app = express();

app.engine("html", cons.underscore);
app.set("view engine", "html");
app.set("views", "files/client");

// authorization server information
let authServer = {
  authorizationEndpoint: "http://localhost:9001/authorize",
  tokenEndpoint: "http://localhost:9001/token",
};

// client information

/*
 * Add the client information in here
 */
let client = {
  client_id: "oauth-client-1",
  client_secret: "oauth-client-secret-1",
  redirect_uris: ["http://localhost:9000/callback"],
};

let protectedResource = "http://localhost:9002/resource";

let state = null;

let access_token = null;
let scope = null;

app.get("/", (req, res) => {
  res.render("index", { access_token, scope });
});

app.get("/authorize", (req, res) => {
  /*
   * Send the user to the authorization server
   */
});

app.get("/callback", (req, res) => {
  /*
   * Parse the response from the authorization server and get a token
   */
});

app.get("/fetch_resource", (req, res) => {
  /*
   * Use the access token to call the resource server
   */
});

let buildUrl = (base, options, hash) => {
  let newUrl = url.parse(base, true);
  delete newUrl.search;
  if (!newUrl.query) {
    newUrl.query = {};
  }
  __.each(options, (value, key, list) => {
    newUrl.query[key] = value;
  });
  if (hash) {
    newUrl.hash = hash;
  }

  return url.format(newUrl);
};

let encodeClientCredentials = (clientId, clientSecret) => {
  return new Buffer(
    querystring.escape(clientId) + ":" + querystring.escape(clientSecret)
  ).toString("base64");
};

app.use("/", express.static("files/client"));

let server = app.listen(9000, "localhost", () => {
  let host = server.address().address;
  let port = server.address().port;
  console.log("OAuth Client is listening at http://%s:%s", host, port);
});
