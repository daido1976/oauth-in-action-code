let express = require("express");
let request = require("sync-request");
let url = require("url");
let qs = require("qs");
let querystring = require("querystring");
let cons = require("consolidate");
let randomstring = require("randomstring");
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

let client = {
  client_id: "oauth-client-1",
  client_secret: "oauth-client-secret-1",
  redirect_uris: ["http://localhost:9000/callback"],
};

let protectedResource = "http://localhost:9002/resource";

let state = null;

let access_token = null;
let scope = null;

app.get("/", function (req, res) {
  res.render("index", { access_token: access_token, scope: scope });
});

app.get("/authorize", function (req, res) {
  access_token = null;

  state = randomstring.generate();

  let authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    state: state,
  });

  console.log("redirect", authorizeUrl);
  res.redirect(authorizeUrl);
});

app.get("/callback", function (req, res) {
  if (req.query.error) {
    // it's an error response, act accordingly
    res.render("error", { error: req.query.error });
    return;
  }

  if (req.query.state != state) {
    console.log(
      "State DOES NOT MATCH: expected %s got %s",
      state,
      req.query.state
    );
    res.render("error", { error: "State value did not match" });
    return;
  }

  let code = req.query.code;

  let form_data = qs.stringify({
    grant_type: "authorization_code",
    code: code,
    redirect_uri: client.redirect_uris[0],
  });
  let headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    Authorization:
      "Basic " +
      encodeClientCredentials(client.client_id, client.client_secret),
  };

  let tokRes = request("POST", authServer.tokenEndpoint, {
    body: form_data,
    headers: headers,
  });

  console.log("Requesting access token for code %s", code);

  if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    let body = JSON.parse(tokRes.getBody());

    access_token = body.access_token;
    console.log("Got access token: %s", access_token);

    res.render("index", { access_token: access_token, scope: scope });
  } else {
    res.render("error", {
      error:
        "Unable to fetch access token, server response: " + tokRes.statusCode,
    });
  }
});

app.get("/fetch_resource", function (req, res) {
  if (!access_token) {
    res.render("error", { error: "Missing Access Token" });
    return;
  }

  console.log("Making request with access token %s", access_token);

  let headers = {
    Authorization: "Bearer " + access_token,
  };

  let resource = request("POST", protectedResource, { headers: headers });

  if (resource.statusCode >= 200 && resource.statusCode < 300) {
    let body = JSON.parse(resource.getBody());
    res.render("data", { resource: body });
    return;
  } else {
    access_token = null;
    res.render("error", { error: resource.statusCode });
    return;
  }
});

let buildUrl = function (base, options, hash) {
  let newUrl = url.parse(base, true);
  delete newUrl.search;
  if (!newUrl.query) {
    newUrl.query = {};
  }
  __.each(options, function (value, key, list) {
    newUrl.query[key] = value;
  });
  if (hash) {
    newUrl.hash = hash;
  }

  return url.format(newUrl);
};

let encodeClientCredentials = function (clientId, clientSecret) {
  return new Buffer(
    querystring.escape(clientId) + ":" + querystring.escape(clientSecret)
  ).toString("base64");
};

app.use("/", express.static("files/client"));

let server = app.listen(9000, "localhost", function () {
  let host = server.address().address;
  let port = server.address().port;
  console.log("OAuth Client is listening at http://%s:%s", host, port);
});
