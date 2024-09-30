const express = require("express");
const axios = require("axios");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const qs = require("qs");
const jwt = require("jsonwebtoken");
const logger = require("./utils/logger"); // Import the logger
const { response } = require("express");
const jwksRsa = require('jwks-rsa');

const app = express();
const port = 3001;

let sessions = {};

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://e24d-2607-fea8-bdc-3550-dc44-4f5f-5bc5-83e3.ngrok-free.app", //here put the react app url
      "https://feciam.ngrok.app", //auth0,
      "https://workys.org",
      "http://localhost:5174",
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], // Custom allowed methods
    allowedHeaders: ["Content-Type", "Authorization"], // Custom allowed headers
  })
);

app.use((req, res, next) => {
  logger.info(`Incoming request to ${req.url}`);
  logger.info(`Request headers: ${JSON.stringify(req.headers)}`);
  next();
});

//kpmg tenent this doens't have dns domain enabled dev-q7
// const CLIENT_ID_AUTH0 = 'v9Fp0NeZ06A4fZHuo7I5YodqvjdzPhNJ';
// const CLIENT_SECRET_AUTH0 = 'cBS1vs56iyG1bmFA-Lktct4K-1MNuMrDSbAB4VoY7T0e49J_1RAN1R88HtorQE4_';
// const AUTH0_DOMAIN_AUTH0 = 'https://dev-q7ybk7ocujetu4ff.ca.auth0.com';

//kpmg tenent this is PG tenent peoplse group test
const CLIENT_ID_AUTH0 = "06GQhUZHeHBltQzGW2Cvz7ntWuQWp8pR";
const CLIENT_SECRET_AUTH0 =
  "C6M7NUWaRqkY-ky-ItWspQpWl-eRMyLM1Jmo7xASkvayPYrEfPPTHOuR0qqZnebt";
const AUTH0_DOMAIN_AUTH0 = "https://peoples-group-test.ca.auth0.com";

// Create a JWKS client
const jwksClient = jwksRsa({
  jwksUri: `${AUTH0_DOMAIN_AUTH0}/.well-known/jwks.json`,
});

const getKey = (header, callback) => {
  jwksClient.getSigningKey(header.kid, (err, key) => {
    if (err) {
      console.error("Error retrieving signing key:", err);
      return callback(err);
    }
    const signingKey = key.getPublicKey();
    console.log("Retrieved signing key:", signingKey);
    callback(null, signingKey);
  });
};

// Function to get Auth0 Management API token
const getManagementApiToken = async () => {
  // const CLIENT_ID = process.env.CLIENT_ID_AUTH0;
  // const CLIENT_SECRET = process.env.CLIENT_SECRET_AUTH0;

  try {
    const response = await axios.post(
      `${AUTH0_DOMAIN_AUTH0}/oauth/token`,
      {
        client_id: CLIENT_ID_AUTH0,
        client_secret: CLIENT_SECRET_AUTH0,
        audience: `${AUTH0_DOMAIN_AUTH0}/api/v2/`,
        grant_type: "client_credentials",
      },
      {
        headers: {
          "Content-Type": "application/json",
        },
      }
    );

    //console.log("response:",response)

    return response.data.access_token;
  } catch (error) {
    console.error("Error getting token:", error);
    throw new Error("Unable to retrieve access token");
  }
};

// User Profile endpoint
app.get("/api/users/:userId", async (req, res) => {
  console.log("inside get ....user profile");
  const { userId } = req.params;

  try {
    // const access_tk_user = req.headers.authorization.split(' ')[1];
    // console.log("Token received:", access_tk_user);
    
    // // Decode the JWT to extract header
    // const decodedHeader = jwt.decode(access_tk_user, { complete: true }).header;
    // console.log("Decoded JWT header:", decodedHeader);
    
    // Get the Management API token
    const token = await getManagementApiToken();
    console.log("here inside token....");
    // Fetch user profile data from Auth0
    const response = await axios.get(
      `${AUTH0_DOMAIN_AUTH0}/api/v2/users/${userId}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );

    //console.log("response:",response)

    res.json(response.data);
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).send("Error fetching user profile");
  }
});

app.get("/api/users/:userId/authenticators", async (req, res) => {
  const { userId } = req.params;

  try {
    const token = await getManagementApiToken();
    console.log("here inside token....");

    // Fetch authenticators for the user
    const authResponse = await axios.get(
      `${AUTH0_DOMAIN_AUTH0}/api/v2/users/${userId}/authenticators`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    res.json(authResponse.data);
  } catch (error) {
    console.error("Error fetching authenticators:", error);
    res.status(500).json({ message: "Error fetching authenticators" });
  }
});

//auth0 user update
app.patch("/api/users/:userId", async (req, res) => {
  const { userId } = req.params;
  const updatedData = req.body;
  console.log("request Update user profile data::", updatedData);
  //{ first_name: "sdfdsaf", last_name: "dsfdsaf", phone_number: "+141631923489" }

  try {
    // Get the Management API token
    const token = await getManagementApiToken();
    // console.log("here token2....".token)

    // Update user profile data on Auth0

    const response = await axios.patch(
      `${AUTH0_DOMAIN_AUTH0}/api/v2/users/${userId}`,
      updatedData,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );
    console.log("response Update user profile data::", response);
    res.json(response.data);
  } catch (error) {
    console.error("Error updating user profile:", error);
    res.status(500).send("Error updating user profile");
  }
});

// Change Password endpoint auth0
app.patch("/api/password/users/:userId", async (req, res) => {
  console.log("calling changepassword of auth0...");
  const { userId } = req.params;
  const { newPassword } = req.body; // Expecting newPassword in the request body

  try {
    // Get the Management API token
    const token = await getManagementApiToken();

    // Make a request to change the user's password
    const response = await axios.patch(
      `${AUTH0_DOMAIN_AUTH0}/api/v2/users/${userId}`,
      {
        password: newPassword,
        connection: "Username-Password-Authentication",
      },
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      }
    );

    console.error(" changing user password response:", response);
    res.json(response.data);
  } catch (error) {
    console.error("Error changing user password:", error);
    console.error("Error changing user password:", response);
    res.status(500).send("Error changing user password");
  }
});

////Below are transmit security api's this is out of scope now since this were route to evaluate transmit secuirty.

// const CLIENT_ID = "<your-client-id>";
// const CLIENT_SECRET = "<your-client-secret>";
// const REDIRECT_URI = "http://localhost:3000/callback";
// const TOKEN_ENDPOINT = "<openam-token-endpoint>";
// const USERINFO_ENDPOINT = "<openam-userinfo-endpoint>";
// const LOGOUT_ENDPOINT = "<openam-logout-endpoint>";
// const JWT_SECRET = "your-secret-key"; // replace with your actual secret key

const client_id = "246z720t5nnetdgp0xw9tbai6zf4cvtf";
const client_secret = "a42b3911-fa3b-4f44-8a42-127966f96919";
const token_url = "https://api.transmitsecurity.io/cis/oidc/token";
const roles_base_url =
  "https://api.transmitsecurity.io/cis/v1/organizations/uovh59ypbxkea4ir9dnqp/members";

async function getAccessTokenRoles() {
  const params = new URLSearchParams();
  params.append("client_id", client_id);
  params.append("client_secret", client_secret);
  params.append("grant_type", "client_credentials");

  try {
    const response = await axios.post(token_url, params, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });

    // const {access_token} = response.data;
    // console.log("access_token :",access_token)
    return response.data.access_token;
  } catch (error) {
    console.error("Error fetching access token:", error);
    throw error;
  }
}

async function getAccessToken() {
  const params = new URLSearchParams();
  params.append("client_id", client_id);
  params.append("client_secret", client_secret);
  params.append("grant_type", "client_credentials");

  try {
    const response = await axios.post(token_url, params, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });

    return response.data.access_token;
  } catch (error) {
    console.error("Error fetching access token:", error);
    throw error;
  }
}

app.get("/roles", async (req, res) => {
  console.log("Inside nodejs roles to pull....");

  const sessionIdfb = req.cookies.sessionIdfb;
  console.log("sessionIdfb of nodejs:::" + sessionIdfb);

  const sessionIdfb2 = req.cookies.sessionIdfb;
  console.log("sessionIdfb2 of nodejs:::" + sessionIdfb2);

  // const sessionIdfb3 = req.headers['sessionIdfb']; // or any header name you choose
  // console.log("sessionIdfb3 of nodejs:::"+sessionIdfb3);

  const authHeader = req.headers["authorization"];
  console.log("authHeader of nodejs:::" + authHeader);
  const sessionIdfb3 =
    authHeader && authHeader.startsWith("Bearer ")
      ? authHeader.substring(7)
      : null;
  console.log("sessionIdfb3 of nodejs:::" + sessionIdfb3);

  // const sessionIdfb4 = req.headers.authorization;
  // console.log("sessionIdfb4 of nodejs:::"+sessionIdfb4);

  //   if (!sessionIdfb) {
  //     return res.status(401).json({ error: 'Unauthorized: No session ID' });
  // }

  // const { userEmail } = sessions[sessionIdfb4];

  console.log("sessions:::::12", sessions[sessionIdfb3]);
  //console.log("sessionIdfb3 of nodejs:::"+email);

  // const roles = users[email]?.roles || [];

  const user_id = req.query.user_id;
  if (!user_id) {
    return res.status(400).json({ error: "user_id is required" });
  }

  try {
    const access_token = await getAccessTokenRoles();
    const roles_url = `${roles_base_url}/${user_id}`;

    const response = await axios.get(roles_url, {
      headers: {
        Authorization: `Bearer ${access_token}`,
      },
    });

    res.json(response.data);
  } catch (error) {
    console.error("Error fetching roles:", error);
    res.status(500).json({ error: "Failed to fetch roles" });
  }
});

async function exchangeToken(code, redirect_uri, client_id, client_secret) {
  try {
    const response = await axios.post(
      "https://api.transmitsecurity.io/cis/oidc/token",
      qs.stringify({
        client_id,
        client_secret,
        code,
        grant_type: "authorization_code",
        redirect_uri,
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const tokenResponse = response.data;
    const { id_token } = tokenResponse;
    //console.log("id_token21", id_token);

    const sessionToken = jwt.sign(
      { sub: id_token, exp: Math.floor(Date.now() / 1000) + 3600 }, // 1 hour expiry
      JWT_SECRET
    );
    console.log("sessionToken1:", sessionToken);
    logger.info("sessionToken::");
    logger.info(sessionToken);
    return { ...tokenResponse, sessionToken };
  } catch (error) {
    console.error("Error handling token exchange:", error);
    throw new Error("Token exchange failed");
  }
}

app.post("/token", async (req, res) => {
  logger.info("Fetching access token115...");
  console.log("inside token call1......");
  process.stdout.write("inside token cal2......\n");
  const { code, redirect_uri } = req.body;

  const client_id = "6rsknktz4mjvv5r947lcf4fpn4oc1ufp";
  const client_secret = "8634542e-dad9-4128-95b9-1cb3f739b5aa";

  try {
    const tokenResponse = await exchangeToken(
      code,
      redirect_uri,
      client_id,
      client_secret
    );
    const sessionIdfb = uuidv4();
    res.cookie("sessionIdfb", sessionIdfb, {
      httpOnly: true,
      secure: false,
      sameSite: "None",
      maxAge: 3600000,
    }); // Set a session cookie

    logger.info(`Generated sessionIdfb: ${sessionIdfb}`);
    logger.info(
      `Token response to be stored in session: ${JSON.stringify(tokenResponse)}`
    );

    // sessions[sessionIdfb] = { tokens: tokenResponse }; // Store tokens in session

    logger.info(`Set session cookie: sessionIdfb=${sessionIdfb}`);
    console.log(`Set session cookie: sessionIdfb=${sessionIdfb}`);
    //console.log("##tokenResponse:",tokenResponse);
    const { id_token, sessionToken, access_token } = tokenResponse;
    const decodedToken = jwt.decode(id_token);
    const userEmail = decodedToken.email;
    const sub = decodedToken.sub;
    console.log("\n subject: " + sub);
    console.log("\n sessionToken: " + sessionToken);

    console.log("\n\n id_token::" + id_token);
    console.log("\n\n userEmail172916::" + userEmail);
    console.log("\n\n access_token::" + access_token);
    sessions[sessionIdfb] = {
      userEmail,
      access_token,
      id_token,
      createdAt: Date.now(),
    };

    res.json({
      email: userEmail,
      sub,
      id_token,
      access_token,
      sessionToken,
      sessionIdfb,
    });
    ///res.json(tokenResponse);
  } catch (error) {
    logger.info("Token exchange failed144..." + error);
    res
      .status(500)
      .json({ error: "Token exchange failed the backend error is:" + error });
  }
});

app.get("/callback", async (req, res) => {
  const { code } = req.query;
  const sessionIdfb = req.cookies.sessionIdfb;

  if (!sessionIdfb || !sessions[sessionIdfb]) {
    return res.status(400).json({ error: "Invalid session" });
  }

  const { codeVerifier } = sessions[sessionIdfb];

  try {
    const response = await axios.post(TOKEN_ENDPOINT, {
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      grant_type: "authorization_code",
      code_verifier: codeVerifier,
    });

    const { access_token, refresh_token, id_token } = response.data;

    sessions[sessionIdfb].tokens = { access_token, refresh_token, id_token };
    res.redirect("/profile");
  } catch (error) {
    console.error("Error exchanging code for tokens:", error);
    res.redirect("/error");
  }
});

app.get("/profile", async (req, res) => {
  const sessionIdfb = req.cookies.sessionIdfb;

  if (!sessionIdfb || !sessions[sessionIdfb] || !sessions[sessionIdfb].tokens) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { access_token } = sessions[sessionIdfb].tokens;

  try {
    const response = await axios.get(USERINFO_ENDPOINT, {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    res.json(response.data);
  } catch (error) {
    console.error("Error fetching user info:", error);
    res.status(401).json({ error: "Unauthorized" });
  }
});

app.get("/user-info", async (req, res) => {
  const sessionIdfb = req.cookies.sessionIdfb;

  if (!sessionIdfb || !sessions[sessionIdfb] || !sessions[sessionIdfb].tokens) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { access_token, id_token } = sessions[sessionIdfb].tokens;

  const idTokenPayload = JSON.parse(
    Buffer.from(id_token.split(".")[1], "base64").toString("utf8")
  );

  res.json({
    first_name: idTokenPayload.given_name,
    last_name: idTokenPayload.family_name,
    email: idTokenPayload.email,
  });
});

app.post("/logout", async (req, res) => {
  const sessionIdfb = req.cookies.sessionIdfb;

  if (!sessionIdfb || !sessions[sessionIdfb]) {
    return res.status(400).json({ error: "Invalid session" });
  }

  const { access_token } = sessions[sessionIdfb].tokens;

  try {
    await axios.post(LOGOUT_ENDPOINT, null, {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    delete sessions[sessionIdfb];
    res.clearCookie("sessionIdfb");
    res.json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Error during logout:", error);
    res.status(500).json({ error: "Logout failed" });
  }
});

// New endpoint to fetch user details by email
app.get("/users/email/:email", async (req, res) => {
  const email = req.params.email;

  try {
    const access_token = await getAccessToken();
    const user_url = `https://api.transmitsecurity.io/cis/v1/users/email/${email}`;

    const response = await axios.get(user_url, {
      headers: {
        Authorization: `Bearer ${access_token}`,
        "Content-Type": "application/json",
      },
    });

    res.json(response.data);
  } catch (error) {
    console.error("Error fetching user by email:", error);
    res.status(500).json({ error: "Failed to fetch user" });
  }
});

app.get("/users", async (req, res) => {
  try {
    const testdata = {
      result: "success",
    };

    res.json(testdata);
  } catch (error) {
    console.error("Error fetching user by email:", error);
    res.status(500).json({ error: "Failed to fetch user" });
  }
});

// New endpoint to update user status

app.put("/users/status/:user_id", async (req, res) => {
  const user_id = req.params.user_id;
  const { status } = req.body;

  try {
    const access_token = await getAccessToken();
    const user_url = `https://api.transmitsecurity.io/cis/v1/users/${user_id}`;

    const response = await axios.put(
      user_url,
      { status: status || "Disabled" }, // Use provided status or default to "Disabled"
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
          "Content-Type": "application/json",
        },
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error("Error updating user status:", error);
    if (error.response && error.response.status === 404) {
      console.log("here....308");
      res.status(404).json({ error: "User not found" });
    } else {
      res.status(500).json({ error: "Failed to update user status" });
    }
  }
});

app.listen(port, () => {
  console.log(
    `########### ${new Date()} Server running at http://localhost:${port}`
  );
});
