const express = require('express');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cookieParser());

// Set up environment variables
const CANVA_CLIENT_ID = process.env.CANVA_CLIENT_ID;
const CANVA_CLIENT_SECRET = process.env.CANVA_CLIENT_SECRET;

if (!CANVA_CLIENT_ID) {
  throw new Error("CANVA_CLIENT_ID environment variable is not set");
}

if (!CANVA_CLIENT_SECRET) {
  throw new Error("CANVA_CLIENT_SECRET environment variable is not set");
}

// Create the server URL
const CODESPACE_NAME = process.env.CODESPACE_NAME;
const PORT = process.env.PORT || 3000;
const SERVER_URL = CODESPACE_NAME
  ? `https://${CODESPACE_NAME}-${PORT}.app.github.dev`
  : `http://localhost:${PORT}`;

// Create the Redirect URL
const REDIRECT_URI_PATH = "/oauth/redirect";
const REDIRECT_URI = SERVER_URL + REDIRECT_URI_PATH;

// Handles requests to the index page
app.get('/', (req, res) => {
  const scopes = new Set([
    "app:read",
    "app:write",
    "design:content:read",
    "design:meta:read",
    "design:content:write",
    "design:permission:read",
    "design:permission:write",
    "folder:read",
    "folder:write",
    "folder:permission:read",
    "folder:permission:write",
    "asset:read",
    "asset:write",
    "comment:read",
    "comment:write",
    "brandtemplate:meta:read",
    "brandtemplate:content:read",
    "profile:read",
  ]);

  const codeVerifier = createCodeVerifier();
  const state = createState();

  // Store the code verifier and state in cookies with appropriate settings
  res.cookie('codeVerifier', codeVerifier, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax'
  });
  res.cookie('state', state, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax'
  });

  createCodeChallenge(codeVerifier).then(codeChallenge => {
    buildAuthUrl({
      clientId: CANVA_CLIENT_ID,
      redirectUri: REDIRECT_URI,
      scopes,
      codeChallenge,
      state,
    }).then(authUrl => {
      const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Log in with Canva</title>
      </head>
      <body>
        <button onclick="window.location.href='${authUrl}'">Log in with Canva</button>
      </body>
      </html>
    `;

      res.send(html);
    });
  });
});

// Handles requests to the Redirect URL
app.get(REDIRECT_URI_PATH, async (req, res) => {
  const { code, state: returnedState } = req.query;
  const { codeVerifier, state: storedState } = req.cookies;

  if (!codeVerifier) {
    return res.status(400).send("Invalid codeVerifier");
  }

  if (returnedState !== storedState) {
    return res.status(400).send(`Invalid state. Returned: ${returnedState}, Stored: ${storedState}`);
  }

  try {

    const tokenResponse = await fetchAccessToken(
      code,
      codeVerifier,
      CANVA_CLIENT_ID,
      CANVA_CLIENT_SECRET,
      REDIRECT_URI
    );

    res.clearCookie('codeVerifier');
    res.clearCookie('state');

    res.json(tokenResponse);
  } catch (error) {
    res.status(500).send(`Error exchanging code for token: ${error.message}`);
  }
});

function createCodeVerifier() {
  return crypto.randomBytes(64).toString('hex').slice(0, 128);
}

function createState(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

async function createCodeChallenge(codeVerifier) {
  const hash = crypto.createHash('sha256');
  hash.update(codeVerifier);
  return hash.digest('base64')
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function buildAuthUrl(opts) {
  const url = new URL("https://www.canva.com/api/oauth/authorize");

  url.searchParams.append("code_challenge_method", "S256");
  url.searchParams.append("response_type", "code");
  url.searchParams.append("client_id", opts.clientId);
  url.searchParams.append("code_challenge", opts.codeChallenge);
  url.searchParams.append("scope", Array.from(opts.scopes).join(" "));
  url.searchParams.append("redirect_uri", opts.redirectUri);
  url.searchParams.append("state", opts.state);

  return url.toString();
}

async function fetchAccessToken(
  code,
  codeVerifier,
  clientId,
  clientSecret,
  redirectUri,
) {
  const endpoint = "https://api.canva.com/rest/v1/oauth/token";
  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Authorization": `Basic ${credentials}`,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri,
    }),
  });

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  return response.json();
}
app.listen(PORT, () => {
  console.log(`The server is running at ${SERVER_URL}`);
  console.log(`The Redirect URL is ${REDIRECT_URI}`);
});