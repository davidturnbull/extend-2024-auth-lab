const express = require('express');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cookieParser());

const CANVA_CLIENT_ID = process.env.CANVA_CLIENT_ID;
const CANVA_CLIENT_SECRET = process.env.CANVA_CLIENT_SECRET;

if (!CANVA_CLIENT_ID) {
  throw new Error("CANVA_CLIENT_ID environment variable is not set");
}

if (!CANVA_CLIENT_SECRET) {
  throw new Error("CANVA_CLIENT_SECRET environment variable is not set");
}

// Handles requests to the index page
app.get('/', (req, res) => {
  // The list of scopes to request access to
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

  // Generate "code verifier" and "state" strings
  const codeVerifier = createCodeVerifier();
  const state = createState();

  // Store the code verifier and state in cookies
  res.cookie('codeVerifier', codeVerifier, { httpOnly: true, secure: true });
  res.cookie('state', state, { httpOnly: true, secure: true });

  // Create a "code challenge" that's derived from the code verifier
  createCodeChallenge(codeVerifier).then(codeChallenge => {
    // Construct the URL of the "Log in with Canva" button
    const redirectUri = `${req.protocol}://${req.get('host')}/oauth/redirect`;
    buildAuthUrl({
      clientId: CANVA_CLIENT_ID,
      redirectUri: redirectUri,
      scopes,
      codeChallenge,
      state,
    }).then(authUrl => {
      // Create the HTML that renders a "Log in with Canva" button
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

      // Return the HTML for the index page
      res.send(html);
    });
  });
});

// Handles requests to the Redirect URL
app.get('/oauth/redirect', async (req, res) => {
  const { code, state } = req.query;
  const { codeVerifier, state: storedState } = req.cookies;

  // If the code verifier isn't available, the request is invalid
  if (!codeVerifier) {
    return res.status(400).send("Invalid codeVerifier");
  }

  // If the stored state doesn't match the "state" query parameter, the request is invalid
  if (state !== storedState) {
    return res.status(400).send("Invalid state");
  }

  // Use the "code" and "code verifier" values to fetch an access token
  try {
    const redirectUri = `${req.protocol}://${req.get('host')}/oauth/redirect`;
    const tokenResponse = await fetchAccessToken(
      code,
      codeVerifier,
      CANVA_CLIENT_ID,
      CANVA_CLIENT_SECRET,
      redirectUri,
    );

    // Clear the cookies
    res.clearCookie('codeVerifier');
    res.clearCookie('state');

    // If the values are valid, the response will contain an access token
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});