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

// Determine the server URL based on whether the app is running in a GitHub Codespace
const CODESPACE_NAME = process.env.CODESPACE_NAME;
const PORT = process.env.PORT || 3000;
const SERVER_URL = CODESPACE_NAME
  ? `https://${CODESPACE_NAME}-${PORT}.app.github.dev`
  : `http://localhost:${PORT}`;

// Define the OAuth redirect URI path
const REDIRECT_URI_PATH = "/oauth/redirect";
const REDIRECT_URI = SERVER_URL + REDIRECT_URI_PATH;

// Route for the index page, which initiates the OAuth flow
app.get('/', async (req, res) => {
  try {
    // Define the OAuth scopes required for the app
    const oauthScopes = new Set([
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

    // Generate a code verifier and state value for PKCE and CSRF protection
    const oauthCodeVerifier = createCodeVerifier();
    const oauthState = generateOAuthState();

    // Store the code verifier and state in cookies to be retrieved after the OAuth redirect
    res.cookie('oauthCodeVerifier', oauthCodeVerifier, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax' // Lax policy is used for CSRF protection
    });
    res.cookie('oauthState', oauthState, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax'
    });

    // Create the code challenge from the code verifier
    const codeChallenge = await createCodeChallenge(oauthCodeVerifier);

    // Build the Canva OAuth authorization URL
    const authUrl = await buildCanvaAuthUrl(
      oauthScopes,
      codeChallenge,
      oauthState,
      REDIRECT_URI,
      CANVA_CLIENT_ID
    );

    // Respond with an HTML page containing a "Log in with Canva" button
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
  } catch (error) {
    // Handle any errors that occur during the OAuth initialization
    res.status(500).send(`Error generating authentication URL: ${error.message}`);
  }
});

// Route to handle the OAuth redirect and exchange the authorization code for an access token
app.get(REDIRECT_URI_PATH, async (req, res) => {
  const { code, state: returnedOAuthState } = req.query; // Extract the code and state from the query parameters
  const { oauthCodeVerifier, oauthState: storedOAuthState } = req.cookies; // Retrieve the code verifier and state from cookies

  // Validate the code verifier and state to ensure they match what was stored before the redirect
  if (!oauthCodeVerifier) {
    return res.status(400).send("Invalid OAuth code verifier");
  }

  if (returnedOAuthState !== storedOAuthState) {
    return res.status(400).send(`Invalid OAuth state. Returned: ${returnedOAuthState}, Stored: ${storedOAuthState}`);
  }

  try {
    // Exchange the authorization code for an access token using the stored code verifier
    const tokenResponse = await fetchAccessToken(
      code,
      oauthCodeVerifier,
      REDIRECT_URI,
      CANVA_CLIENT_ID,
      CANVA_CLIENT_SECRET
    );

    // Clear the cookies after the token exchange to protect the data
    res.clearCookie('oauthCodeVerifier');
    res.clearCookie('oauthState');

    // Respond with the access token JSON data
    res.json(tokenResponse);
  } catch (error) {
    // Handle errors that occur during the token exchange process
    res.status(500).send(`Error exchanging code for token: ${error.message}`);
  }
});

// Function to generate a code verifier (a random string used in PKCE)
function createCodeVerifier() {
  return crypto.randomBytes(64).toString('hex').slice(0, 128);
}

// Function to generate a random state value for CSRF protection
function generateOAuthState(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

// Function to create a code challenge from the code verifier using SHA-256
async function createCodeChallenge(codeVerifier) {
  const hash = crypto.createHash('sha256');
  hash.update(codeVerifier);
  return hash.digest('base64')
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// Function to build the Canva OAuth authorization URL with the required parameters
async function buildCanvaAuthUrl(
  scopes,
  codeChallenge,
  state,
  redirectUri,
  clientId = CANVA_CLIENT_ID
) {
  const url = new URL("https://www.canva.com/api/oauth/authorize");

  // Append necessary query parameters to the OAuth URL
  url.searchParams.append("code_challenge_method", "S256");
  url.searchParams.append("response_type", "code");
  url.searchParams.append("client_id", clientId);
  url.searchParams.append("code_challenge", codeChallenge);
  url.searchParams.append("scope", Array.from(scopes).join(" "));
  url.searchParams.append("redirect_uri", redirectUri);
  url.searchParams.append("state", state);

  return url.toString();
}

// Function to exchange the authorization code for an access token
async function fetchAccessToken(
  code,
  codeVerifier,
  redirectUri,
  clientId = CANVA_CLIENT_ID,
  clientSecret = CANVA_CLIENT_SECRET
) {
  const endpoint = "https://api.canva.com/rest/v1/oauth/token";
  const credentials = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

  // Send the POST request to exchange the code for an access token
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

  // Check for an HTTP error and throw an exception if one occurs
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  // Parse and return the JSON response containing the access token
  return response.json();
}

// Start the Express server and listen on the specified port
app.listen(PORT, () => {
  console.log(`The server is running at ${SERVER_URL}`);
  console.log(`The Redirect URL is ${REDIRECT_URI}`);
});
