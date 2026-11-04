// ==================== CONFIGURATION ====================
const TARGET_SITE = "https://krillion.io";
const CORRECT_PASSWORD = "Iskender"; 
const MASTER_CODE = "RiddleA7c";
const CUSTOM_PROMPT = "switch a to e";
// =======================================================

const DEPLOYMENT_SECRET = crypto.randomUUID();

interface LockoutInfo {
  attempts: number;
  lockoutUntil: number;
}
const ipTracker = new Map<string, LockoutInfo>();
const activeSessions = new Map<string, number>();

// Perfectly Centered Layout Engine
function renderThemedPage(titleText: string, bodyContent: string) {
  return [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '  <title>Proxy Authorization</title>',
    '  <meta charset="UTF-8">',
    '  <meta name="viewport" content="width=device-width, initial-scale=1.0">',
    '  <style>',
    '    * { box-sizing: border-box; }',
    '    html, body { height: 100%; margin: 0; padding: 0; }',
    '    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; background: #121212; color: #ffffff; padding: 20px; }',
    '    .card { background: #1e1e1e; padding: 40px 30px; border-radius: 16px; box-shadow: 0 8px 30px rgba(0,0,0,0.6); text-align: center; max-width: 420px; width: 100%; }',
    '    h2 { margin-top: 0; margin-bottom: 24px; font-size: 1.3rem; color: #f0f0f0; line-height: 1.5; font-weight: 600; }',
    '    input[type="password"], input[type="text"] { width: 100%; padding: 14px; margin: 10px 0 20px 0; border-radius: 8px; border: 1px solid #333; background: #2a2a2a; color: #fff; font-size: 1rem; text-align: center; outline: none; transition: border-color 0.2s; }',
    '    input:focus { border-color: #00fa9a; }',
    '    button { background: #00fa9a; color: #000; border: none; padding: 14px 24px; font-weight: bold; border-radius: 8px; cursor: pointer; width: 100%; font-size: 1rem; transition: background 0.2s; }',
    '    button:hover { background: #00c87d; }',
    '    .error-title { color: #ff6b6b; font-weight: bold; font-size: 1.2rem; margin-bottom: 10px; }',
    '    .info-text { color: #aaa; font-size: 0.95rem; line-height: 1.6; margin-bottom: 20px; }',
    '    .status-box { background: #2a1a1a; padding: 12px; border-radius: 8px; border: 1px solid #5a2a2a; color: #ff8b8b; font-size: 0.9rem; margin-bottom: 24px; }',
    '    .divider { border: 0; border-top: 1px solid #333; margin: 24px 0; }',
    '    .admin-label { color: #888; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; display: block; }',
    '  </style>',
    '</head>',
    '<body>',
    '  <div class="card">',
    '    <h2>' + titleText + '</h2>',
    '    ' + bodyContent,
    '  </div>',
    '</body>',
    '</html>'
  ].join('\n');
}

Deno.serve(async (req: Request, info) => {
  const url = new URL(req.url);
  
  let clientIp = "unknown-ip";
  if (info && info.remoteAddr && "hostname" in info.remoteAddr) {
    clientIp = info.remoteAddr.hostname;
  }

  const targetUrl = new URL(url.pathname + url.search, TARGET_SITE);

  if (!ipTracker.has(clientIp)) {
    ipTracker.set(clientIp, { attempts: 0, lockoutUntil: 0 });
  }
  const status = ipTracker.get(clientIp)!;

  const cookieHeader = req.headers.get("cookie") || "";
  const cookieMatch = cookieHeader.match(new RegExp(`session_${DEPLOYMENT_SECRET}=([^;]+)`));
  const sessionToken = cookieMatch ? cookieMatch[1] : null;
  
  let isAuthenticated = false;
  if (sessionToken && activeSessions.has(sessionToken)) {
    const expiry = activeSessions.get(sessionToken)!;
    if (Date.now() < expiry) {
      isAuthenticated = true;
    } else {
      activeSessions.delete(sessionToken);
    }
  }

  // Action Form Handling
  if (req.method === "POST" && url.pathname === "/proxy-login") {
    try {
      const formData = await req.formData();
      const enteredPassword = formData.get("password")?.toString();

      // Check Master Override Key
      if (enteredPassword === MASTER_CODE) {
        status.attempts = 0;
        status.lockoutUntil = 0;
        
        return new Response(renderThemedPage("System Override", `
          <div style="color: #00fa9a; font-weight: bold; font-size: 1.2rem; margin-bottom: 10px;">Bypass Successful</div>
          <p class="info-text">The network ban has been successfully lifted.</p>
          <button onclick="window.location.href='/'" style="margin-top: 10px;">Return to Login</button>
        `), { headers: { "Content-Type": "text/html" } });
      }

      // Hard stop if currently banned
      if (status.lockoutUntil > Date.now()) {
        const minutesLeft = Math.ceil((status.lockoutUntil - Date.now()) / 60000);
        return new Response(renderThemedPage("Access Denied", `
          <div class="error-title">Security Lockout Active</div>
          <p class="info-text">Too many bad attempts. Access restricted for ${minutesLeft} more minutes.</p>
          <div class="divider"></div>
          <span class="admin-label">System Administrator Override</span>
          <form action="/proxy-login" method="POST">
            <input type="text" name="password" placeholder="Enter Master Override Code" required autocomplete="off">
            <button type="submit" style="background: #ff6b6b; color: #fff;">Clear Lockout</button>
          </form>
        `), { status: 429, headers: { "Content-Type": "text/html" } });
      }

      // Evaluate Standard Password
      if (enteredPassword === CORRECT_PASSWORD) {
        status.attempts = 0;
        status.lockoutUntil = 0;

        const newSessionToken = crypto.randomUUID();
        const sessionDurationMs = 20 * 60 * 1000; 
        activeSessions.set(newSessionToken, Date.now() + sessionDurationMs);

        return new Response(null, {
          status: 302,
          headers: {
            "Location": "/",
            "Set-Cookie": `session_${DEPLOYMENT_SECRET}=${newSessionToken}; Path=/; HttpOnly; SameSite=Strict`,
          },
        });
      } else {
        status.attempts += 1;
        
        if (status.attempts >= 5) {
          status.lockoutUntil = Date.now() + (15 * 60 * 1000);
          return new Response(renderThemedPage("Access Suspended", `
            <div class="error-title">Maximum Attempts Exceeded</div>
            <p class="info-text">Your connection has been temporarily locked out for 15 minutes.</p>
            <div class="divider"></div>
            <span class="admin-label">System Administrator Override</span>
            <form action="/proxy-login" method="POST">
              <input type="text" name="password" placeholder="Enter Master Override Code" required autocomplete="off">
              <button type="submit" style="background: #ff6b6b; color: #fff;">Clear Lockout</button>
            </form>
          `), { status: 429, headers: { "Content-Type": "text/html" } });
        }

        const attemptsLeft = 5 - status.attempts;
        return new Response(renderThemedPage("Authentication Failed", `
          <div class="error-title">Invalid Credentials</div>
          <p class="info-text">The key phrase entered is incorrect.</p>
          <div class="status-box">
            ${attemptsLeft} ${attemptsLeft === 1 ? 'attempt remains' : 'attempts remain'} before lockout.
          </div>
          <button onclick="window.location.href='/'">Try Again</button>
        `), { headers: { "Content-Type": "text/html" } });
      }
    } catch {
      return new Response("Bad Request", { status: 400 });
    }
  }

  // Gateway route if not authenticated
  if (!isAuthenticated) {
    if (status.lockoutUntil > Date.now()) {
      const remainingTime = Math.ceil((status.lockoutUntil - Date.now()) / 60000);
      return new Response(renderThemedPage("Access Suspended", `
        <div class="error-title">Security Lockout Active</div>
        <p class="info-text">Please wait ${remainingTime} minutes before attempting authentication.</p>
        <div class="divider"></div>
        <span class="admin-label">System Administrator Override</span>
        <form action="/proxy-login" method="POST">
          <input type="text" name="password" placeholder="Enter Master Override Code" required autocomplete="off">
          <button type="submit" style="background: #ff6b6b; color: #fff;">Clear Lockout</button>
        </form>
      `), { headers: { "Content-Type": "text/html" } });
    }

    return new Response(renderThemedPage("Gateway Authentication", `
      <div style="font-size: 1.1rem; margin-bottom: 20px; line-height: 1.5; color: #e0e0e0;">${CUSTOM_PROMPT}</div>
      <form action="/proxy-login" method="POST">
        <input type="password" name="password" placeholder="Enter password..." required autofocus>
        <button type="submit">Unlock Game</button>
      </form>
    `), { headers: { "Content-Type": "text/html" } });
  }

  // Serve verified connection to Krillion
  try {
    const forwardHeaders = new Headers(req.headers);
    forwardHeaders.set("host", "krillion.io");
    return await fetch(targetUrl.href, {
      method: req.method,
      headers: forwardHeaders,
      body: req.body,
      redirect: "manual"
    });
  } catch (err) {
    return new Response(`Proxy Error: ${err.message}`, { status: 500 });
  }
});
