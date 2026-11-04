// ==================== CONFIGURATION ====================
const TARGET_SITE = "https://krillion.io";
const CORRECT_PASSWORD = "Iskender"; 
const MASTER_CODE = "RiddleA7c";
const CUSTOM_PROMPT = "Same as last password but switch a for e";
// =======================================================

// Generate a brand new server key on every single deployment/restart.
// This guarantees that any cookies issued BEFORE you changed the code 
// become immediately invalid and unreadable by the server.
const DEPLOYMENT_SECRET = crypto.randomUUID();

// Memory tracking for rate-limiting (Survives page reloads)
interface LockoutInfo {
  attempts: number;
  lockoutUntil: number;
}
const ipTracker = new Map<string, LockoutInfo>();

// Memory tracking for sessions (Session token -> Expiry Timestamp)
// This naturally wipes clean whenever Deno redeploys your code!
const activeSessions = new Map<string, number>();

Deno.serve(async (req: Request, info) => {
  const url = new URL(req.url);
  const clientIp = info.remoteAddr.hostname || "unknown-ip";
  const now = Date.now();

  // Force absolute restriction to krillion.io
  const targetUrl = new URL(url.pathname + url.search, TARGET_SITE);

  // Initialize or get rate-limiting status for this IP
  if (!ipTracker.has(clientIp)) {
    ipTracker.set(clientIp, { attempts: 0, lockoutUntil: 0 });
  }
  const status = ipTracker.get(clientIp)!;

  // Read cookies to check session status
  const cookieHeader = req.headers.get("cookie") || "";
  
  // Look for a session cookie that matches our current deployment's secret format
  const cookieMatch = cookieHeader.match(new RegExp(`session_${DEPLOYMENT_SECRET}=([^;]+)`));
  const sessionToken = cookieMatch ? cookieMatch[1] : null;
  
  let isAuthenticated = false;
  if (sessionToken && activeSessions.has(sessionToken)) {
    const expiry = activeSessions.get(sessionToken)!;
    if (now < expiry) {
      isAuthenticated = true;
    } else {
      activeSessions.delete(sessionToken); // Clean up expired session
    }
  }

  // Handle Login Submission
  if (req.method === "POST" && url.pathname === "/proxy-login") {
    if (status.lockoutUntil > now) {
      const minutesLeft = Math.ceil((status.lockoutUntil - now) / 60000);
      return new Response(`Too many failed attempts. Try again in ${minutesLeft} minutes.`, { status: 429 });
    }

    try {
      const formData = await req.formData();
      const enteredPassword = formData.get("password")?.toString();

      // Master code execution
      if (enteredPassword === MASTER_CODE) {
        status.attempts = 0;
        status.lockoutUntil = 0;
        return new Response("Lockout timer reset. Please go back and try again.");
      }

      // Password Verification
      if (enteredPassword === CORRECT_PASSWORD) {
        status.attempts = 0;
        status.lockoutUntil = 0;

        // Generate session properties
        const newSessionToken = crypto.randomUUID();
        const sessionDurationMs = 20 * 60 * 1000; // 20 minutes
        activeSessions.set(newSessionToken, now + sessionDurationMs);

        // Name the cookie using the unique deployment secret so old cookies are discarded
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
          status.lockoutUntil = now + (15 * 60 * 1000); // 15-minute ban
          return new Response("Too many failed attempts. You are locked out for 15 minutes.", { status: 429 });
        }
        return new Response(`Incorrect password. ${5 - status.attempts} attempts remaining. <a href="/">Try again</a>`, {
          headers: { "Content-Type": "text/html" }
        });
      }
    } catch {
      return new Response("Bad Request", { status: 400 });
    }
  }

  // If not logged in, render the custom password prompt screen
  if (!isAuthenticated) {
    const isLockedOut = status.lockoutUntil > now;
    const remainingTime = isLockedOut ? Math.ceil((status.lockoutUntil - now) / 60000) : 0;

    const loginHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Proxy Authorization</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
          body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #121212; color: #fff; margin: 0; }
          .card { background: #1e1e1e; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); text-align: center; max-width: 400px; width: 90%; }
          h2 { margin-bottom: 20px; font-size: 1.2rem; color: #e0e0e0; }
          input[type="password"] { width: 100%; padding: 12px; margin: 15px 0; border-radius: 6px; border: 1px solid #333; background: #2a2a2a; color: #fff; box-sizing: border-box; }
          button { background: #00fa9a; color: #000; border: none; padding: 12px 24px; font-weight: bold; border-radius: 6px; cursor: pointer; width: 100%; }
          button:hover { background: #00c87d; }
          .error { color: #ff6b6b; font-weight: bold; margin-bottom: 10px; }
        </style>
      </head>
      <body>
        <div class="card">
          <h2>${CUSTOM_PROMPT}</h2>
          ${isLockedOut ? `<div class="error">Locked out! Try again in ${remainingTime} mins.</div>` : `
            <form action="/proxy-login" method="POST">
              <input type="password" name="password" placeholder="Enter password..." required autofocus>
              <button type="submit">Unlock Game</button>
            </form>
          `}
        </div>
      </body>
      </html>
    `;
    return new Response(loginHtml, { headers: { "Content-Type": "text/html" } });
  }

  // Pass traffic safely to Krillion if authenticated
  try {
    const forwardHeaders = new Headers(req.headers);
    forwardHeaders.set("host", "krillion.io");

    const response = await fetch(targetUrl.href, {
      method: req.method,
      headers: forwardHeaders,
      body: req.body,
      redirect: "manual"
    });

    return response;
  } catch (err) {
    return new Response(`Proxy Error: ${err.message}`, { status: 500 });
  }
});
