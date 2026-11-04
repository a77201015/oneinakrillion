// ==================== CONFIGURATION ====================
const TARGET_SITE = "https://krillion.io";
const CORRECT_PASSWORD = "Iskender"; 
const MASTER_CODE = "RiddleA7c";
const CUSTOM_PROMPT = "Same as last password but switch a for e";
// =======================================================

const DEPLOYMENT_SECRET = crypto.randomUUID();

interface LockoutInfo {
  attempts: number;
  lockoutUntil: number;
}
const ipTracker = new Map<string, LockoutInfo>();
const activeSessions = new Map<string, number>();

// Reusable Professional Dark-Themed Page Wrapper
function renderThemedPage(titleText: string, bodyContent: html) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Proxy Authorization</title>
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #121212; color: #fff; margin: 0; }
        .card { background: #1e1e1e; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); text-align: center; max-width: 400px; width: 90%; }
        h2 { margin-top: 0; margin-bottom: 20px; font-size: 1.2rem; color: #e0e0e0; line-height: 1.4; }
        input[type="password"], input[type="text"] { width: 100%; padding: 12px; margin: 15px 0; border-radius: 6px; border: 1px solid #333; background: #2a2a2a; color: #fff; box-sizing: border-box; text-align: center; }
        button { background: #00fa9a; color: #000; border: none; padding: 12px 24px; font-weight: bold; border-radius: 6px; cursor: pointer; width: 100%; font-size: 1rem; margin-top: 5px; }
        button:hover { background: #00c87d; }
        .error { color: #ff6b6b; font-weight: bold; margin-bottom: 15px; font-size: 1rem; line-height: 1.4; }
        .info { color: #888; font-size: 0.9rem; margin-top: 15px; }
        a { color: #00fa9a; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>${titleText}</h2>
        ${bodyContent}
      </div>
    </body>
    </html>
  `;
}

Deno.serve(async (req: Request, info) => {
  const url = new URL(req.url);
  const clientIp = info.remoteAddr.hostname || "unknown-ip";
  const now = Date.now();

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
    if (now < expiry) {
      isAuthenticated = true;
    } else {
      activeSessions.delete(sessionToken);
    }
  }

  // Handle Login or Master Unlock Submissions
  if (req.method === "POST" && url.pathname === "/proxy-login") {
    try {
      const formData = await req.formData();
      const enteredPassword = formData.get("password")?.toString();

      // Master code verification (Can be entered at normal screen or lockout screen)
      if (enteredPassword === MASTER_CODE) {
        status.attempts = 0;
        status.lockoutUntil = 0;
        
        const masterSuccessHtml = renderThemedPage("System Override", `
          <div style="color: #00fa9a; font-weight: bold; margin-bottom: 20px;">Master Code Accepted</div>
          <p class="info" style="color: #bbb; margin-bottom: 20px;">The security ban for your IP address has been successfully lifted.</p>
          <a href="/"><button type="button">Return to Login</button></a>
        `);
        return new Response(masterSuccessHtml, { headers: { "Content-Type": "text/html" } });
      }

      // If user is locked out and didn't use the master code, block them
      if (status.lockoutUntil > now) {
        const minutesLeft = Math.ceil((status.lockoutUntil - now) / 60000);
        const lockedHtml = renderThemedPage("Access Suspended", `
          <div class="error">Security Lockout Active</div>
          <p class="info" style="color: #bbb;">Too many failed attempts. Your access is restricted for another ${minutesLeft} minutes.</p>
          <hr style="border: 0; border-top: 1px solid #333; margin: 20px 0;">
          <p class="info">Administrator? Enter Master Code to override:</p>
          <form action="/proxy-login" method="POST">
            <input type="text" name="password" placeholder="Master Override Code" required autocomplete="off">
            <button type="submit" style="background: #ff6b6b; color: #fff;">Execute Override</button>
          </form>
        `);
        return new Response(lockedHtml, { status: 429, headers: { "Content-Type": "text/html" } });
      }

      // Standard Password Verification
      if (enteredPassword === CORRECT_PASSWORD) {
        status.attempts = 0;
        status.lockoutUntil = 0;

        const newSessionToken = crypto.randomUUID();
        const sessionDurationMs = 20 * 60 * 1000; 
        activeSessions.set(newSessionToken, now + sessionDurationMs);

        return new Response(null, {
          status: 302,
          headers: {
            "Location": "/",
            "Set-Cookie": `session_${DEPLOYMENT_SECRET}=${newSessionToken}; Path=/; HttpOnly; SameSite=Strict`,
          },
        });
      } else {
        // Failed attempt handling
        status.attempts += 1;
        
        if (status.attempts >= 5) {
          status.lockoutUntil = now + (15 * 60 * 1000); // 15-minute ban
          const justLockedHtml = renderThemedPage("Access Suspended", `
            <div class="error">Maximum Attempts Exceeded</div>
            <p class="info" style="color: #bbb;">You have been locked out for 15 minutes due to security protocols.</p>
            <hr style="border: 0; border-top: 1px solid #333; margin: 20px 0;">
            <p class="info">Administrator? Enter Master Code to override:</p>
            <form action="/proxy-login" method="POST">
              <input type="text" name="password" placeholder="Master Override Code" required autocomplete="off">
              <button type="submit" style="background: #ff6b6b; color: #fff;">Execute Override</button>
            </form>
          `);
          return new Response(justLockedHtml, { status: 429, headers: { "Content-Type": "text/html" } });
        }

        // Professional-themed incorrect password message
        const attemptsLeft = 5 - status.attempts;
        const failedHtml = renderThemedPage("Authorization Failed", `
          <div class="error">Incorrect Password</div>
          <p style="color: #bbb; margin-bottom: 20px;">The credentials provided do not match our configuration records.</p>
          <div class="info" style="background: #2a1a1a; padding: 10px; border-radius: 6px; border: 1px solid #5a2a2a; color: #ff8b8b; margin-bottom: 20px;">
            ${attemptsLeft} authentication ${attemptsLeft === 1 ? 'attempt remains' : 'attempts remain'} before lockout.
          </div>
          <a href="/"><button type="button">Try Again</button></a>
        `);
        return new Response(failedHtml, { headers: { "Content-Type": "text/html" } });
      }
    } catch {
      return new Response("Bad Request", { status: 400 });
    }
  }

  // Rendering for Default Unauthenticated Request
  if (!isAuthenticated) {
    if (status.lockoutUntil > now) {
      const remainingTime = Math.ceil((status.lockoutUntil - now) / 60000);
      const activeLockoutHtml = renderThemedPage("Access Suspended", `
        <div class="error">Security Lockout Active</div>
        <p class="info" style="color: #bbb;">Please wait ${remainingTime} minutes before trying again.</p>
        <hr style="border: 0; border-top: 1px solid #333; margin: 20px 0;">
        <p class="info">Administrator? Enter Master Code to override:</p>
        <form action="/proxy-login" method="POST">
          <input type="text" name="password" placeholder="Master Override Code" required autocomplete="off">
          <button type="submit" style="background: #ff6b6b; color: #fff;">Execute Override</button>
        </form>
      `);
      return new Response(activeLockoutHtml, { headers: { "Content-Type": "text/html" } });
    }

    const defaultLoginHtml = renderThemedPage(CUSTOM_PROMPT, `
      <form action="/proxy-login" method="POST">
        <input type="password" name="password" placeholder="Enter password..." required autofocus>
        <button type="submit">Unlock Game</button>
      </form>
    `);
    return new Response(defaultLoginHtml, { headers: { "Content-Type": "text/html" } });
  }

  // Serve authorized stream directly
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
