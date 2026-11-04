const UPSTREAM = "https://watchthementalistonline.cc/";

Deno.serve(async (req: Request) => {
  // Build the target URL from the incoming request path and query
  const url = new URL(req.url);
  const target = new URL(url.pathname + url.search, UPSTREAM);

  // Forward the request to Krillion
  return await fetch(target.href, {
    method: req.method,
    headers: req.headers,
    body: req.body,
  });
});
