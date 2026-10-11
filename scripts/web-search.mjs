#!/usr/bin/env node
// Cipher web-search sidecar (browser fallback). The plain HTTP path
// (html.duckduckgo.com) serves a 202 bot challenge to non-browser
// clients after a few queries; a real headless Chromium passes it. This
// script searches DuckDuckGo in the browser and prints ONE JSON object:
//
//   { "query": ..., "results": [{ "title": ..., "url": ..., "snippet": ... }] }
//
// Contract: `web-search --query <q>`. Exit codes: 0 success, 2 usage
// error, 3 navigation/extraction error, 4 playwright not importable.

const args = process.argv.slice(2);
function opt(name) {
  const i = args.indexOf(name);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : null;
}
const query = opt("--query");

if (!query || !query.trim()) {
  console.error("usage: web-search --query <search terms>");
  process.exit(2);
}

async function loadPlaywright() {
  // Local node_modules first, then the global npm root (npm install -g).
  try {
    return await import("playwright");
  } catch {
    const { execSync } = await import("node:child_process");
    let globalRoot = "";
    try {
      globalRoot = execSync("npm root -g", { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    } catch {
      throw new Error("playwright not importable and `npm root -g` failed");
    }
    const { createRequire } = await import("node:module");
    const req = createRequire(globalRoot + "/noop.js");
    return req("playwright");
  }
}

const pw = await loadPlaywright().catch((e) => {
  console.error(String(e));
  process.exit(4);
});

function extractResults() {
  // Run in the page. DuckDuckGo's markup varies by endpoint (html vs
  // lite) and shifts over time, so try the known layouts, then fall back
  // to any external result anchor. Hrefs are often redirect-wrapped
  // (uddg param carries the real target) — unwrap them.
  const clean = (s) => (s || "").replace(/\s+/g, " ").trim();
  const unwrap = (href) => {
    try {
      const u = new URL(href, location.href);
      return u.searchParams.get("uddg") || href;
    } catch {
      return href;
    }
  };
  const fromAnchors = (sel, snipSel) => {
    const anchors = [...document.querySelectorAll(sel)];
    if (!anchors.length) return null;
    const snips = snipSel
      ? [...document.querySelectorAll(snipSel)].map(clean)
      : [];
    return anchors.slice(0, 10).map((a, i) => ({
      title: clean(a.textContent),
      url: unwrap(a.href),
      snippet: snips[i] || "",
    }));
  };
  // 1. html.duckduckgo.com  2. lite.duckduckgo.com
  let out =
    fromAnchors("a.result__a", ".result__snippet") ||
    fromAnchors("a.result-link", ".result-snippet");
  if (out && out.length) return out;
  // 3. Generic fallback: external links that aren't DDG's own nav.
  const seen = new Set();
  out = [];
  for (const a of document.querySelectorAll("a[href]")) {
    const url = unwrap(a.href);
    const title = clean(a.textContent);
    if (!title || !/^https?:\/\//.test(url)) continue;
    if (/(^|\.)duckduckgo\.com/.test(url)) continue;
    if (seen.has(url)) continue;
    seen.add(url);
    out.push({ title, url, snippet: "" });
    if (out.length >= 10) break;
  }
  return out;
}

const browser = await pw.chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  const targets = [
    `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`,
    `https://lite.duckduckgo.com/lite/?q=${encodeURIComponent(query)}`,
  ];
  let results = null;
  let lastErr = "";
  for (const url of targets) {
    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
      // Give the anomaly challenge a brief chance to self-resolve, but do
      // NOT hard-fail if the expected selector never shows — extract
      // whatever the page has (the fallback handles shifted markup and
      // partially-rendered challenge pages). Short timeout so a dead
      // endpoint is cheap, not a 20s stall.
      await page
        .waitForSelector("a.result__a, a.result-link", { timeout: 6000 })
        .catch(() => {});
      results = await page.evaluate(extractResults);
      if (results && results.length > 0) break;
    } catch (e) {
      lastErr = String(e && e.message ? e.message : e);
    }
  }
  if (!results || results.length === 0) {
    console.error(`no results extracted (${lastErr || "empty page"})`);
    process.exit(3);
  }
  console.log(JSON.stringify({ query, engine: "duckduckgo-browser", results }));
} finally {
  await browser.close().catch(() => {});
}
