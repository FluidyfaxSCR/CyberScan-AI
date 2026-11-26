import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analyze, parseScripts } from "./rules";

async function dnsQuery(name: string, type: string): Promise<{ data: string[]; ad: boolean }> {
  try {
    const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, { signal: AbortSignal.timeout(6000) });
    if (!r.ok) return { data: [], ad: false };
    const j = (await r.json()) as { AD?: boolean; Answer?: { data: string }[] };
    return { data: (j.Answer ?? []).map((a) => a.data), ad: !!j.AD };
  } catch { return { data: [], ad: false }; }
}

function blockedHost(host: string) {
  return /^(localhost|0\.|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) || /\.(local|internal|localhost)$/.test(host) || host.startsWith("[") || !host.includes(".");
}

async function readText(res: Response, max: number) {
  if (!res.body) return { text: "", bytes: 0 };
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let text = "", bytes = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.length;
    text += dec.decode(value, { stream: true });
    if (bytes >= max) { await reader.cancel(); break; }
  }
  return { text, bytes };
}

const UA = { "user-agent": "CyberScanAI/2.0 (passive security check)" };
type Kind = "secret" | "admin" | "docs";
const PROBES: { path: string; kind: Kind; test: (t: string, ct: string) => boolean }[] = [
  { path: "/.git/HEAD", kind: "secret", test: (t) => t.trim().startsWith("ref:") },
  { path: "/.git/config", kind: "secret", test: (t) => t.includes("[core]") },
  { path: "/.env", kind: "secret", test: (t, ct) => !ct.includes("html") && /^[A-Z][A-Z0-9_]*=/m.test(t) },
  { path: "/.env.local", kind: "secret", test: (t, ct) => !ct.includes("html") && /^[A-Z][A-Z0-9_]*=/m.test(t) },
  { path: "/.DS_Store", kind: "secret", test: (t) => t.includes("Bud1") },
  { path: "/.htpasswd", kind: "secret", test: (t, ct) => !ct.includes("html") && /^[\w.-]+:\S{6,}/m.test(t) },
  { path: "/.aws/credentials", kind: "secret", test: (t) => /aws_access_key_id/i.test(t) },
  { path: "/docker-compose.yml", kind: "secret", test: (t, ct) => !ct.includes("html") && /^services:/m.test(t) },
  { path: "/wp-config.php.bak", kind: "secret", test: (t) => t.includes("DB_PASSWORD") },
  { path: "/phpinfo.php", kind: "secret", test: (t) => t.includes("PHP Version") },
  { path: "/server-status", kind: "secret", test: (t) => t.includes("Apache Server Status") },
  { path: "/backup.sql", kind: "secret", test: (t, ct) => !ct.includes("html") && /(CREATE TABLE|INSERT INTO)/i.test(t) },
  { path: "/dump.sql", kind: "secret", test: (t, ct) => !ct.includes("html") && /(CREATE TABLE|INSERT INTO)/i.test(t) },
  { path: "/WEB-INF/web.xml", kind: "secret", test: (t) => t.includes("<web-app") },
  { path: "/actuator/env", kind: "secret", test: (t) => /propertySources|activeProfiles/.test(t) },
  { path: "/actuator/heapdump", kind: "secret", test: (t, ct) => ct.includes("octet-stream") || t.startsWith("JAVA PROFILE") },
  { path: "/actuator", kind: "admin", test: (t) => t.includes("_links") },
  { path: "/h2-console/", kind: "admin", test: (t) => /H2 Console/i.test(t) },
  { path: "/phpmyadmin/", kind: "admin", test: (t) => /phpMyAdmin/i.test(t) },
  { path: "/adminer.php", kind: "admin", test: (t) => /Adminer/i.test(t) },
  { path: "/manager/html", kind: "admin", test: (t) => /Tomcat/i.test(t) },
  { path: "/swagger-ui.html", kind: "docs", test: (t) => /swagger/i.test(t) },
  { path: "/v3/api-docs", kind: "docs", test: (t) => /"openapi"/.test(t) },
  { path: "/v2/api-docs", kind: "docs", test: (t) => /"swagger"/.test(t) },
];

export const scanSite = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => z.object({ url: z.string().min(3).max(300) }).parse(d))
  .handler(async ({ data }) => {
    let raw = data.url.trim();
    if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;
    let u: URL;
    try { u = new URL(raw); } catch { throw new Error("Adresse invalide."); }
    if (blockedHost(u.hostname)) throw new Error("Adresse non autorisée.");

    const t0 = Date.now();
    const res = await fetch(u.toString(), { redirect: "follow", headers: UA, signal: AbortSignal.timeout(12000) });
    const ttfbMs = Date.now() - t0;
    const finalUrl = res.url || u.toString();
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => (headers[k] = v));
    const setCookies = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
    const { text: html, bytes: htmlBytes } = await readText(res, 500000);
    const origin = new URL(finalUrl);
    const domain = origin.hostname.replace(/^www\./, "");

    const firstJs = parseScripts(html, finalUrl).filter((s) => s.first).slice(0, 4);
    const inline = [...html.matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1] ?? "").join("\n");

    const get = (path: string, init: RequestInit = {}) => fetch(`${origin.origin}${path}`, { redirect: "manual", headers: UA, signal: AbortSignal.timeout(6000), ...init });
    const [txt, dmarc, caa, ns, a, httpRes, jsContents, probed, burst, notFound, trace, reflect, securityTxt, robots] = await Promise.all([
      dnsQuery(domain, "TXT"), dnsQuery(`_dmarc.${domain}`, "TXT"), dnsQuery(domain, "CAA"), dnsQuery(domain, "NS"), dnsQuery(domain, "A"),
      fetch(`http://${origin.host}/`, { redirect: "manual", headers: UA, signal: AbortSignal.timeout(8000) })
        .then((r) => { r.body?.cancel(); const loc = r.headers.get("location") ?? ""; return r.status >= 300 && r.status < 400 ? loc.startsWith("https://") : false; })
        .catch(() => null),
      Promise.all(firstJs.map((s) => fetch(s.src, { headers: UA, signal: AbortSignal.timeout(8000) }).then((r) => readText(r, 300000)).then((x) => x.text).catch(() => ""))),
      Promise.all(PROBES.map((p) => get(p.path)
        .then(async (r) => (r.status === 200 && p.test((await readText(r, 20000)).text, r.headers.get("content-type") ?? "") ? p : null))
        .catch(() => null))).then((r) => r.filter((x): x is (typeof PROBES)[number] => !!x)),
      Promise.all(Array.from({ length: 6 }, async () => {
        const s = Date.now();
        try { const r = await fetch(finalUrl, { headers: UA, signal: AbortSignal.timeout(8000) }); r.body?.cancel(); return { code: r.status, ms: Date.now() - s }; }
        catch { return { code: 599, ms: Date.now() - s }; }
      })).then((rs) => ({ sent: rs.length, limited: rs.filter((r) => r.code === 429).length, serverErrors: rs.filter((r) => r.code >= 500).length, maxMs: Math.max(...rs.map((r) => r.ms)) })),
      get(`/cyberscan-${Date.now()}-introuvable`).then(async (r) => ({ status: r.status, text: (await readText(r, 100000)).text })).catch(() => null),
      get("/", { method: "TRACE" }).then(async (r) => r.status === 200 && /^TRACE \//.test((await readText(r, 5000)).text)).catch(() => null),
      fetch(`${finalUrl}${finalUrl.includes("?") ? "&" : "?"}cs_probe=cs7q%22%3Cb%3Ecs7q`, { headers: UA, signal: AbortSignal.timeout(8000) })
        .then(async (r) => (r.status >= 200 && r.status < 300 ? (await readText(r, 500000)).text.includes('cs7q"<b>cs7q') : null)).catch(() => null),
      get("/.well-known/security.txt").then(async (r) => r.status === 200 && /contact:/i.test((await readText(r, 20000)).text)).catch(() => null),
      get("/robots.txt").then(async (r) => (r.status === 200 ? (await readText(r, 50000)).text : null)).catch(() => null),
    ]);

    const result = analyze({
      finalUrl, status: res.status, headers, setCookies, html, htmlBytes,
      jsContents: [inline, ...jsContents],
      dns: { spf: txt.data.some((t) => t.includes("v=spf1")), dmarc: dmarc.data.some((t) => t.includes("v=DMARC1")), caa: caa.data.length > 0, ns: ns.data.length, dnssec: a.ad },
      httpToHttps: httpRes, exposed: probed.filter((p) => p.kind === "secret").map((p) => p.path), ttfbMs, burst,
      extra: {
        admin: probed.filter((p) => p.kind === "admin").map((p) => p.path), docs: probed.filter((p) => p.kind === "docs").map((p) => p.path),
        notFound, trace, reflect, securityTxt, robots,
        spfRecord: txt.data.find((t) => t.includes("v=spf1")) ?? null, dmarcRecord: dmarc.data.find((t) => t.includes("v=DMARC1")) ?? null,
      },
    });
    return { url: finalUrl, status: res.status, ttfbMs, ...result };
  });
