import { collectSqlEvidence } from "./sql-evidence";

export type Severity = "critical" | "high" | "medium" | "low";
export type Category = "transport" | "headers" | "injection" | "javascript" | "ratelimit" | "availability";
export type Finding = { id: string; category: Category; title: string; ok: boolean | null; severity: Severity; detail: string; advice: string; evidence?: string[] };

export const CATEGORY_LABELS: Record<Category, string> = {
  transport: "Transport & cookies",
  headers: "En-têtes & CORS",
  injection: "Injections & fuites (SQL, XSS)",
  javascript: "JavaScript & dépendances",
  ratelimit: "Limitation de débit & bots",
  availability: "Disponibilité & signaux réseau",
};

export type ScriptTag = { src: string; integrity: boolean; first: boolean };
export type ScanInput = {
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  html: string;
  htmlBytes: number;
  jsContents: string[];
  dns: { spf: boolean; dmarc: boolean; caa: boolean; ns: number; dnssec: boolean };
  httpToHttps: boolean | null;
  exposed: string[];
  ttfbMs: number;
  burst: { sent: number; limited: number; serverErrors: number; maxMs: number } | null;
  /** Additional passive probes; a missing field means "not tested". */
  extra?: Partial<{
    admin: string[]; docs: string[];
    notFound: { status: number; text: string } | null;
    trace: boolean | null; reflect: boolean | null; securityTxt: boolean | null; robots: string | null;
    spfRecord: string | null; dmarcRecord: string | null;
  }>;
};

const weight: Record<Severity, number> = { critical: 25, high: 15, medium: 8, low: 4 };

export function parseScripts(html: string, pageUrl: string): ScriptTag[] {
  const out: ScriptTag[] = [];
  let host = "";
  try { host = new URL(pageUrl).hostname.replace(/^www\./, ""); } catch { /* ignore */ }
  for (const m of html.matchAll(/<script\b([^>]*)>/gi)) {
    const attrs = m[1] ?? "";
    const src = /\bsrc\s*=\s*["']([^"']+)["']/i.exec(attrs)?.[1];
    if (!src) continue;
    try {
      const abs = new URL(src, pageUrl);
      const h = abs.hostname.replace(/^www\./, "");
      out.push({ src: abs.toString(), integrity: /\bintegrity\s*=/i.test(attrs), first: h === host || h.endsWith("." + host) });
    } catch { /* ignore */ }
  }
  return out;
}

const DEBUG_LEAK = /(Traceback \(most recent call last\)|at [\w.$]+\([\w$]+\.java:\d+\)|Fatal error:.{0,80} on line \d+|Stack trace:|Exception in thread|Whoops, looks like something went wrong|DEBUG = True)/i;
const SECRETS: [string, RegExp][] = [
  ["clé AWS", /AKIA[0-9A-Z]{16}/],
  ["clé Google API", /AIza[0-9A-Za-z_-]{35}/],
  ["clé Stripe secrète", /sk_live_[0-9a-zA-Z]{20,}/],
  ["clé privée", /-----BEGIN (RSA |EC )?PRIVATE KEY-----/],
  ["jeton Slack", /xox[baprs]-[0-9A-Za-z-]{20,}/],
];
const WAF_HEADERS = ["cf-ray", "x-amz-cf-id", "x-sucuri-id", "x-vercel-id", "x-azure-ref", "x-akamai-transformed", "x-iinfo", "x-fastly-request-id", "x-served-by"];

export function analyze(i: ScanInput) {
  const h = i.headers;
  const f: Finding[] = [];
  const add = (x: Finding) => f.push(x);
  const https = i.finalUrl.startsWith("https://");
  const scripts = parseScripts(i.html, i.finalUrl);
  const csp = h["content-security-policy"];

  // ---- Transport & cookies
  add({ id: "https", category: "transport", title: "Connexion HTTPS", ok: https, severity: "critical", detail: https ? "Le site est servi en HTTPS." : "Le site n'utilise pas HTTPS : trafic lisible et modifiable sur le réseau.", advice: "Activer un certificat TLS (ex. Let's Encrypt) et rediriger tout le trafic HTTP." });
  add({ id: "redirect", category: "transport", title: "Redirection HTTP → HTTPS", ok: i.httpToHttps !== false, severity: "high", detail: i.httpToHttps === null ? "Non testable." : i.httpToHttps ? "http:// redirige bien vers https://." : "http:// ne redirige pas vers HTTPS (risque d'interception).", advice: "Configurer une redirection 301 de HTTP vers HTTPS sur le serveur ou le CDN." });
  const hsts = h["strict-transport-security"];
  const maxAge = Number(/max-age=(\d+)/i.exec(hsts ?? "")?.[1] ?? 0);
  add({ id: "hsts", category: "transport", title: "HSTS (≥ 6 mois)", ok: maxAge >= 15552000, severity: "high", detail: hsts ? `max-age=${maxAge}` : "En-tête absent.", advice: "Ajouter Strict-Transport-Security: max-age=31536000; includeSubDomains." });
  const bad = i.setCookies.filter((c) => !/;\s*secure/i.test(c) || !/;\s*httponly/i.test(c));
  add({ id: "cookies", category: "transport", title: "Cookies Secure + HttpOnly", ok: i.setCookies.length === 0 ? null : bad.length === 0, severity: "medium", detail: i.setCookies.length === 0 ? "Aucun cookie déposé." : `${bad.length}/${i.setCookies.length} cookie(s) sans Secure ou HttpOnly.`, advice: "Ajouter Secure et HttpOnly aux cookies de session." });
  const noSame = i.setCookies.filter((c) => !/;\s*samesite/i.test(c));
  add({ id: "samesite", category: "transport", title: "Cookies SameSite (anti-CSRF)", ok: i.setCookies.length === 0 ? null : noSame.length === 0, severity: "medium", detail: i.setCookies.length === 0 ? "Aucun cookie déposé." : `${noSame.length} cookie(s) sans SameSite.`, advice: "Ajouter SameSite=Lax (ou Strict) à chaque cookie." });

  // ---- Headers & CORS
  const weakCsp = !!csp && /unsafe-inline|unsafe-eval|\*/.test(csp);
  add({ id: "csp", category: "headers", title: "Content-Security-Policy (anti-XSS)", ok: !!csp && !weakCsp, severity: "high", detail: !csp ? "Aucune politique CSP : une faille XSS serait pleinement exploitable." : weakCsp ? "CSP permissive (unsafe-inline / unsafe-eval / *)." : "CSP stricte présente.", advice: "Définir une CSP limitant les sources de scripts, sans unsafe-inline." });
  const xfo = !!h["x-frame-options"] || /frame-ancestors/i.test(csp ?? "");
  add({ id: "clickjacking", category: "headers", title: "Protection clickjacking", ok: xfo, severity: "medium", detail: xfo ? "X-Frame-Options ou frame-ancestors présent." : "Le site peut être intégré dans une iframe piégée.", advice: "Ajouter X-Frame-Options: DENY ou frame-ancestors 'none'." });
  add({ id: "nosniff", category: "headers", title: "X-Content-Type-Options", ok: (h["x-content-type-options"] ?? "").toLowerCase() === "nosniff", severity: "low", detail: h["x-content-type-options"] ?? "En-tête absent.", advice: "Ajouter X-Content-Type-Options: nosniff." });
  add({ id: "referrer", category: "headers", title: "Referrer-Policy", ok: !!h["referrer-policy"], severity: "low", detail: h["referrer-policy"] ?? "En-tête absent.", advice: "Ajouter Referrer-Policy: strict-origin-when-cross-origin." });
  add({ id: "permissions", category: "headers", title: "Permissions-Policy", ok: !!h["permissions-policy"], severity: "low", detail: h["permissions-policy"] ? "Présent." : "En-tête absent (caméra, micro, géoloc non restreints).", advice: "Ajouter Permissions-Policy: camera=(), microphone=(), geolocation=()." });
  const leak = [h["server"], h["x-powered-by"], h["x-aspnet-version"]].filter((v) => v && /\d/.test(v));
  add({ id: "leak", category: "headers", title: "Pas de version logicielle exposée", ok: leak.length === 0, severity: "medium", detail: leak.length ? `Versions exposées : ${leak.join(", ")}` : "Aucune version exposée.", advice: "Masquer Server / X-Powered-By avec numéros de version (facilite le ciblage de CVE)." });
  const acao = h["access-control-allow-origin"];
  const corsBad = acao === "null" || (acao === "*" && h["access-control-allow-credentials"] === "true");
  add({ id: "cors", category: "headers", title: "CORS non permissif", ok: !corsBad, severity: "high", detail: !acao ? "Pas de CORS ouvert." : corsBad ? `Configuration dangereuse : Allow-Origin ${acao} avec identifiants.` : `Allow-Origin: ${acao}`, advice: "Lister explicitement les origines autorisées ; ne jamais combiner * ou null avec les identifiants." });
  const cc = h["cache-control"] ?? "";
  add({ id: "nocache", category: "headers", title: "Pages avec cookies non mises en cache", ok: i.setCookies.length === 0 ? null : /no-store|private|no-cache/i.test(cc), severity: "medium", detail: i.setCookies.length === 0 ? "Pas de cookie." : cc || "Cache-Control absent alors que des cookies sont posés.", advice: "Ajouter Cache-Control: private, no-store sur les réponses personnalisées." });

  // ---- Injections & leaks (passive)
  const sql = collectSqlEvidence(i.html, i.finalUrl);
  add({ id: "sqlerr", category: "injection", title: "Fuite de messages d'erreur SQL", ok: sql.errors.length === 0, severity: "high", detail: sql.errors.length ? "Des signatures d'erreur SQL sont visibles. Cela indique une fuite technique, pas une injection SQL confirmée." : "Aucune signature dans le texte analysé ; cela ne teste pas les injections SQL. Exemples de code et scripts exclus.", evidence: sql.errors.map((e) => `${e.engine} · ${e.signature}`), advice: "Masquer les erreurs en production et contrôler les journaux serveur ; utiliser des requêtes paramétrées." });
  add({ id: "sql-inputs", category: "injection", title: "Entrées à auditer côté SQL", ok: null, severity: "high", detail: `${sql.inputs.length} point(s) d'entrée repéré(s) sur cette page (30 maximum). Les paramètres ne prouvent pas l'utilisation d'une base SQL. Aucune valeur n'est envoyée ou reproduite ici.`, evidence: sql.inputs, advice: "Vérifier côté application que ces entrées passent par des requêtes paramétrées. Les API dynamiques et pages authentifiées ne sont pas couvertes." });
  add({ id: "sqli", category: "injection", title: "Injection SQL exploitable", ok: null, severity: "critical", detail: "Non vérifiée : aucun test SQL actif, booléen ou temporel n'a été effectué. Une page sans erreur SQL peut rester vulnérable.", advice: "Faire un audit autorisé sur une copie de test avec Burp Suite ou OWASP ZAP, puis vérifier le code et les requêtes SQL." });
  const dbg = DEBUG_LEAK.exec(i.html)?.[0];
  add({ id: "debug", category: "injection", title: "Pas de trace d'erreur / mode debug", ok: !dbg, severity: "high", detail: dbg ? `Trace technique exposée : « ${dbg.slice(0, 60)} »` : "Aucune trace technique visible.", advice: "Désactiver le mode debug et afficher une page d'erreur générique." });
  const forms = [...i.html.matchAll(/<form\b[^>]*>[\s\S]*?<\/form>/gi)].map((m) => m[0]);
  const postForms = forms.filter((x) => /method\s*=\s*["']?post/i.test(x));
  const noCsrf = postForms.filter((x) => !/name\s*=\s*["'][^"']*(csrf|xsrf|token|nonce|authenticity)[^"']*["']/i.test(x));
  add({ id: "csrf", category: "injection", title: "Formulaires POST protégés par un jeton CSRF", ok: postForms.length === 0 ? null : noCsrf.length === 0, severity: "medium", detail: postForms.length === 0 ? "Aucun formulaire POST sur la page." : `${noCsrf.length}/${postForms.length} formulaire(s) sans jeton CSRF visible.`, advice: "Ajouter un jeton anti-CSRF par session dans chaque formulaire qui modifie des données." });
  const insecureForm = forms.filter((x) => /action\s*=\s*["']http:\/\//i.test(x));
  add({ id: "formhttp", category: "injection", title: "Formulaires envoyés en HTTPS", ok: forms.length === 0 ? null : insecureForm.length === 0, severity: "high", detail: insecureForm.length ? `${insecureForm.length} formulaire(s) envoient vers http://.` : "Aucun formulaire non chiffré.", advice: "Faire pointer tous les formulaires (surtout mots de passe) vers des URLs HTTPS." });
  add({ id: "exposed", category: "injection", title: "Fichiers sensibles inaccessibles (.git, .env…)", ok: i.exposed.length === 0, severity: "critical", detail: i.exposed.length ? `Accessibles publiquement : ${i.exposed.join(", ")}` : "Aucun fichier sensible exposé parmi ceux testés.", advice: "Bloquer l'accès à ces chemins sur le serveur et changer tous les secrets exposés." });
  add({ id: "dirlist", category: "injection", title: "Pas de listing de répertoire", ok: !/<title>\s*Index of \//i.test(i.html), severity: "medium", detail: "Recherche d'une page « Index of / ».", advice: "Désactiver l'autoindex du serveur web." });

  // ---- JavaScript
  const third = scripts.filter((s) => !s.first);
  const noSri = third.filter((s) => !s.integrity);
  add({ id: "sri", category: "javascript", title: "Scripts tiers avec SRI", ok: third.length === 0 ? null : noSri.length === 0, severity: "medium", detail: third.length === 0 ? "Aucun script tiers." : `${noSri.length}/${third.length} script(s) tiers sans attribut integrity (compromission de CDN possible).`, advice: "Ajouter integrity=\"sha384-…\" et crossorigin sur les scripts chargés depuis un CDN." });
  const mixed = https && /<(script|link)\b[^>]*(src|href)\s*=\s*["']http:\/\//i.test(i.html);
  add({ id: "mixed", category: "javascript", title: "Pas de contenu mixte (scripts HTTP)", ok: !mixed, severity: "high", detail: mixed ? "Un script ou style est chargé en HTTP sur une page HTTPS." : "Aucune ressource active en HTTP.", advice: "Charger toutes les ressources en HTTPS." });
  const js = [i.html, ...i.jsContents].join("\n");
  const secrets = SECRETS.filter(([, r]) => r.test(js)).map(([n]) => n);
  add({ id: "secrets", category: "javascript", title: "Aucun secret dans le JavaScript", ok: secrets.length === 0, severity: "critical", detail: secrets.length ? `Secrets détectés dans le code public : ${secrets.join(", ")}` : "Aucun motif de clé secrète trouvé.", advice: "Révoquer ces clés et déplacer les appels sensibles côté serveur." });
  const dangerous = (js.match(/\beval\s*\(|document\.write\s*\(|new Function\s*\(/g) ?? []).length;
  add({ id: "evaljs", category: "javascript", title: "Usage limité de eval / document.write", ok: dangerous < 3, severity: "low", detail: `${dangerous} occurrence(s) dans le JS analysé.`, advice: "Remplacer eval/document.write par des API sûres (textContent, createElement)." });
  const srcs = scripts.map((s) => s.src).join(" ");
  const old: string[] = [];
  const jq = /jquery[-.@/]v?(\d+)\.(\d+)\.(\d+)/i.exec(srcs);
  if (jq && (Number(jq[1]) < 3 || (Number(jq[1]) === 3 && Number(jq[2]) < 5))) old.push(`jQuery ${jq[1]}.${jq[2]}.${jq[3]} (XSS connues)`);
  if (/angular(js)?[/@-]1\.\d/i.test(srcs)) old.push("AngularJS 1.x (fin de support)");
  const bs = /bootstrap[-/@.]v?([0-3])\.\d/i.exec(srcs);
  if (bs) old.push(`Bootstrap ${bs[1]}.x (obsolète)`);
  add({ id: "oldlibs", category: "javascript", title: "Bibliothèques JS à jour", ok: old.length === 0, severity: "high", detail: old.length ? old.join(" ; ") : "Aucune bibliothèque obsolète repérée dans les URLs.", advice: "Mettre à jour les bibliothèques et lancer un audit de dépendances (npm audit)." });
  add({ id: "sourcemap", category: "javascript", title: "Pas de source maps publiques", ok: !i.jsContents.some((c) => /sourceMappingURL=\S+\.map/.test(c)), severity: "low", detail: "Les source maps révèlent le code source d'origine.", advice: "Ne pas publier les fichiers .map en production." });

  // ---- Rate limit & bots
  const rlHeader = Object.keys(h).some((k) => /^(x-)?ratelimit|^x-rate-limit|^retry-after/.test(k));
  const limited = (i.burst?.limited ?? 0) > 0 || i.status === 429;
  add({ id: "ratelimit", category: "ratelimit", title: "Signal de limitation de débit", ok: limited ? true : null, severity: "medium", detail: limited ? "Une réponse 429 a été observée sur cette URL. Le seuil et les autres pages ne sont pas vérifiés." : rlHeader ? "Des en-têtes annoncent une limite, mais son application n'est pas vérifiée." : "Aucun 429 ni en-tête explicite ; cela ne prouve pas l'absence de limite.", evidence: Object.entries(h).filter(([k]) => /^(x-)?ratelimit|^x-rate-limit|^retry-after/.test(k)).map(([k, v]) => `${k}: ${v}`), advice: "Vérifier séparément login et API : seuil, fenêtre, portée IP/compte et Retry-After, sur un environnement autorisé." });
  const waf = WAF_HEADERS.filter((k) => h[k]);
  const serverWaf = /cloudflare|akamai|cloudfront|sucuri|imperva|fastly|netlify|vercel/i.test(h["server"] ?? "") || /cloudfront|varnish/i.test(h["via"] ?? "");
  const hasWaf = waf.length > 0 || serverWaf;
  add({ id: "waf", category: "ratelimit", title: "Présence d'un intermédiaire CDN", ok: null, severity: "high", detail: hasWaf ? "Des signatures d'un intermédiaire CDN sont visibles. Ni l'activation d'un WAF ni sa configuration ne sont prouvées." : "Aucune signature CDN reconnue ; impossible d'en déduire que l'origine est exposée.", evidence: waf.map((k) => k), advice: "Vérifier les règles WAF dans la console du fournisseur et restreindre l'accès direct à l'origine." });
  const botSig = i.setCookies.some((c) => /__cf_bm|datadome|_px|incap_ses|reese84|bm_sz|ak_bmsc/i.test(c)) || !!h["cf-mitigated"] || /turnstile|recaptcha|hcaptcha|datadome|perimeterx|kasada/i.test(i.html);
  add({ id: "bots", category: "ratelimit", title: "Indices anti-bots", ok: null, severity: "medium", detail: botSig ? "Un CAPTCHA ou marqueur anti-bot est visible ; son efficacité et sa validation côté serveur ne sont pas vérifiées." : "Aucun marqueur reconnu sur cette page ; une protection invisible peut exister.", advice: "Contrôler la validation côté serveur et les règles anti-abus des endpoints sensibles." });

  // ---- Availability & DDoS
  add({ id: "status", category: "availability", title: "Site répond sans erreur serveur", ok: i.status < 500, severity: "high", detail: `Code HTTP ${i.status}.`, advice: "Corriger l'erreur serveur et surveiller la disponibilité." });
  add({ id: "ttfb", category: "availability", title: "Réponse initiale < 1,5 s", ok: i.ttfbMs < 1500, severity: "medium", detail: `${i.ttfbMs} ms jusqu'aux en-têtes, depuis le point de mesure du scanner (redirections incluses). Ce n'est pas une mesure du réseau des visiteurs.`, advice: "Comparer plusieurs mesures depuis plusieurs régions ; isoler DNS, connexion, TLS et traitement serveur avec un outil de performance." });
  const cacheHit = /\bHIT\b/i.test(`${h["cf-cache-status"] ?? ""} ${h["x-cache"] ?? ""}`) || Number(h["age"] ?? 0) > 0;
  add({ id: "cache", category: "availability", title: "Réponse effectivement servie depuis un cache", ok: cacheHit ? true : null, severity: "medium", detail: cacheHit ? "HIT ou Age positif observé sur cette réponse uniquement." : "Pas de HIT confirmé. MISS, DYNAMIC et BYPASS ne prouvent pas une mise en cache ; l'absence de cache peut être volontaire.", evidence: ["cache-control", "age", "cf-cache-status", "x-cache"].filter((k) => h[k]).map((k) => `${k}: ${h[k]}`), advice: "Contrôler le cache des ressources publiques sans jamais mettre les réponses privées en cache partagé." });
  add({ id: "gzip", category: "availability", title: "Compression des réponses", ok: /gzip|br|zstd|deflate/i.test(h["content-encoding"] ?? ""), severity: "low", detail: h["content-encoding"] ?? "Pas de compression.", advice: "Activer Brotli/gzip pour réduire la bande passante." });
  add({ id: "weight", category: "availability", title: "Page HTML légère", ok: i.htmlBytes < 300000, severity: "low", detail: `${Math.round(i.htmlBytes / 1024)} Ko de HTML.`, advice: "Réduire le HTML initial (pagination, chargement différé)." });
  const hosts = new Set(third.map((s) => { try { return new URL(s.src).hostname; } catch { return s.src; } }));
  add({ id: "spof", category: "availability", title: "Peu de dépendances tierces critiques", ok: hosts.size <= 8, severity: "medium", detail: `${hosts.size} domaine(s) tiers de scripts : chacun peut tomber et casser la page.`, advice: "Réduire les scripts tiers, les charger en async et prévoir un repli." });
  const b = i.burst;
  add({ id: "burst", category: "availability", title: "Échantillon de requêtes simultanées", ok: !b || b.sent === 0 ? null : b.serverErrors > 0 || b.maxMs >= 5000 ? false : null, severity: "medium", detail: b ? `${b.sent} requêtes · ${b.limited} réponse(s) 429 · ${b.serverErrors} échec(s) serveur/réseau, délais dépassés inclus · maximum ${b.maxMs} ms. Petit échantillon ponctuel : aucune capacité de charge déduite.` : "Aucun échantillon disponible.", evidence: b && b.sent > 0 ? [`Échecs : ${Math.round(b.serverErrors / b.sent * 100)} % de cet échantillon`, "Mesures jusqu'aux en-têtes, corps non téléchargés."] : [], advice: "Reproduire les erreurs avec les journaux serveur. Pour mesurer la capacité, utiliser une préproduction et un test de charge plafonné et autorisé." });
  add({ id: "ddos", category: "availability", title: "Résistance DDoS et saturation réseau", ok: null, severity: "critical", detail: "Non mesurée : pas de trafic volumétrique, de test L3/L4, de mesure de bande passante ou de saturation des connexions. Aucun seuil de panne ne peut être annoncé.", advice: "Vérifier la protection chez l'hébergeur, les limites d'origine et le plan d'incident ; faire valider un test encadré par le fournisseur." });
  add({ id: "ns", category: "availability", title: "DNS redondant (≥ 2 serveurs de noms)", ok: i.dns.ns === 0 ? null : i.dns.ns >= 2, severity: "medium", detail: i.dns.ns ? `${i.dns.ns} serveur(s) de noms retourné(s) ; leur disponibilité indépendante n'est pas mesurée.` : "Aucune réponse exploitable : absence, délégation ou échec de résolution non distingués.", advice: "Vérifier la délégation du domaine et la redondance chez le fournisseur DNS." });
  add({ id: "dnssec", category: "availability", title: "DNSSEC", ok: i.dns.dnssec ? true : null, severity: "low", detail: i.dns.dnssec ? "Réponses DNS authentifiées." : "Authentification non observée : absence de signature et erreur de résolution non distinguées.", advice: "Vérifier la chaîne DNSSEC chez le registrar et le fournisseur DNS." });
  add({ id: "spf", category: "availability", title: "SPF (anti-usurpation e-mail)", ok: i.dns.spf ? true : null, severity: "medium", detail: i.dns.spf ? "SPF trouvé ; validité de la politique non auditée." : "SPF non observé ; réponse négative et échec DNS non distingués.", advice: "Vérifier le TXT SPF sur le domaine d'envoi réel, qui peut différer du site." });
  add({ id: "dmarc", category: "availability", title: "DMARC", ok: i.dns.dmarc ? true : null, severity: "medium", detail: i.dns.dmarc ? "DMARC trouvé ; niveau d'application non audité." : "DMARC non observé ; héritage de politique et échec DNS non distingués.", advice: "Vérifier la politique DMARC du domaine d'envoi et son héritage." });
  add({ id: "caa", category: "availability", title: "CAA (autorités de certification)", ok: i.dns.caa ? true : null, severity: "low", detail: i.dns.caa ? "CAA trouvé ; politique non auditée." : "CAA non observé ; héritage et échec DNS non distingués.", advice: "Vérifier les règles CAA applicables et les autorités autorisées." });

  // ---- Extra passive checks
  const x = i.extra ?? {};
  const ext = (v: unknown) => v === undefined ? null : v;
  add({ id: "admin", category: "injection", title: "Consoles d'administration non publiques", ok: x.admin === undefined ? null : x.admin.length === 0, severity: "high", detail: x.admin?.length ? `Accessibles : ${x.admin.join(", ")} (Spring Actuator, H2, phpMyAdmin, Adminer, Tomcat…)` : x.admin ? "Aucune console connue accessible parmi celles testées." : "Non testé.", evidence: x.admin ?? [], advice: "Restreindre ces interfaces par IP/VPN ou les désactiver en production." });
  add({ id: "apidocs", category: "injection", title: "Documentation d'API non exposée", ok: x.docs === undefined ? null : x.docs.length === 0, severity: "low", detail: x.docs?.length ? `Publique : ${x.docs.join(", ")}. Elle donne la carte de toutes les routes à un attaquant.` : x.docs ? "Aucune documentation Swagger/OpenAPI trouvée aux chemins usuels." : "Non testé.", advice: "Protéger Swagger/OpenAPI par authentification en production." });
  const nf = x.notFound;
  const nfLeak = nf ? (DEBUG_LEAK.exec(nf.text)?.[0] ?? /Whitelabel Error Page|Apache Tomcat\/\d|nginx\/\d|Apache\/\d|Werkzeug|Django Version|Laravel|at org\.springframework/i.exec(nf.text)?.[0]) : undefined;
  add({ id: "errorpage", category: "injection", title: "Page d'erreur sans détails techniques", ok: nf ? !nfLeak : null, severity: "high", detail: !nf ? "Non testé." : nfLeak ? `La page 404 révèle : « ${nfLeak.slice(0, 60)} »` : `Page introuvable (code ${nf.status}) sans trace ni version visible.`, advice: "Configurer une page d'erreur générique (Spring : server.error.whitelabel.enabled=false, Tomcat : ErrorReportValve)." });
  add({ id: "soft404", category: "injection", title: "Code 404 pour les pages inexistantes", ok: nf ? nf.status === 404 || nf.status === 410 : null, severity: "low", detail: nf ? `Une page inexistante renvoie ${nf.status}.` : "Non testé.", advice: "Renvoyer un vrai 404 : sinon les scanners et robots ne distinguent plus le contenu réel." });
  add({ id: "trace", category: "headers", title: "Méthode TRACE désactivée", ok: ext(x.trace) === null ? null : !x.trace, severity: "medium", detail: x.trace ? "TRACE renvoie la requête (Cross-Site Tracing)." : x.trace === false ? "TRACE ne renvoie pas la requête." : "Non testé.", advice: "Désactiver TRACE (Apache : TraceEnable off)." });
  add({ id: "reflect", category: "injection", title: "Paramètres d'URL échappés (XSS réfléchi)", ok: ext(x.reflect) === null ? null : !x.reflect, severity: "high", detail: x.reflect ? "Un marqueur inoffensif contenant \" et < a été recopié tel quel dans la page : forte suspicion de XSS réfléchi." : x.reflect === false ? "Le marqueur inoffensif n'est pas recopié sans échappement sur cette URL. Les autres paramètres ne sont pas couverts." : "Non testé.", advice: "Échapper toute donnée utilisateur à l'affichage et ajouter une CSP stricte." });
  add({ id: "securitytxt", category: "headers", title: "Fichier security.txt", ok: ext(x.securityTxt) === null ? null : !!x.securityTxt, severity: "low", detail: x.securityTxt ? "Contact de sécurité publié." : x.securityTxt === false ? "Aucun /.well-known/security.txt : personne ne sait où signaler une faille." : "Non testé.", advice: "Publier /.well-known/security.txt avec Contact: et Expires:." });
  const robotsHits = (x.robots ?? "").split("\n").filter((l) => /^disallow:/i.test(l) && /admin|backup|private|secret|config|db|sql|internal|staging/i.test(l)).map((l) => l.trim());
  add({ id: "robots", category: "injection", title: "robots.txt sans chemins sensibles", ok: x.robots === undefined ? null : robotsHits.length === 0, severity: "low", detail: robotsHits.length ? "robots.txt indique des zones sensibles (ce fichier est public)." : x.robots === null ? "Pas de robots.txt." : x.robots === undefined ? "Non testé." : "Rien de sensible annoncé.", evidence: robotsHits.slice(0, 10), advice: "Ne pas lister les zones privées dans robots.txt : les protéger par authentification." });
  const passForms = forms.filter((fm) => /type\s*=\s*["']?password/i.test(fm));
  add({ id: "pwdhttp", category: "transport", title: "Mot de passe uniquement en HTTPS", ok: passForms.length === 0 ? null : https, severity: "critical", detail: passForms.length === 0 ? "Aucun champ mot de passe sur la page." : https ? "Champ mot de passe sur une page HTTPS." : "Champ mot de passe sur une page HTTP : identifiants lisibles sur le réseau.", advice: "Servir toutes les pages de connexion en HTTPS." });
  add({ id: "jsessionurl", category: "transport", title: "Identifiant de session hors de l'URL", ok: !/;jsessionid=|[?&](phpsessid|sid|sessionid)=/i.test(i.html), severity: "medium", detail: "Recherche de ;jsessionid= ou PHPSESSID dans les liens (session volable via le Referer ou l'historique).", advice: "Java : tracking-mode COOKIE dans web.xml ; ne jamais mettre la session dans l'URL." });
  add({ id: "hstsfull", category: "transport", title: "HSTS avec includeSubDomains", ok: !hsts ? false : /includesubdomains/i.test(hsts), severity: "low", detail: hsts ?? "En-tête absent.", advice: "Ajouter includeSubDomains (et preload si possible)." });
  const coop = !!h["cross-origin-opener-policy"];
  add({ id: "coop", category: "headers", title: "Cross-Origin-Opener-Policy", ok: coop, severity: "low", detail: h["cross-origin-opener-policy"] ?? "En-tête absent (isolation des fenêtres non activée).", advice: "Ajouter Cross-Origin-Opener-Policy: same-origin." });
  const blank = [...i.html.matchAll(/<a\b[^>]*target\s*=\s*["']?_blank[^>]*>/gi)].map((m) => m[0]).filter((t) => /href\s*=\s*["']https?:/i.test(t) && !/noopener|noreferrer/i.test(t));
  add({ id: "noopener", category: "javascript", title: "Liens externes avec rel=noopener", ok: blank.length === 0, severity: "low", detail: `${blank.length} lien(s) target=_blank sans noopener (anciens navigateurs : tabnabbing).`, advice: "Ajouter rel=\"noopener noreferrer\" aux liens target=_blank." });
  const inlineHandlers = (i.html.match(/\son(click|load|error|mouseover|submit|change)\s*=/gi) ?? []).length;
  add({ id: "inlinejs", category: "javascript", title: "Peu de gestionnaires JS en ligne (onclick=…)", ok: inlineHandlers <= 5, severity: "low", detail: `${inlineHandlers} attribut(s) on…= : ils empêchent une CSP stricte.`, advice: "Déplacer les gestionnaires dans des fichiers JS (addEventListener)." });
  const comments = [...i.html.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1] ?? "").filter((c) => /password|passwd|mot de passe|todo|fixme|api[_-]?key|secret|token|admin/i.test(c));
  add({ id: "comments", category: "javascript", title: "Commentaires HTML sans info sensible", ok: comments.length === 0, severity: "low", detail: comments.length ? `${comments.length} commentaire(s) suspect(s) dans le code source public.` : "Aucun commentaire suspect.", evidence: comments.slice(0, 5).map((c) => c.trim().slice(0, 80)), advice: "Retirer les commentaires de développement avant la mise en ligne." });
  const autoPwd = passForms.filter((fm) => !/autocomplete\s*=\s*["']?(new-password|current-password|off)/i.test(fm));
  add({ id: "autocomplete", category: "transport", title: "Champs mot de passe avec autocomplete", ok: passForms.length === 0 ? null : autoPwd.length === 0, severity: "low", detail: passForms.length === 0 ? "Aucun champ mot de passe." : `${autoPwd.length} formulaire(s) sans autocomplete explicite.`, advice: "Utiliser autocomplete=\"current-password\" ou \"new-password\"." });
  const spf = x.spfRecord;
  add({ id: "spfstrict", category: "availability", title: "SPF strict (pas de +all / ?all)", ok: spf ? !/[+?]all\b/i.test(spf) : null, severity: "medium", detail: spf ?? "SPF non lu.", advice: "Terminer le SPF par -all ou ~all." });
  const dm = x.dmarcRecord;
  add({ id: "dmarcpolicy", category: "availability", title: "DMARC appliqué (quarantine/reject)", ok: dm ? /p=(quarantine|reject)/i.test(dm) : null, severity: "medium", detail: dm ?? "DMARC non lu.", advice: "Passer progressivement de p=none à p=quarantine puis p=reject." });

  // A denial/error page is not evidence about the application's actual HTML.
  if (i.status < 200 || i.status >= 300) {
    const pageChecks = new Set(["sqlerr", "sql-inputs", "debug", "csrf", "formhttp", "dirlist", "sri", "mixed", "secrets", "evaljs", "oldlibs", "sourcemap", "spof", "reflect", "pwdhttp", "jsessionurl", "noopener", "inlinejs", "comments", "autocomplete"]);
    for (const finding of f) {
      if (!pageChecks.has(finding.id)) continue;
      finding.ok = null;
      finding.detail = `Réponse HTTP ${i.status} : le contenu de la page cible n'est pas vérifié.`;
      finding.evidence = [];
    }
  }

  const pct = (xs: Finding[]) => {
    const checked = xs.filter((x) => x.ok !== null);
    const total = checked.reduce((s, x) => s + weight[x.severity], 0);
    const lost = checked.filter((x) => x.ok === false).reduce((s, x) => s + weight[x.severity], 0);
    return total === 0 ? null : Math.round(((total - lost) / total) * 100);
  };
  // Caps: a serious failure cannot be compensated by many easy passes.
  const capped = (xs: Finding[]) => {
    const raw = pct(xs);
    if (raw === null) return null;
    const failed = xs.filter((x) => x.ok === false);
    let cap = 100;
    if (failed.filter((x) => x.category === "headers").length >= 3) cap = Math.min(cap, 69);
    if (failed.some((x) => x.severity === "high")) cap = Math.min(cap, 79);
    if (failed.filter((x) => x.severity === "high").length >= 2) cap = Math.min(cap, 64);
    if (failed.some((x) => x.severity === "critical")) cap = Math.min(cap, 39);
    return Math.min(raw, cap);
  };
  const score = capped(f) ?? 0;
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  const categories = (Object.keys(CATEGORY_LABELS) as Category[]).map((id) => ({ id, label: CATEGORY_LABELS[id], score: capped(f.filter((x) => x.category === id)) }));
  return { score, grade, findings: f, categories };
}
