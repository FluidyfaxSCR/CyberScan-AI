// Evidence collection only: an error message is not proof of SQL injection.
const signatures: [string, RegExp][] = [
  ["MySQL / MariaDB", /you have an error in your sql syntax|warning:\s*mysqli?_|mysqli?_sql_exception|SQLSTATE\[42000\].{0,100}1064/i],
  ["PostgreSQL", /pg_query\(\)|PostgreSQL.{0,40}ERROR|syntax error at or near|psycopg\w*\.(?:errors|ProgrammingError)/i],
  ["SQL Server", /unclosed quotation mark after the character string|microsoft ole db provider|odbc sql server driver|System\.Data\.SqlClient\.SqlException/i],
  ["Oracle", /ORA-\d{5}/i],
  ["SQLite", /SQLITE_ERROR|sqlite3?::|sqlite3\.(?:OperationalError|DatabaseError)|SQLiteException/i],
  ["JDBC / Java", /java\.sql\.(?:SQL\w*Exception|SQLException)|org\.hibernate\.exception\.SQLGrammarException/i],
  ["SQL (moteur non identifié)", /SQLSTATE\[[0-9A-Z]{5}\]/i],
];

function attr(tag: string, name: string) {
  const m = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i").exec(tag);
  return m?.[1] ?? m?.[2] ?? m?.[3] ?? "";
}

export function collectSqlEvidence(html: string, pageUrl: string) {
  const visible = html.replace(/<!--[\s\S]*?-->|<(script|style|code)\b[^>]*>[\s\S]*?<\/\1>/gi, " ")
    .replace(/<[^>]*>/g, " ").replace(/&(?:quot|apos|#39|#34);/g, "'").replace(/\s+/g, " ");
  const errors = signatures.flatMap(([engine, pattern]) => {
    const match = pattern.exec(visible);
    return match ? [{ engine, signature: match[0].slice(0, 120) }] : [];
  });
  const inputs = new Set<string>();
  const base = new URL(pageUrl);
  const record = (raw: string, method: string, names: string[] = []) => {
    try {
      const url = new URL(raw.replace(/&amp;/g, "&"), base);
      if (url.origin !== base.origin) return;
      const fields = [...new Set([...url.searchParams.keys(), ...names])].filter(Boolean).slice(0, 20);
      // Never include parameter values, passwords or tokens in the report.
      if (fields.length && inputs.size < 30) inputs.add(`${method} ${url.pathname.slice(0, 150)} · ${fields.map((n) => n.slice(0, 60)).join(", ")}`);
    } catch { /* malformed or non-HTTP URL */ }
  };
  record(pageUrl, "GET");
  for (const tag of html.matchAll(/<a\b[^>]*>/gi)) record(attr(tag[0], "href"), "GET");
  for (const form of html.matchAll(/<form\b[^>]*>[\s\S]*?<\/form>/gi)) {
    const tag = /^<form\b[^>]*>/i.exec(form[0])?.[0] ?? "";
    const names = [...form[0].matchAll(/<(?:input|select|textarea)\b[^>]*>/gi)]
      .filter((m) => !/^(?:password|hidden|submit|button|file)$/i.test(attr(m[0], "type")))
      .map((m) => attr(m[0], "name"));
    record(attr(tag, "action") || pageUrl, (attr(tag, "method") || "GET").toUpperCase(), names);
  }
  return { errors, inputs: [...inputs] };
}