import { describe, expect, it } from "vitest";
import { collectSqlEvidence } from "./sql-evidence";

describe("preuves SQL", () => {
  it.each([
    ["MySQL / MariaDB", "You have an error in your SQL syntax"],
    ["PostgreSQL", 'syntax error at or near "test"'],
    ["SQL Server", "System.Data.SqlClient.SqlException"],
    ["Oracle", "ORA-00933"],
    ["SQLite", "sqlite3.OperationalError"],
    ["JDBC / Java", "java.sql.SQLSyntaxErrorException"],
  ])("identifie %s sans confirmer une injection", (engine, message) => {
    expect(collectSqlEvidence(`<p>${message}</p>`, "https://a.fr").errors.map((e) => e.engine)).toContain(engine);
  });
  it("ignore les exemples de code et scripts", () => {
    expect(collectSqlEvidence('<code>ORA-00933</code><script>"SQLITE_ERROR"</script>', "https://a.fr").errors).toHaveLength(0);
  });
  it("conserve les traces SQL réelles dans une balise pre", () => {
    expect(collectSqlEvidence('<pre>java.sql.SQLException: database error</pre>', "https://a.fr").errors.map((e) => e.engine)).toContain("JDBC / Java");
  });
  it("inventorie URL, liens et formulaires locaux sans valeurs sensibles", () => {
    const result = collectSqlEvidence('<a href="/item?id=SECRET">x</a><a href="https://autre.fr/?x=1">x</a><form method="POST" action="/search"><input name="q"><input type="password" name="password"><input type="hidden" name="csrf"></form>', "https://a.fr/?page=PRIVATE");
    expect(result.inputs).toEqual(["GET / · page", "GET /item · id", "POST /search · q"]);
    expect(JSON.stringify(result)).not.toContain("SECRET");
    expect(JSON.stringify(result)).not.toContain("PRIVATE");
  });
  it("plafonne la collecte à 30 entrées", () => {
    const html = Array.from({ length: 50 }, (_, n) => `<a href="/item${n}?id=1">x</a>`).join("");
    expect(collectSqlEvidence(html, "https://a.fr").inputs).toHaveLength(30);
  });
});