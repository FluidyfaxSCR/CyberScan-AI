import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { scanSite } from "@/lib/scan.functions";
import { CATEGORY_LABELS, type Category } from "@/lib/rules";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "CyberScan AI — Analyseur de sécurité de sites web" },
      { name: "description", content: "Audit léger de site web : indices SQL, en-têtes et observations réseau. Preuves visibles et limites explicites, sans promesse de résistance DDoS." },
      { property: "og:title", content: "CyberScan AI — Analyseur de sécurité de sites web" },
      { property: "og:description", content: "Examinez les indices SQL et réseau, les preuves observées et les points qui restent à vérifier." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

type Result = Awaited<ReturnType<typeof scanSite>>;
const sevLabel = { critical: "Critique", high: "Élevé", medium: "Moyen", low: "Faible" } as const;
const sevTone = { critical: "bg-destructive/15 text-destructive", high: "bg-destructive/10 text-destructive", medium: "bg-warning/20 text-accent-foreground", low: "bg-muted text-muted-foreground" } as const;
const toneFor = (s: number) => (s >= 75 ? "text-success" : s >= 50 ? "text-warning" : "text-destructive");
const barFor = (s: number) => (s >= 75 ? "bg-success" : s >= 50 ? "bg-warning" : "bg-destructive");

function Index() {
  const scan = useServerFn(scanSite);
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [res, setRes] = useState<Result | null>(null);

  async function run(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true); setError(null); setRes(null);
    try { setRes(await scan({ data: { url } })); }
    catch { setError("Impossible d'analyser ce site. Vérifiez l'adresse."); }
    finally { setLoading(false); }
  }

  const failed = (res?.findings.filter((f) => f.ok === false) ?? []).sort((a, b) => ["critical", "high", "medium", "low"].indexOf(a.severity) - ["critical", "high", "medium", "low"].indexOf(b.severity));
  const unknown = res?.findings.filter((f) => f.ok === null).length ?? 0;

  return (
    <main className="mx-auto min-h-screen max-w-4xl px-5 py-16">
      <p className="text-sm font-medium text-primary">Analyse de sécurité, simplement</p>
      <h1 className="mt-2 text-5xl font-bold md:text-6xl">CyberScan AI</h1>
      <p className="mt-4 max-w-2xl text-lg text-muted-foreground">Indices SQL, configuration web et observations réseau. Chaque conclusion distingue ce qui est observé de ce qui reste à vérifier.</p>

      <form onSubmit={run} className="mt-10 flex flex-col gap-3 sm:flex-row">
        <input aria-label="Adresse du site" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="exemple.fr" required
          className="flex-1 rounded-full border border-input bg-card px-6 py-4 shadow-soft outline-none transition focus:border-primary focus:ring-4 focus:ring-primary/15" />
        <Button type="submit" disabled={loading} className="h-auto rounded-full px-8 py-4 font-semibold shadow-soft">
          {loading ? "Analyse…" : "Analyser"}
        </Button>
      </form>

      {loading && <p role="status" className="animate-breathe mt-8 rounded-3xl bg-card p-6 text-muted-foreground shadow-soft">Lecture des réponses publiques, inventaire des entrées et collecte d'un petit échantillon réseau…</p>}
      {error && <p className="mt-8 rounded-3xl bg-destructive/10 p-5 text-destructive">{error}</p>}

      {res && (
        <section className="animate-float-in mt-10 space-y-8">
          <div className="grid gap-6 rounded-3xl bg-card p-8 shadow-soft sm:grid-cols-[auto_1fr] sm:items-center">
            <div className={`font-display text-8xl font-bold ${toneFor(res.score)}`}>{res.grade}</div>
            <div>
              <p className="break-all text-sm text-muted-foreground">{res.url} · HTTP {res.status} · réponse initiale {res.ttfbMs} ms</p>
              <p className="mt-2 text-sm font-medium">Score des contrôles concluants uniquement</p>
              <p className={`mt-1 text-3xl font-bold ${toneFor(res.score)}`}>{res.score}/100</p>
              <div className="mt-3 h-2.5 rounded-full bg-muted"><div className={`h-full rounded-full ${barFor(res.score)}`} style={{ width: `${res.score}%` }} /></div>
              <p className="mt-3 text-sm text-muted-foreground">{failed.length} anomalie(s) observée(s) · {res.findings.length - unknown}/{res.findings.length} contrôles concluants · {unknown} non concluant(s).</p>
            </div>
          </div>

          <div className="border-y border-border py-5">
            <h2 className="text-xl font-bold">SQL et DDoS : pas de validation de sécurité</h2>
            <p className="mt-2 text-sm text-muted-foreground">Une fuite SQL n'est pas une injection confirmée. Six requêtes ne mesurent ni la capacité du site ni sa résistance à une attaque. Les contrôles non concluants ou sans objet ne donnent aucun point, et toute faille haute ou critique plafonne la note.</p>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {res.categories.map((c) => (
              <div key={c.id} className="rounded-2xl bg-card p-4 shadow-soft">
                <p className="text-sm text-muted-foreground">{c.label}</p>
                <p className={`mt-1 text-2xl font-bold ${c.score === null ? "text-muted-foreground" : toneFor(c.score)}`}>{c.score ?? "—"}{c.score !== null && <span className="text-sm font-medium text-muted-foreground">/100</span>}</p>
                <p className="mt-1 text-xs text-muted-foreground">{res.findings.filter((f) => f.category === c.id && f.ok !== null).length} / {res.findings.filter((f) => f.category === c.id).length} concluants</p>
              </div>
            ))}
          </div>

          {failed.length > 0 && (
            <div>
              <h2 className="text-2xl font-bold">À corriger en priorité</h2>
              <ol className="mt-4 space-y-3">
                {failed.map((f) => (
                  <li key={f.id} className="rounded-2xl bg-card p-5 shadow-soft">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`rounded-full px-3 py-0.5 text-xs font-semibold ${sevTone[f.severity]}`}>{sevLabel[f.severity]}</span>
                      <strong>{f.title}</strong>
                      <span className="ml-auto text-xs text-muted-foreground">{CATEGORY_LABELS[f.category]}</span>
                    </div>
                    <p className="mt-2 text-sm text-muted-foreground">{f.detail}</p>
                    <p className="mt-2 text-sm font-medium text-primary">Conseil : {f.advice}</p>
                  </li>
                ))}
              </ol>
            </div>
          )}

          <div>
            <h2 className="text-2xl font-bold">Détail des contrôles</h2>
            <div className="mt-4 space-y-5">
              {(Object.keys(CATEGORY_LABELS) as Category[]).map((cat) => (
                <div key={cat} className="overflow-hidden rounded-2xl bg-card shadow-soft">
                  <h3 className="bg-secondary px-5 py-3 text-lg font-bold">{CATEGORY_LABELS[cat]}</h3>
                  <ul className="divide-y divide-border">
                    {res.findings.filter((f) => f.category === cat).map((f) => (
                      <li key={f.id} className="flex items-start justify-between gap-4 px-5 py-3 text-sm">
                        <div className="min-w-0 flex-1 break-words"><p className="font-medium">{f.title}</p><p className="text-muted-foreground">{f.detail}</p>
                          {!!f.evidence?.length && <ul aria-label="Éléments observés" className="mt-2 space-y-1 border-l-2 border-border pl-3 font-mono text-xs text-muted-foreground">{f.evidence.map((evidence, n) => <li key={n} className="break-all">{evidence}</li>)}</ul>}
                          {f.ok === null && <p className="mt-2 text-xs text-muted-foreground">À vérifier : {f.advice}</p>}
                        </div>
                        <span className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-semibold ${f.ok === null ? "bg-warning/20 text-accent-foreground" : f.ok ? "bg-success/15 text-success" : "bg-destructive/10 text-destructive"}`}>{f.ok === null ? "Non concluant" : f.ok ? "Observé" : "À corriger"}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}
      <footer className="mt-20 text-xs leading-relaxed text-muted-foreground"><Link to="/code" className="mb-3 inline-block font-semibold text-primary underline-offset-4 hover:underline">Voir le code source de CyberScan AI →</Link><br />Audit léger des réponses publiques et de quelques chemins courants, avec 6 requêtes simultanées. Aucun test d'injection, de charge soutenue ou DDoS. DNS, connexion TCP et négociation TLS ne sont pas chronométrés séparément. Les pages privées, API dynamiques et autres régions ne sont pas couvertes. Réservé aux sites que vous êtes autorisé à auditer.</footer>
    </main>
  );
}

