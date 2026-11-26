# CyberScan AI — Utilisation de l'IA

## Le projet
Outil d'audit léger de réponses publiques. La note A–F porte uniquement sur les contrôles concluants ; ce n'est ni une certification de sécurité ni une validation des injections SQL ou de la résistance DDoS.

## API utilisées
- Requête HTTP vers le site analysé (lecture des en-têtes et cookies).
- **Google Public DNS (dns.google/resolve)** : enregistrements TXT (SPF), `_dmarc` (DMARC) et CAA.

## Règles d'analyse
Six familles : transport/cookies, en-têtes/CORS, injections/fuites, JavaScript, limitation de débit/bots, disponibilité/signaux réseau. Chaque règle concluante a une gravité pondérée (critique 25, élevé 15, moyen 8, faible 4). Les résultats non concluants sont exclus du numérateur et du dénominateur ; une catégorie sans conclusion n'a pas de note. Le rapport affiche la couverture à côté du score.

## Comment l'IA a été utilisée
- Génération du code en « vibe coding » avec Lovable (agent IA) à partir d'un prompt décrivant le sujet.
- L'IA a proposé les règles de sécurité (basées sur les recommandations OWASP) et la pondération du score.
- Tests automatisés (`src/lib/rules.test.ts`) pour vérifier les règles.

## Éthique
Lecture de réponses publiques, sondes de quelques fichiers courants et six requêtes simultanées. Aucune injection ni charge soutenue. L'outil refuse certaines adresses locales à l'entrée ; ce filtrage n'est pas une garantie contre tous les scénarios de redirection ou de résolution DNS. Usage limité aux sites autorisés.

## Lien de la conversation
(à compléter avec le lien de partage de la conversation)

## SQL : preuves et limites
- Signatures MySQL/MariaDB, PostgreSQL, SQL Server, Oracle, SQLite et JDBC/Java ; les exemples balisés comme code et les scripts sont exclus.
- Une signature est une fuite technique possible, jamais une preuve d'injection exploitable.
- Inventaire plafonné à 30 entrées de la même origine : paramètres de l'URL, liens et formulaires présents dans le HTML. Aucune valeur de paramètre n'est reproduite ; champs mot de passe et cachés exclus.
- Aucun test SQL actif, booléen ou temporel. Les injections restent « non concluantes », y compris quand aucune erreur SQL n'apparaît.

## Réseau : preuves et limites
- Durée initiale jusqu'aux en-têtes depuis le scanner, redirections incluses ; pas de décomposition DNS/TCP/TLS.
- Six requêtes simultanées : nombre de réponses 429, échecs serveur/réseau (délais dépassés inclus) et durée maximale. Pas de moyenne, de percentile ou de débit inventé à partir de cet agrégat.
- Absence de 429 ≠ absence de limitation. Un en-tête RateLimit ne prouve pas l'application de la limite.
- Une signature CDN ne prouve ni un WAF actif ni une origine protégée. Un CAPTCHA ne prouve pas sa validation côté serveur.
- Cache confirmé uniquement par HIT ou Age positif ; MISS/DYNAMIC/BYPASS ne sont pas des succès de cache.
- Résistance DDoS, saturation de bande passante et capacité de charge non mesurées. Un audit autorisé en préproduction et une vérification chez l'hébergeur restent nécessaires.
- Une réponse DNS absente n'est pas distinguée d'un échec de résolution par le collecteur actuel : le résultat reste non concluant. Les politiques héritées et leur efficacité ne sont pas auditées.
- Les contrôles de contenu deviennent non concluants si la page renvoie une réponse hors 2xx, pour ne pas noter une page de blocage à la place de l'application.

## Contrôles passifs supplémentaires
Consoles admin (Spring Actuator, H2, phpMyAdmin, Adminer, Tomcat), fichiers sensibles (.git, .env, heapdump, WEB-INF, dumps SQL…), Swagger/OpenAPI, page 404 bavarde, faux 404, méthode TRACE, reflet XSS via un marqueur inoffensif, security.txt, robots.txt, mot de passe en HTTP, jsessionid dans les URLs, includeSubDomains, COOP, noopener, onclick en ligne, commentaires HTML, autocomplete, SPF +all, DMARC p=none.
