import 'dotenv/config';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL! });
const prisma  = new PrismaClient({ adapter });

async function main() {
  console.log('🌱 Démarrage du seed VulnScan Pro...\n');

  // ── 1. Comptes utilisateurs ────────────────────────────────────────────────
  const adminHash = await bcrypt.hash('Admin@2026', 10);
  const demoHash  = await bcrypt.hash('Demo@2026',  10);

  const admin = await prisma.user.upsert({
    where:  { email: 'admin@vulnscan.io' },
    update: {},
    create: { username: 'admin', email: 'admin@vulnscan.io', passwordHash: adminHash, role: 'ADMIN' },
  });

  const demoUser = await prisma.user.upsert({
    where:  { email: 'demo@vulnscan.io' },
    update: {},
    create: { username: 'demo', email: 'demo@vulnscan.io', passwordHash: demoHash },
  });

  console.log(`✅ Utilisateurs : ${admin.email} (ADMIN), ${demoUser.email} (USER)`);

  // ── 2. Modules de scan ─────────────────────────────────────────────────────
  const modulesData = [
    // ── Sécurité ───────────────────────────────────────────────────────────
    { slug: 'sql_injection',            name: 'Injection SQL',              category: 'SECURITY',          description: "Injecte des payloads dans les paramètres GET/POST. Détecte les erreurs SQL et comportements anormaux." },
    { slug: 'xss_scanner',              name: 'Cross-Site Scripting',       category: 'SECURITY',          description: "Teste les formulaires HTML et les paramètres URL pour le Cross-Site Scripting réfléchi." },
    { slug: 'ssl_checker',              name: 'SSL/TLS Checker',            category: 'SECURITY',          description: "Vérifie le certificat SSL/TLS (expiration, version TLS, chiffrements faibles)." },
    { slug: 'csrf_scanner',             name: 'CSRF Scanner',               category: 'SECURITY',          description: "Détecte l'absence de token CSRF dans les formulaires POST et les cookies sans SameSite." },
    { slug: 'directory_traversal',      name: 'Directory Traversal',        category: 'SECURITY',          description: "Teste les vulnérabilités de type path traversal (../../etc/passwd) sur les paramètres." },
    { slug: 'open_redirect',            name: 'Open Redirect',              category: 'SECURITY',          description: "Détecte les redirections ouvertes non validées exploitables pour le phishing." },
    { slug: 'security_misconfiguration',name: 'Security Misconfiguration',  category: 'SECURITY',          description: "Détecte les pages admin exposées (/admin, /phpmyadmin, /.env, /.git, phpinfo)." },
    { slug: 'sensitive_files',          name: 'Sensitive Files',            category: 'SECURITY',          description: "Détecte les fichiers sensibles exposés (backup.zip, .env, config.php, dump.sql)." },
    // ── Réseau ────────────────────────────────────────────────────────────
    { slug: 'port_scanner',             name: 'Scan de ports',              category: 'NETWORK',           description: "Connexion TCP sur 20 ports communs (MySQL, Redis, RDP, SMB...). Évalue l'exposition réseau." },
    { slug: 'http_headers',             name: 'En-têtes HTTP',              category: 'NETWORK',           description: "Vérifie la présence de CSP, HSTS, X-Frame-Options, X-Content-Type-Options et Referrer-Policy." },
    // ── OSINT ─────────────────────────────────────────────────────────────
    { slug: 'whois_lookup',             name: 'WHOIS Lookup',               category: 'OSINT',             description: "Récupère les informations WHOIS publiques du domaine (registrar, dates, nameservers, pays)." },
    { slug: 'dns_recon',                name: 'DNS Reconnaissance',         category: 'OSINT',             description: "Énumère les enregistrements DNS (A, MX, NS, TXT) et détecte les transferts de zone ouverts." },
    { slug: 'subdomain_enum',           name: 'Énumération sous-domaines',  category: 'OSINT',             description: "Énumère les sous-domaines courants (www, mail, api, admin...) et résout leurs adresses IP." },
    { slug: 'email_harvester',          name: 'Email Harvester',            category: 'OSINT',             description: "Scrape les adresses email exposées sur le site web cible (HTML, pages contact, métadonnées)." },
    { slug: 'technology_fingerprint',   name: 'Tech Fingerprinting',        category: 'OSINT',             description: "Détecte les technologies utilisées : CMS, frameworks, serveurs, langages, CDN et analytics." },
    { slug: 'google_dorks',             name: 'Google Dorks',               category: 'OSINT',             description: "Génère des dorks de recherche (filetype:pdf, inurl:admin, intext:password) sur le domaine cible." },
    // ── Scraping ──────────────────────────────────────────────────────────
    { slug: 'metadata_extractor',       name: 'Metadata Extractor',         category: 'SCRAPING',          description: "Extrait les métadonnées des PDF et images (auteurs, logiciels, chemins internes, dates)." },
    { slug: 'broken_links',             name: 'Broken Links',               category: 'SCRAPING',          description: "Crawl le site et détecte les liens cassés (404, 500) selon la profondeur configurée." },
    { slug: 'javascript_analyzer',      name: 'JavaScript Analyzer',        category: 'SCRAPING',          description: "Analyse les fichiers JS : API keys, tokens AWS/Google, JWTs, endpoints cachés, commentaires sensibles." },
    // ── Offensif Web ──────────────────────────────────────────────────────
    { slug: 'lfi_rfi_scanner',          name: 'LFI/RFI Scanner',            category: 'WEB_OFFENSIVE',     description: "Teste les vulnérabilités LFI/RFI en injectant ../../etc/passwd dans les paramètres GET/POST. CVSS 9.0 CRITICAL." },
    { slug: 'xxe_scanner',              name: 'XXE Scanner',                category: 'WEB_OFFENSIVE',     description: "Injecte des payloads XXE dans les formulaires et endpoints XML/JSON. CVSS 8.2 HIGH." },
    { slug: 'ssrf_scanner',             name: 'SSRF Scanner',               category: 'WEB_OFFENSIVE',     description: "Teste les redirections vers 169.254.169.254, localhost, 127.0.0.1. Détecte les SSRF. CVSS 8.6 HIGH." },
    { slug: 'command_injection',        name: 'Command Injection',          category: 'WEB_OFFENSIVE',     description: "Injecte ; ls, && id, | whoami dans les paramètres. Détecte les injections OS. CVSS 9.8 CRITICAL." },
    { slug: 'http_methods_scanner',     name: 'HTTP Methods Scanner',       category: 'WEB_OFFENSIVE',     description: "Teste PUT DELETE TRACE CONNECT OPTIONS sur le serveur. Détecte les méthodes dangereuses activées. CVSS 6.5 MEDIUM." },
    // ── Offensif API ──────────────────────────────────────────────────────
    { slug: 'api_fuzzer',               name: 'API Fuzzer',                 category: 'API_OFFENSIVE',     description: "Fuzz /api/v1/, /graphql, /swagger, /admin sans token. Détecte les endpoints exposés. CVSS 8.0 HIGH." },
    { slug: 'broken_auth_api',          name: 'Broken Auth API',            category: 'API_OFFENSIVE',     description: "Teste IDOR sur /api/users/1-2, accès sans token, tokens expirés. CVSS 8.8 HIGH." },
    { slug: 'graphql_introspection',    name: 'GraphQL Introspection',      category: 'API_OFFENSIVE',     description: "POST {__schema{types{name}}} sur /graphql. Détecte l'introspection activée. CVSS 5.3 MEDIUM." },
    { slug: 'rate_limit_tester',        name: 'Rate Limit Tester',          category: 'API_OFFENSIVE',     description: "Envoie 20 requêtes rapides sur /api/auth/login. Détecte l'absence de rate limiting. CVSS 5.3 MEDIUM." },
    // ── Offensif Réseau ───────────────────────────────────────────────────
    { slug: 'banner_grabbing',          name: 'Banner Grabbing',            category: 'NETWORK_OFFENSIVE', description: "Connexion TCP sur ports ouverts, récupère les banners et détecte les versions exposées. CVSS 5.0 MEDIUM." },
    { slug: 'firewall_detection',       name: 'Firewall/WAF Detection',     category: 'NETWORK_OFFENSIVE', description: "Détecte WAF via headers (X-Sucuri, CF-RAY, X-Powered-By-Plesk). Analyse blocage de payloads. CVSS 4.0 MEDIUM." },
    { slug: 'traceroute_analysis',      name: 'Traceroute Analysis',        category: 'NETWORK_OFFENSIVE', description: "Traceroute vers la cible, compte les hops, révèle la topologie réseau. CVSS 3.0 LOW." },
    { slug: 'ipv6_scanner',             name: 'IPv6 Scanner',               category: 'NETWORK_OFFENSIVE', description: "Résout AAAA, scanne les ports IPv6. Détecte les expositions IPv6 non protégées. CVSS 4.5 MEDIUM." },
    // ── Système ───────────────────────────────────────────────────────────
    { slug: 'os_fingerprint',           name: 'OS Fingerprinting',          category: 'SYSTEM',            description: "Analyse TTL (64=Linux, 128=Windows), headers Server, X-Powered-By pour identifier l'OS. CVSS 3.7 LOW." },
    { slug: 'service_version_scan',     name: 'Service Version Scan',       category: 'SYSTEM',            description: "Récupère les versions services, interroge NVD API pour les CVEs connus. CVSS 7.5 HIGH." },
    { slug: 'default_credentials',      name: 'Default Credentials',        category: 'SYSTEM',            description: "Teste admin/admin, root/root, admin/password sur HTTP Basic Auth et formulaires login. CVSS 9.8 CRITICAL." },
  ];

  const modules = [];
  for (const m of modulesData) {
    const mod = await prisma.scanModule.upsert({
      where:  { slug: m.slug },
      update: { name: m.name, description: m.description, category: m.category as 'SECURITY'|'NETWORK'|'OSINT'|'SCRAPING'|'WEB_OFFENSIVE'|'API_OFFENSIVE'|'NETWORK_OFFENSIVE'|'SYSTEM' },
      create: { slug: m.slug, name: m.name, description: m.description, category: m.category as 'SECURITY'|'NETWORK'|'OSINT'|'SCRAPING'|'WEB_OFFENSIVE'|'API_OFFENSIVE'|'NETWORK_OFFENSIVE'|'SYSTEM', isActive: true, defaultEnabled: true },
    });
    modules.push(mod);
  }
  console.log(`✅ Modules : ${modules.map(m => m.slug).join(', ')}`);

  // ── 3. Scans de démonstration ──────────────────────────────────────────────

  // Scan 1 — testphp.vulnweb.com (COMPLETED, beaucoup de vulnérabilités)
  const scan1 = await prisma.scan.create({
    data: {
      userId: demoUser.id, targetUrl: 'http://testphp.vulnweb.com',
      description: 'Site de test OWASP officiel — résultats de démonstration',
      status: 'COMPLETED', depth: 'normal',
      startedAt: new Date(Date.now() - 3600_000), completedAt: new Date(Date.now() - 3500_000),
    },
  });
  for (const mod of modules) {
    await prisma.scanModuleResult.create({
      data: { scanId: scan1.id, moduleId: mod.id, status: 'DONE', executionTime: Math.floor(Math.random() * 8000) + 2000 },
    });
  }
  const SQL_REFS = ['https://owasp.org/www-community/attacks/SQL_Injection','https://cwe.mitre.org/data/definitions/89.html','https://portswigger.net/web-security/sql-injection','https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'];
  const XSS_REFS = ['https://owasp.org/www-community/attacks/xss/','https://cwe.mitre.org/data/definitions/79.html','https://portswigger.net/web-security/cross-site-scripting','https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'];
  const HDR_REFS = ['https://owasp.org/www-project-secure-headers/','https://securityheaders.com/','https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'];
  const PRT_REFS = ['https://www.iana.org/assignments/service-names-port-numbers/','https://nmap.org/book/man-port-scanning-basics.html'];

  await prisma.vulnerability.createMany({
    data: [
      { scanId: scan1.id, name: 'Injection SQL détectée', severity: 'CRITICAL', cvssScore: 9.8,
        endpoint: 'http://testphp.vulnweb.com/listproducts.php', parameter: 'cat',
        description: "Injection SQL confirmée via le paramètre 'cat'. Le payload provoque un message d'erreur MySQL révélant la technologie de base de données.",
        payload: "' OR '1'='1' --",
        recommendation: "Utiliser des requêtes préparées (prepared statements). Ne jamais concaténer les entrées utilisateur dans les requêtes SQL.",
        references: SQL_REFS },
      { scanId: scan1.id, name: 'Injection SQL détectée', severity: 'CRITICAL', cvssScore: 9.8,
        endpoint: 'http://testphp.vulnweb.com/artists.php', parameter: 'artist',
        description: "Injection SQL confirmée via le paramètre 'artist'.",
        payload: "'",
        recommendation: "Utiliser des requêtes préparées.",
        references: SQL_REFS },
      { scanId: scan1.id, name: 'Cross-Site Scripting (XSS) réfléchi', severity: 'HIGH', cvssScore: 7.2,
        endpoint: 'http://testphp.vulnweb.com/search.php', parameter: 'test',
        description: "Le paramètre 'test' réfléchit le payload XSS sans encodage HTML, permettant l'exécution de code JavaScript arbitraire.",
        payload: '<script>alert(1)</script>',
        recommendation: "Encoder toutes les sorties HTML avec htmlspecialchars(). Implémenter une CSP stricte.",
        references: XSS_REFS },
      { scanId: scan1.id, name: 'En-tête Content-Security-Policy manquant', severity: 'HIGH', cvssScore: 7.5,
        endpoint: 'http://testphp.vulnweb.com',
        description: "L'en-tête Content-Security-Policy (CSP) est absent. Cela expose l'application aux attaques XSS.",
        recommendation: "Configurer une politique CSP stricte : Content-Security-Policy: default-src 'self'",
        references: HDR_REFS },
      { scanId: scan1.id, name: 'Port MySQL exposé (3306/tcp)', severity: 'CRITICAL', cvssScore: 9.8,
        endpoint: 'testphp.vulnweb.com:3306',
        description: "MySQL (port 3306) est accessible depuis l'extérieur. La base de données ne devrait jamais être exposée sur Internet.",
        recommendation: "Fermer le port 3306 dans le pare-feu. Restreindre l'accès aux IP internes.",
        references: PRT_REFS },
      { scanId: scan1.id, name: 'En-tête HSTS manquant', severity: 'MEDIUM', cvssScore: 6.1,
        endpoint: 'http://testphp.vulnweb.com',
        description: "L'en-tête HTTP Strict Transport Security (HSTS) est absent.",
        recommendation: "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains",
        references: HDR_REFS },
      { scanId: scan1.id, name: 'En-tête X-Frame-Options manquant', severity: 'MEDIUM', cvssScore: 5.4,
        endpoint: 'http://testphp.vulnweb.com',
        description: "L'en-tête X-Frame-Options est absent, ce qui permet le clickjacking.",
        recommendation: "Ajouter : X-Frame-Options: DENY",
        references: HDR_REFS },
      { scanId: scan1.id, name: 'En-tête X-Content-Type-Options manquant', severity: 'LOW', cvssScore: 3.7,
        endpoint: 'http://testphp.vulnweb.com',
        description: "L'en-tête X-Content-Type-Options est absent.",
        recommendation: "Ajouter : X-Content-Type-Options: nosniff",
        references: HDR_REFS },
    ],
  });
  console.log(`✅ Scan 1 créé (8 vulnérabilités) : ${scan1.targetUrl}`);

  // Scan 2 — demo.testfire.net (COMPLETED, quelques vulnérabilités)
  const scan2 = await prisma.scan.create({
    data: {
      userId: admin.id, targetUrl: 'http://demo.testfire.net',
      status: 'COMPLETED', depth: 'fast',
      startedAt: new Date(Date.now() - 7200_000), completedAt: new Date(Date.now() - 7100_000),
    },
  });
  for (const mod of modules) {
    await prisma.scanModuleResult.create({
      data: { scanId: scan2.id, moduleId: mod.id, status: 'DONE', executionTime: Math.floor(Math.random() * 5000) + 1000 },
    });
  }
  await prisma.vulnerability.createMany({
    data: [
      { scanId: scan2.id, name: 'En-tête HSTS manquant', severity: 'MEDIUM', cvssScore: 6.1,
        endpoint: 'http://demo.testfire.net',
        description: "L'en-tête HSTS est absent.", recommendation: "Ajouter Strict-Transport-Security.",
        references: ['https://owasp.org/www-project-secure-headers/','https://securityheaders.com/','https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'] },
      { scanId: scan2.id, name: 'Port HTTP alternatif ouvert (8080/tcp)', severity: 'MEDIUM', cvssScore: 5.3,
        endpoint: 'demo.testfire.net:8080',
        description: "Port 8080 ouvert, peut exposer une interface d'administration.",
        recommendation: "Fermer le port si non nécessaire.",
        references: ['https://www.iana.org/assignments/service-names-port-numbers/','https://nmap.org/book/man-port-scanning-basics.html'] },
    ],
  });
  console.log(`✅ Scan 2 créé (2 vulnérabilités) : ${scan2.targetUrl}`);

  // Scan 3 — FAILED
  const scan3 = await prisma.scan.create({
    data: {
      userId: demoUser.id, targetUrl: 'http://target-inaccessible.example.com',
      description: 'Scan de démonstration — cible inaccessible',
      status: 'FAILED', depth: 'normal',
      startedAt: new Date(Date.now() - 86400_000), completedAt: new Date(Date.now() - 86280_000),
    },
  });
  for (const mod of modules) {
    await prisma.scanModuleResult.create({
      data: { scanId: scan3.id, moduleId: mod.id, status: 'ERROR' },
    });
  }
  console.log(`✅ Scan 3 créé (FAILED) : ${scan3.targetUrl}`);

  // ── 4. Profils de scan par défaut ──────────────────────────────────────────

  const PROFILE_RECON = [
    'whois_lookup', 'dns_recon', 'subdomain_enum',
    'email_harvester', 'technology_fingerprint',
    'http_headers', 'port_scanner',
  ];

  const PROFILE_WEB = [
    'http_headers', 'sql_injection', 'xss_scanner',
    'csrf_scanner', 'directory_traversal', 'open_redirect',
    'security_misconfiguration', 'sensitive_files',
    'ssl_checker', 'lfi_rfi_scanner', 'xxe_scanner',
    'ssrf_scanner', 'command_injection', 'http_methods_scanner',
  ];

  const PROFILE_API = [
    'api_fuzzer', 'broken_auth_api', 'graphql_introspection',
    'rate_limit_tester', 'http_methods_scanner', 'ssl_checker',
  ];

  const PROFILE_OSINT = [
    'whois_lookup', 'dns_recon', 'subdomain_enum',
    'email_harvester', 'technology_fingerprint',
    'google_dorks', 'metadata_extractor',
  ];

  const ALL_SLUGS = modules.map(m => m.slug);

  const profilesData = [
    {
      name: 'Reconnaissance',
      description: 'OSINT et reconnaissance réseau — profil par défaut non intrusif.',
      modules: PROFILE_RECON,
      isDefault: true,
    },
    {
      name: 'Web Scan Complet',
      description: 'Analyse complète de la sécurité web : injections, headers, SSL, LFI, XXE, SSRF.',
      modules: PROFILE_WEB,
      isDefault: false,
    },
    {
      name: 'API Security',
      description: 'Audit de sécurité des APIs REST et GraphQL : fuzzing, auth, rate limiting.',
      modules: PROFILE_API,
      isDefault: false,
    },
    {
      name: 'OSINT Complet',
      description: 'Collecte maximale d\'informations publiques : WHOIS, DNS, emails, dorks, métadonnées.',
      modules: PROFILE_OSINT,
      isDefault: false,
    },
    {
      name: 'Audit Complet',
      description: 'Tous les 35 modules activés — audit de sécurité exhaustif.',
      modules: ALL_SLUGS,
      isDefault: false,
    },
  ];

  for (const user of [admin, demoUser]) {
    for (const profile of profilesData) {
      await prisma.scanProfile.upsert({
        where: {
          userId_name: { userId: user.id, name: profile.name },
        },
        update: { modules: profile.modules, description: profile.description },
        create: {
          userId: user.id,
          name: profile.name,
          description: profile.description,
          modules: profile.modules,
          isDefault: profile.isDefault,
        },
      });
    }
  }
  console.log(`✅ Profils de scan créés pour admin et demo (${profilesData.length} profils)`);

  // ── 5. Permissions utilisateurs ──────────────────────────────────────────────

  const adminPerms = {
    maxScansPerDay: 9999, maxScansPerMonth: 9999, maxConcurrentScans: 10,
    maxTargetsPerScan: 10, maxThreads: 20, maxScanDuration: 3600, maxScanDepth: 'deep',
    allowedCategories: [] as string[], blockedModules: [] as string[],
    canUseOffensiveModules: true, canGenerateReports: true, canExportData: true,
    canCreateProfiles: true, canScanInternalIPs: true, canUseDeepScan: true, canScheduleScans: true,
  };
  const userPerms = {
    maxScansPerDay: 10, maxScansPerMonth: 100, maxConcurrentScans: 2,
    maxTargetsPerScan: 1, maxThreads: 5, maxScanDuration: 300, maxScanDepth: 'normal',
    allowedCategories: [] as string[], blockedModules: [] as string[],
    canUseOffensiveModules: false, canGenerateReports: true, canExportData: true,
    canCreateProfiles: true, canScanInternalIPs: false, canUseDeepScan: false, canScheduleScans: false,
  };

  await prisma.userPermissions.upsert({
    where:  { userId: admin.id },
    update: adminPerms,
    create: { userId: admin.id, ...adminPerms },
  });
  await prisma.userPermissions.upsert({
    where:  { userId: demoUser.id },
    update: userPerms,
    create: { userId: demoUser.id, ...userPerms },
  });
  console.log(`✅ Permissions créées : admin (illimitées), demo (limites standard)`);

  console.log('\n✅ Seed terminé avec succès !');
  console.log('──────────────────────────────────────────');
  console.log('  ADMIN : admin@vulnscan.io / Admin@2026');
  console.log('  USER  : demo@vulnscan.io  / Demo@2026');
  console.log('──────────────────────────────────────────\n');
}

main()
  .catch((e) => { console.error('❌ Erreur seed :', e); process.exit(1); })
  .finally(() => prisma.$disconnect());
