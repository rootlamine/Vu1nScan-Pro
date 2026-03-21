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
    { slug: 'sql_injection',            name: 'Injection SQL',              category: 'SECURITY', description: "Injecte des payloads dans les paramètres GET/POST. Détecte les erreurs SQL et comportements anormaux." },
    { slug: 'xss_scanner',              name: 'Cross-Site Scripting',       category: 'SECURITY', description: "Teste les formulaires HTML et les paramètres URL pour le Cross-Site Scripting réfléchi." },
    { slug: 'ssl_checker',              name: 'SSL/TLS Checker',            category: 'SECURITY', description: "Vérifie le certificat SSL/TLS (expiration, version TLS, chiffrements faibles)." },
    { slug: 'csrf_scanner',             name: 'CSRF Scanner',               category: 'SECURITY', description: "Détecte l'absence de token CSRF dans les formulaires POST et les cookies sans SameSite." },
    { slug: 'directory_traversal',      name: 'Directory Traversal',        category: 'SECURITY', description: "Teste les vulnérabilités de type path traversal (../../etc/passwd) sur les paramètres." },
    { slug: 'open_redirect',            name: 'Open Redirect',              category: 'SECURITY', description: "Détecte les redirections ouvertes non validées exploitables pour le phishing." },
    { slug: 'security_misconfiguration',name: 'Security Misconfiguration',  category: 'SECURITY', description: "Détecte les pages admin exposées (/admin, /phpmyadmin, /.env, /.git, phpinfo)." },
    { slug: 'sensitive_files',          name: 'Sensitive Files',            category: 'SECURITY', description: "Détecte les fichiers sensibles exposés (backup.zip, .env, config.php, dump.sql)." },
    // ── Réseau ────────────────────────────────────────────────────────────
    { slug: 'port_scanner',             name: 'Scan de ports',              category: 'NETWORK',  description: "Connexion TCP sur 20 ports communs (MySQL, Redis, RDP, SMB...). Évalue l'exposition réseau." },
    { slug: 'http_headers',             name: 'En-têtes HTTP',              category: 'NETWORK',  description: "Vérifie la présence de CSP, HSTS, X-Frame-Options, X-Content-Type-Options et Referrer-Policy." },
    // ── OSINT ─────────────────────────────────────────────────────────────
    { slug: 'whois_lookup',             name: 'WHOIS Lookup',               category: 'OSINT',    description: "Récupère les informations WHOIS publiques du domaine (registrar, dates, nameservers, pays)." },
    { slug: 'dns_recon',                name: 'DNS Reconnaissance',         category: 'OSINT',    description: "Énumère les enregistrements DNS (A, MX, NS, TXT) et détecte les transferts de zone ouverts." },
    { slug: 'subdomain_enum',           name: 'Énumération sous-domaines',  category: 'OSINT',    description: "Énumère les sous-domaines courants (www, mail, api, admin...) et résout leurs adresses IP." },
    { slug: 'email_harvester',          name: 'Email Harvester',            category: 'OSINT',    description: "Scrape les adresses email exposées sur le site web cible (HTML, pages contact, métadonnées)." },
    { slug: 'technology_fingerprint',   name: 'Tech Fingerprinting',        category: 'OSINT',    description: "Détecte les technologies utilisées : CMS, frameworks, serveurs, langages, CDN et analytics." },
    { slug: 'google_dorks',             name: 'Google Dorks',               category: 'OSINT',    description: "Génère des dorks de recherche (filetype:pdf, inurl:admin, intext:password) sur le domaine cible." },
    // ── Scraping ──────────────────────────────────────────────────────────
    { slug: 'metadata_extractor',       name: 'Metadata Extractor',         category: 'SCRAPING', description: "Extrait les métadonnées des PDF et images (auteurs, logiciels, chemins internes, dates)." },
    { slug: 'broken_links',             name: 'Broken Links',               category: 'SCRAPING', description: "Crawl le site et détecte les liens cassés (404, 500) selon la profondeur configurée." },
    { slug: 'javascript_analyzer',      name: 'JavaScript Analyzer',        category: 'SCRAPING', description: "Analyse les fichiers JS : API keys, tokens AWS/Google, JWTs, endpoints cachés, commentaires sensibles." },
  ];

  const modules = [];
  for (const m of modulesData) {
    const mod = await prisma.scanModule.upsert({
      where:  { slug: m.slug },
      update: { name: m.name, description: m.description, category: m.category as 'SECURITY'|'NETWORK'|'OSINT'|'SCRAPING' },
      create: { slug: m.slug, name: m.name, description: m.description, category: m.category as 'SECURITY'|'NETWORK'|'OSINT'|'SCRAPING', isActive: true, defaultEnabled: true },
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
  await prisma.vulnerability.createMany({
    data: [
      { scanId: scan1.id, name: 'Injection SQL détectée', severity: 'CRITICAL', cvssScore: 9.8,
        endpoint: 'http://testphp.vulnweb.com/listproducts.php', parameter: 'cat',
        description: "Injection SQL confirmée via le paramètre 'cat'. Le payload provoque un message d'erreur MySQL révélant la technologie de base de données.",
        payload: "' OR '1'='1' --",
        recommendation: "Utiliser des requêtes préparées (prepared statements). Ne jamais concaténer les entrées utilisateur dans les requêtes SQL." },
      { scanId: scan1.id, name: 'Injection SQL détectée', severity: 'CRITICAL', cvssScore: 9.8,
        endpoint: 'http://testphp.vulnweb.com/artists.php', parameter: 'artist',
        description: "Injection SQL confirmée via le paramètre 'artist'.",
        payload: "'",
        recommendation: "Utiliser des requêtes préparées." },
      { scanId: scan1.id, name: 'Cross-Site Scripting (XSS) réfléchi', severity: 'HIGH', cvssScore: 7.2,
        endpoint: 'http://testphp.vulnweb.com/search.php', parameter: 'test',
        description: "Le paramètre 'test' réfléchit le payload XSS sans encodage HTML, permettant l'exécution de code JavaScript arbitraire.",
        payload: '<script>alert(1)</script>',
        recommendation: "Encoder toutes les sorties HTML avec htmlspecialchars(). Implémenter une CSP stricte." },
      { scanId: scan1.id, name: 'En-tête Content-Security-Policy manquant', severity: 'HIGH', cvssScore: 7.5,
        endpoint: 'http://testphp.vulnweb.com',
        description: "L'en-tête Content-Security-Policy (CSP) est absent. Cela expose l'application aux attaques XSS.",
        recommendation: "Configurer une politique CSP stricte : Content-Security-Policy: default-src 'self'" },
      { scanId: scan1.id, name: 'Port MySQL exposé (3306/tcp)', severity: 'CRITICAL', cvssScore: 9.8,
        endpoint: 'testphp.vulnweb.com:3306',
        description: "MySQL (port 3306) est accessible depuis l'extérieur. La base de données ne devrait jamais être exposée sur Internet.",
        recommendation: "Fermer le port 3306 dans le pare-feu. Restreindre l'accès aux IP internes." },
      { scanId: scan1.id, name: 'En-tête HSTS manquant', severity: 'MEDIUM', cvssScore: 6.1,
        endpoint: 'http://testphp.vulnweb.com',
        description: "L'en-tête HTTP Strict Transport Security (HSTS) est absent.",
        recommendation: "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains" },
      { scanId: scan1.id, name: 'En-tête X-Frame-Options manquant', severity: 'MEDIUM', cvssScore: 5.4,
        endpoint: 'http://testphp.vulnweb.com',
        description: "L'en-tête X-Frame-Options est absent, ce qui permet le clickjacking.",
        recommendation: "Ajouter : X-Frame-Options: DENY" },
      { scanId: scan1.id, name: 'En-tête X-Content-Type-Options manquant', severity: 'LOW', cvssScore: 3.7,
        endpoint: 'http://testphp.vulnweb.com',
        description: "L'en-tête X-Content-Type-Options est absent.",
        recommendation: "Ajouter : X-Content-Type-Options: nosniff" },
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
        description: "L'en-tête HSTS est absent.", recommendation: "Ajouter Strict-Transport-Security." },
      { scanId: scan2.id, name: 'Port HTTP alternatif ouvert (8080/tcp)', severity: 'MEDIUM', cvssScore: 5.3,
        endpoint: 'demo.testfire.net:8080',
        description: "Port 8080 ouvert, peut exposer une interface d'administration.",
        recommendation: "Fermer le port si non nécessaire." },
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

  console.log('\n✅ Seed terminé avec succès !');
  console.log('──────────────────────────────────────────');
  console.log('  ADMIN : admin@vulnscan.io / Admin@2026');
  console.log('  USER  : demo@vulnscan.io  / Demo@2026');
  console.log('──────────────────────────────────────────\n');
}

main()
  .catch((e) => { console.error('❌ Erreur seed :', e); process.exit(1); })
  .finally(() => prisma.$disconnect());
