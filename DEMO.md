# Guide de démonstration — VulnScan Pro

## Avant la présentation

```bash
make setup       # Docker + install + migrate + seed (une seule fois)
make dev         # Lance backend (3001) + frontend (5173)
```

Vérifier : `curl http://localhost:3001/api/health`

---

## Scénario de démonstration (15 min)

### 1. Connexion (1 min)
- Ouvrir `http://localhost:5173`
- Se connecter avec : `demo@vulnscan.io / Demo@2026`
- **Montrer** : redirection automatique vers le Dashboard

### 2. Dashboard (2 min)
- **Montrer** : StatCards (scans totaux, actifs, terminés, échoués)
- **Montrer** : liste des 5 derniers scans avec StatusBadge colorés
- **Expliquer** : les données sont celles du seed (scans pré-chargés sur testphp.vulnweb.com)

### 3. Lancer un nouveau scan (3 min)
- Cliquer "Nouveau scan"
- Saisir l'URL : `http://testphp.vulnweb.com`
- Sélectionner profondeur : Normal
- **Montrer** : les 4 modules listés (En-têtes HTTP, SQL Injection, XSS, Ports)
- Cliquer "Lancer le scan"
- **Page Live** : montrer la barre de progression et les modules qui se terminent un à un
- **Expliquer** : architecture BullMQ — le scan tourne en Worker Node.js qui lance des scripts Python

### 4. Résultats du scan (4 min)
- Quand COMPLETED → cliquer "Voir les résultats"
- **Montrer** : StatCards CRITICAL/HIGH/MEDIUM/LOW
- **Ouvrir** une vulnérabilité CRITICAL (SQL Injection) → afficher accordéon
  - Montrer : endpoint, paramètre, description, payload en fond sombre, recommandation
- **Filtrer** par severity=CRITICAL → seulement les critiques
- **Rechercher** "XSS" → filtre en temps réel
- Cliquer "Exporter PDF" → génération Puppeteer → toast succès

### 5. Télécharger le rapport PDF (1 min)
- Aller dans "Rapports"
- **Montrer** : rapport listé avec date et taille
- Cliquer "PDF" → téléchargement du fichier

### 6. Administration (2 min)
- Se déconnecter → se connecter avec `admin@vulnscan.io / Admin@2026`
- Aller dans "Admin"
- **Onglet Utilisateurs** : montrer les 2 comptes, changer le rôle d'un user
- **Onglet Modules** : activer/désactiver un module
- **Onglet Statistiques** : stats globales de la plateforme

### 7. Profil utilisateur (1 min)
- Aller dans "Mon profil"
- **Montrer** : modification de l'email, changement de mot de passe

---

## Points techniques à souligner

| Aspect | Ce qu'on montre |
|--------|-----------------|
| **Sécurité API** | JWT dans toutes les requêtes, RBAC (USER vs ADMIN), rate limiting |
| **Architecture async** | BullMQ + Redis — le scan ne bloque pas l'API |
| **Modules Python** | 4 modules spécialisés, interface commune JSON, spawn Node.js→Python |
| **Frontend** | React 18 + TanStack Query (polling temps réel), Tailwind CSS |
| **Base de données** | Prisma ORM + PostgreSQL + relations Cascade |
| **Génération PDF** | Puppeteer headless (Chromium) |

---

## Comptes de démonstration

| Rôle | Email | Mot de passe |
|------|-------|-------------|
| ADMIN | admin@vulnscan.io | Admin@2026 |
| USER  | demo@vulnscan.io  | Demo@2026  |

## Site de test légal

`http://testphp.vulnweb.com` — site officiel OWASP conçu pour les tests de sécurité.
