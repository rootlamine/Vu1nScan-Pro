# VulnScan Pro

Plateforme de détection de vulnérabilités web — projet de fin d'études, École du Code — Sonatel Academy.

## Stack technique

| Couche | Technologies |
|--------|-------------|
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, TanStack Query v5, React Router v6 |
| **Backend** | Node.js, Express 4, TypeScript, Prisma 5, JWT, BullMQ, Puppeteer |
| **Scanner** | Python 3.12 (4 modules : HTTP Headers, SQL Injection, XSS, Port Scanner) |
| **Infrastructure** | PostgreSQL 16, Redis 7, Docker Compose |

## Démarrage rapide

```bash
# 1. Copier la configuration
cp backend/.env.example backend/.env

# 2. Setup complet (Docker + install + migrate + seed)
make setup

# 3. Lancer l'application
make dev
```

L'application est disponible sur :
- **App** : http://localhost:5173
- **API** : http://localhost:3001/api/health
- **Adminer** : http://localhost:8080

## Comptes de démonstration

| Rôle | Email | Mot de passe |
|------|-------|-------------|
| ADMIN | admin@vulnscan.io | Admin@2026 |
| USER  | demo@vulnscan.io  | Demo@2026  |

## Architecture

```
vulnscan-pro/
├── backend/          # API REST Express + Worker BullMQ
│   ├── src/
│   │   ├── domain/   # Types, interfaces (Repository pattern)
│   │   ├── repositories/  # Implémentations Prisma
│   │   ├── services/ # Logique métier
│   │   ├── controllers/   # Handlers HTTP
│   │   ├── routes/   # Définition des routes
│   │   ├── middlewares/   # Auth, RBAC, validation, erreurs
│   │   ├── jobs/     # Worker BullMQ (scan asynchrone)
│   │   └── scanner/  # Moteur de scan (spawn Python)
│   └── prisma/       # Schéma + migrations + seed
├── frontend/         # SPA React
│   └── src/
│       ├── pages/    # Dashboard, ScanNew, ScanLive, Results, Reports, Admin…
│       ├── components/    # UI réutilisables
│       ├── hooks/    # useAuth, useScans…
│       └── lib/      # Axios client
└── scanner/          # Modules Python
    ├── modules/      # http_headers, sql_injection, xss_scanner, port_scanner
    └── main.py       # Point d'entrée CLI
```

## Pipeline de scan

`POST /api/scans` → BullMQ job → Worker Node.js → spawn Python (4 modules en parallèle) → résultats JSON → vulnérabilités en DB → status COMPLETED

## Commandes utiles

```bash
make setup       # Setup complet (première fois)
make dev         # Lance backend (3001) + frontend (5173)
make test        # Tests backend (Vitest)
make seed        # Re-charger les données de démo
make docker-down # Arrêter les conteneurs
make clean       # Tout supprimer (conteneurs + node_modules)
```

## Site de test légal

`http://testphp.vulnweb.com` — site officiel OWASP conçu pour les tests de sécurité.
