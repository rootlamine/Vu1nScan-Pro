.PHONY: setup dev test seed clean docker-up docker-down install migrate

# ─── Setup complet (première fois) ───────────────────────────────────────────
setup: docker-up install migrate seed
	@echo "\n✅ VulnScan Pro prêt ! Lancez : make dev\n"

# ─── Développement ────────────────────────────────────────────────────────────
dev:
	npm run dev:all

# ─── Infrastructure Docker ────────────────────────────────────────────────────
docker-up:
	docker-compose up -d
	@echo "⏳ Attente que PostgreSQL soit prêt..."
	@sleep 3

docker-down:
	docker-compose down

# ─── Dépendances ──────────────────────────────────────────────────────────────
install:
	cd backend  && npm install
	cd frontend && npm install
	cd scanner  && pip install -r requirements.txt

# ─── Base de données ──────────────────────────────────────────────────────────
migrate:
	cd backend && npx prisma migrate dev --name init
	cd backend && npx prisma generate

seed:
	cd backend && npm run db:seed

# ─── Tests ────────────────────────────────────────────────────────────────────
test:
	cd backend && npm test

# ─── Nettoyage ────────────────────────────────────────────────────────────────
clean:
	docker-compose down -v
	rm -rf backend/node_modules frontend/node_modules backend/dist
	@echo "✅ Environnement nettoyé"
