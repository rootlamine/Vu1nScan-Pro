import 'dotenv/config';
import express from 'express';
import cors    from 'cors';
import helmet  from 'helmet';
import morgan  from 'morgan';

import authRoutes   from '@/routes/auth.routes';
import scanRoutes   from '@/routes/scan.routes';
import vulnRoutes   from '@/routes/vuln.routes';
import moduleRoutes from '@/routes/module.routes';
import reportRoutes from '@/routes/report.routes';
import adminRoutes  from '@/routes/admin.routes';
import { errorHandler } from '@/middlewares/error-handler';

// Démarre le BullMQ worker (désactivé en mode test)
if (process.env.NODE_ENV !== 'test') {
  import('@/jobs/scan-worker').catch(err =>
    console.error('[Worker] Erreur de démarrage :', err),
  );
}

const app  = express();
const PORT = process.env.PORT || 3001;

// ─── Middlewares globaux ──────────────────────────────────────────────────────
app.use(helmet());
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:5173' }));
app.use(morgan('dev'));
app.use(express.json());

// ─── Routes ───────────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', version: '1.0.0', timestamp: new Date().toISOString() });
});

app.use('/api/auth',            authRoutes);
app.use('/api/scans',           scanRoutes);
app.use('/api/vulnerabilities', vulnRoutes);
app.use('/api/modules',         moduleRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/admin',   adminRoutes);

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Route non trouvée' });
});

// ─── Gestionnaire d'erreurs (DOIT être en dernier) ───────────────────────────
app.use(errorHandler);

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`\n🛡  VulnScan Pro API — http://localhost:${PORT}/api/health\n`);
  });
}

export default app;
