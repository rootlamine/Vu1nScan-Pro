import { Router } from 'express';
import { authMiddleware } from '@/middlewares/auth.middleware';
import { validate }       from '@/middlewares/validate.middleware';
import { listAllVulnerabilities, getGlobalStats, updateVuln, updateVulnSchema } from '@/controllers/vuln.controller';

const router = Router();

router.use(authMiddleware);

router.get  ('/stats',  getGlobalStats);
router.get  ('/',       listAllVulnerabilities);
router.patch('/:id',   validate(updateVulnSchema), updateVuln);

export default router;
