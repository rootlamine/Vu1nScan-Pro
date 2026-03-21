import { Router } from 'express';
import { authMiddleware } from '@/middlewares/auth.middleware';
import { ModuleRepository } from '@/repositories/module.repository';
import { sendSuccess } from '@/utils/response';

const router     = Router();
const moduleRepo = new ModuleRepository();

router.get('/', authMiddleware, async (_req, res, next) => {
  try {
    const modules = await moduleRepo.findAllActive();
    sendSuccess(res, modules);
  } catch (err) { next(err); }
});

export default router;
