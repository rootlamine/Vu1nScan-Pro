import { Router } from 'express';
import { authMiddleware } from '@/middlewares/auth.middleware';
import { requireRole }    from '@/middlewares/role.middleware';
import { validate }       from '@/middlewares/validate.middleware';
import {
  listUsers, createUser, updateUser, listModules, updateModule, getAdminStats,
  createUserSchema, updateUserSchema, updateModuleSchema,
} from '@/controllers/admin.controller';

const router = Router();

router.use(authMiddleware);
router.use(requireRole('ADMIN'));

router.get   ('/users',        listUsers);
router.post  ('/users',        validate(createUserSchema), createUser);
router.patch ('/users/:id',    validate(updateUserSchema), updateUser);
router.get   ('/modules',      listModules);
router.patch ('/modules/:id',  validate(updateModuleSchema), updateModule);
router.get   ('/stats',        getAdminStats);

export default router;
