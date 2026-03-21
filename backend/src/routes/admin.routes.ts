import { Router } from 'express';
import { authMiddleware } from '@/middlewares/auth.middleware';
import { requireRole }    from '@/middlewares/role.middleware';
import { validate }       from '@/middlewares/validate.middleware';
import {
  listUsers, createUser, updateUser, listModules, updateModule, getAdminStats,
  getUserPermissions, updateUserPermissions, resetUserPermissions, getUserStats,
  createUserSchema, updateUserSchema, updateModuleSchema, updatePermissionsSchema,
} from '@/controllers/admin.controller';

const router = Router();

router.use(authMiddleware);
router.use(requireRole('ADMIN'));

router.get   ('/users',        listUsers);
router.post  ('/users',        validate(createUserSchema), createUser);
router.patch ('/users/:id',    validate(updateUserSchema), updateUser);
router.get   ('/modules',      listModules);
router.patch ('/modules/:id',  validate(updateModuleSchema), updateModule);
router.get   ('/stats',                      getAdminStats);
router.get   ('/users/:id/permissions',      getUserPermissions);
router.patch ('/users/:id/permissions',      validate(updatePermissionsSchema), updateUserPermissions);
router.post  ('/users/:id/permissions/reset', resetUserPermissions);
router.get   ('/users/:id/stats',            getUserStats);

export default router;
