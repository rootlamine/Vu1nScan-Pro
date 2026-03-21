import { Router } from 'express';
import { authMiddleware } from '@/middlewares/auth.middleware';
import { validate }       from '@/middlewares/validate.middleware';
import {
  listProfiles, createProfile, updateProfile, deleteProfile, applyProfile,
  createProfileSchema, updateProfileSchema,
} from '@/controllers/profile.controller';

const router = Router();

router.use(authMiddleware);

router.get   ('/',          listProfiles);
router.post  ('/',          validate(createProfileSchema), createProfile);
router.patch ('/:id',       validate(updateProfileSchema), updateProfile);
router.delete('/:id',       deleteProfile);
router.post  ('/:id/apply', applyProfile);

export default router;
