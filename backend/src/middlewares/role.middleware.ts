import { Request, Response, NextFunction } from 'express';
import { Role } from '@prisma/client';
import { AppError } from '@/utils/errors';

export function requireRole(role: Role) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.user) return next(new AppError('Non authentifié', 401));
    if (req.user.role !== role) return next(new AppError('Accès refusé — droits insuffisants', 403));
    next();
  };
}
