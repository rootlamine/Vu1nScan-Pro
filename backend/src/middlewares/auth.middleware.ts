import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '@/utils/config';
import { AppError } from '@/utils/errors';
import { JwtPayload } from '@/domain/types';

declare global {
  namespace Express {
    interface Request {
      user?: JwtPayload;
    }
  }
}

export function authMiddleware(req: Request, _res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return next(new AppError("Token d'authentification manquant", 401));
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, config.JWT_SECRET) as JwtPayload;
    req.user = payload;
    next();
  } catch {
    next(new AppError('Token invalide ou expiré', 401));
  }
}
