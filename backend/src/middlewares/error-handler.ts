import { Request, Response, NextFunction } from 'express';
import { Prisma } from '@prisma/client';
import { AppError } from '@/utils/errors';

export function errorHandler(err: Error, _req: Request, res: Response, _next: NextFunction): void {
  // Erreur métier attendue
  if (err instanceof AppError && err.isOperational) {
    res.status(err.statusCode).json({ success: false, message: err.message });
    return;
  }

  // Contrainte d'unicité Prisma (P2002)
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
    res.status(409).json({ success: false, message: 'Cette ressource existe déjà' });
    return;
  }

  // Enregistrement introuvable Prisma (P2025)
  if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2025') {
    res.status(404).json({ success: false, message: 'Ressource introuvable' });
    return;
  }

  // Erreur inattendue — loggée mais masquée en production
  console.error('[ERREUR INTERNE]', err);
  res.status(500).json({ success: false, message: 'Erreur interne du serveur' });
}
