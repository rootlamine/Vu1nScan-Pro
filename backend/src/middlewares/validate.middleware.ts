import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';

export function validate(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (err) {
      if (err instanceof ZodError) {
        res.status(422).json({
          success: false,
          message: 'Données invalides',
          errors: err.errors.map(e => ({ field: e.path.join('.'), message: e.message })),
        });
        return;
      }
      next(err);
    }
  };
}
