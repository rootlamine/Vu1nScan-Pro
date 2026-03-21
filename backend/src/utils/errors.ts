export class AppError extends Error {
  public readonly statusCode: number;
  public readonly isOperational: boolean;

  constructor(message: string, statusCode: number, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Object.setPrototypeOf(this, new.target.prototype);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    if ((Error as any).captureStackTrace) (Error as any).captureStackTrace(this, this.constructor);
  }
}
