import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { User } from '@prisma/client';
import { UserRepository } from '@/repositories/user.repository';
import { AppError } from '@/utils/errors';
import { config } from '@/utils/config';
import {
  CreateUserDTO, LoginDTO, UpdateProfileDTO,
  ChangePasswordDTO, JwtPayload,
} from '@/domain/types';

const userRepo = new UserRepository();

type SafeUser = Omit<User, 'passwordHash'>;

function stripHash(user: User): SafeUser {
  const { passwordHash: _, ...safe } = user;
  return safe;
}

export class AuthService {
  async register(dto: CreateUserDTO): Promise<{ token: string; user: SafeUser }> {
    const [byEmail, byUsername] = await Promise.all([
      userRepo.findByEmail(dto.email),
      userRepo.findByUsername(dto.username),
    ]);
    if (byEmail)    throw new AppError("Cet email est déjà utilisé", 409);
    if (byUsername) throw new AppError("Ce nom d'utilisateur est déjà pris", 409);

    const passwordHash = await bcrypt.hash(dto.password, 10);
    const user = await userRepo.create({ username: dto.username, email: dto.email, passwordHash });
    return { token: this.signToken(user), user: stripHash(user) };
  }

  async login(dto: LoginDTO): Promise<{ token: string; user: SafeUser }> {
    const user = await userRepo.findByEmail(dto.email);
    if (!user) throw new AppError('Email ou mot de passe incorrect', 401);
    if (!user.isActive) throw new AppError('Compte désactivé', 403);

    const valid = await bcrypt.compare(dto.password, user.passwordHash);
    if (!valid) throw new AppError('Email ou mot de passe incorrect', 401);

    return { token: this.signToken(user), user: stripHash(user) };
  }

  async me(userId: string): Promise<SafeUser> {
    const user = await userRepo.findById(userId);
    if (!user) throw new AppError('Utilisateur introuvable', 404);
    return stripHash(user);
  }

  async updateProfile(userId: string, dto: UpdateProfileDTO): Promise<SafeUser> {
    if (dto.email) {
      const existing = await userRepo.findByEmail(dto.email);
      if (existing && existing.id !== userId)
        throw new AppError('Cet email est déjà utilisé', 409);
    }
    if (dto.username) {
      const existing = await userRepo.findByUsername(dto.username);
      if (existing && existing.id !== userId)
        throw new AppError("Ce nom d'utilisateur est déjà pris", 409);
    }
    const user = await userRepo.updateProfile(userId, dto);
    return stripHash(user);
  }

  async changePassword(userId: string, dto: ChangePasswordDTO): Promise<void> {
    const user = await userRepo.findById(userId);
    if (!user) throw new AppError('Utilisateur introuvable', 404);

    const valid = await bcrypt.compare(dto.currentPassword, user.passwordHash);
    if (!valid) throw new AppError('Mot de passe actuel incorrect', 401);

    const newHash = await bcrypt.hash(dto.newPassword, 10);
    await userRepo.updatePassword(userId, newHash);
  }

  private signToken(user: User): string {
    const payload: JwtPayload = { userId: user.id, email: user.email, role: user.role };
    return jwt.sign(payload, config.JWT_SECRET, { expiresIn: config.JWT_EXPIRES_IN } as jwt.SignOptions);
  }
}
