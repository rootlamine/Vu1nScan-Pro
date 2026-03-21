import { User } from '@prisma/client';
import { prisma } from '@/utils/prisma';
import { IUserRepository } from '@/domain/interfaces';
import { CreateUserDTO, UpdateProfileDTO } from '@/domain/types';

export class UserRepository implements IUserRepository {
  async findById(id: string): Promise<User | null> {
    return prisma.user.findUnique({ where: { id } });
  }

  async findByEmail(email: string): Promise<User | null> {
    return prisma.user.findUnique({ where: { email } });
  }

  async findByUsername(username: string): Promise<User | null> {
    return prisma.user.findUnique({ where: { username } });
  }

  async create(dto: Omit<CreateUserDTO, 'password'> & { passwordHash: string }): Promise<User> {
    return prisma.user.create({
      data: {
        username: dto.username,
        email:    dto.email,
        passwordHash: dto.passwordHash,
      },
    });
  }

  async updateProfile(id: string, data: UpdateProfileDTO): Promise<User> {
    return prisma.user.update({ where: { id }, data });
  }

  async updatePassword(id: string, passwordHash: string): Promise<User> {
    return prisma.user.update({ where: { id }, data: { passwordHash } });
  }
}
