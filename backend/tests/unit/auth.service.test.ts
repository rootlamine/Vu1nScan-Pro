import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthService } from '@/services/auth.service';

// vi.hoisted garantit que l'objet est créé avant le hoist de vi.mock
const mockRepo = vi.hoisted(() => ({
  findByEmail:    vi.fn(),
  findByUsername: vi.fn(),
  findById:       vi.fn(),
  create:         vi.fn(),
  updateProfile:  vi.fn(),
  updatePassword: vi.fn(),
}));

vi.mock('@/repositories/user.repository', () => ({
  UserRepository: vi.fn().mockImplementation(() => mockRepo),
}));

vi.mock('@/utils/config', () => ({
  config: {
    JWT_SECRET:     'test_secret_minimum_32_characters_ok',
    JWT_EXPIRES_IN: '1h',
  },
}));

vi.mock('@/services/permission.service', () => ({
  PermissionService: vi.fn().mockImplementation(() => ({
    createDefaultPermissions: vi.fn().mockResolvedValue(undefined),
    checkScanPermissions:     vi.fn().mockResolvedValue(undefined),
    getPermissions:           vi.fn().mockResolvedValue({ blockedModules: [] }),
  })),
}));

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new AuthService();
  });

  describe('register', () => {
    it('crée un utilisateur et retourne un token', async () => {
      mockRepo.findByEmail.mockResolvedValue(null);
      mockRepo.findByUsername.mockResolvedValue(null);
      mockRepo.create.mockResolvedValue({
        id: 'uuid-1', username: 'alice', email: 'alice@test.com',
        passwordHash: 'hashed', role: 'USER', isActive: true,
        createdAt: new Date(), updatedAt: new Date(),
      });

      const result = await service.register({
        username: 'alice', email: 'alice@test.com', password: 'Alice@2026',
      });

      expect(result.token).toBeDefined();
      expect(result.user.email).toBe('alice@test.com');
      expect((result.user as { passwordHash?: string }).passwordHash).toBeUndefined();
    });

    it('lance AppError 409 si email déjà utilisé', async () => {
      mockRepo.findByEmail.mockResolvedValue({ id: 'existing' });

      await expect(
        service.register({ username: 'alice', email: 'alice@test.com', password: 'Alice@2026' }),
      ).rejects.toMatchObject({ statusCode: 409 });
    });
  });

  describe('login', () => {
    it('retourne un token pour des identifiants valides', async () => {
      const bcrypt = await import('bcryptjs');
      const hash   = await bcrypt.hash('Alice@2026', 10);

      mockRepo.findByEmail.mockResolvedValue({
        id: 'uuid-1', username: 'alice', email: 'alice@test.com',
        passwordHash: hash, role: 'USER', isActive: true,
        createdAt: new Date(), updatedAt: new Date(),
      });

      const result = await service.login({ email: 'alice@test.com', password: 'Alice@2026' });
      expect(result.token).toBeDefined();
    });

    it('lance AppError 401 si mot de passe incorrect', async () => {
      const bcrypt = await import('bcryptjs');
      const hash   = await bcrypt.hash('correct', 10);
      mockRepo.findByEmail.mockResolvedValue({
        id: 'uuid-1', email: 'alice@test.com', passwordHash: hash, isActive: true,
      });

      await expect(
        service.login({ email: 'alice@test.com', password: 'wrong' }),
      ).rejects.toMatchObject({ statusCode: 401 });
    });

    it('lance AppError 401 si utilisateur introuvable', async () => {
      mockRepo.findByEmail.mockResolvedValue(null);

      await expect(
        service.login({ email: 'nobody@test.com', password: 'pass' }),
      ).rejects.toMatchObject({ statusCode: 401 });
    });
  });
});
