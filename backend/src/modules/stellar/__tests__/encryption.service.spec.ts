import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import {
  DecryptionError,
  DecryptionErrorType,
  EncryptionService,
} from '../services/encryption.service';

describe('EncryptionService', () => {
  let service: EncryptionService;

  const mockConfigService = {
    get: jest.fn().mockReturnValue({
      encryptionKey: 'test-encryption-key-for-testing-purposes',
    }),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EncryptionService,
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    service = module.get<EncryptionService>(EncryptionService);
  });

  describe('encrypt and decrypt', () => {
    it('should encrypt and decrypt a secret key correctly', () => {
      const originalSecret =
        'SABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUV';

      const encrypted = service.encrypt(originalSecret);
      expect(encrypted).toBeDefined();
      expect(encrypted).not.toBe(originalSecret);

      const decrypted = service.decrypt(encrypted);
      expect(decrypted).toBe(originalSecret);
    });

    it('should produce different ciphertext for same plaintext (due to random nonce)', () => {
      const secret = 'SABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUV';

      const encrypted1 = service.encrypt(secret);
      const encrypted2 = service.encrypt(secret);

      expect(encrypted1).not.toBe(encrypted2);

      // But both should decrypt to the same value
      expect(service.decrypt(encrypted1)).toBe(secret);
      expect(service.decrypt(encrypted2)).toBe(secret);
    });

    it('should throw an error for invalid encrypted data', () => {
      expect(() => service.decrypt('invalid-base64-data')).toThrow();
    });

    const decryptError = (data: string): DecryptionError => {
      try {
        service.decrypt(data);
      } catch (e) {
        return e as DecryptionError;
      }
      throw new Error('expected decrypt to throw');
    };

    it('reports CORRUPTED_DATA for malformed or truncated payloads', () => {
      expect(decryptError('not base64!').type).toBe(
        DecryptionErrorType.CORRUPTED_DATA,
      );
      expect(decryptError('AAAA').type).toBe(
        DecryptionErrorType.CORRUPTED_DATA,
      );
    });

    it('reports INVALID_KEY when the key fingerprint does not match', () => {
      const [v, , payload] = service.encrypt('secret').split('.');
      const err = decryptError(`${v}.deadbeef.${payload}`);
      expect(err).toBeInstanceOf(DecryptionError);
      expect(err.type).toBe(DecryptionErrorType.INVALID_KEY);
    });

    it('reports TAMPERING when ciphertext is modified', () => {
      const [v, fp, payload] = service.encrypt('secret').split('.');
      const bytes = Buffer.from(payload, 'base64');
      bytes[bytes.length - 1] ^= 0xff;
      const err = decryptError(`${v}.${fp}.${bytes.toString('base64')}`);
      expect(err.type).toBe(DecryptionErrorType.TAMPERING);
      expect(
        service.getDecryptionFailureMetrics()[DecryptionErrorType.TAMPERING],
      ).toBe(1);
    });

    it('should handle empty strings', () => {
      const encrypted = service.encrypt('');
      const decrypted = service.decrypt(encrypted);
      expect(decrypted).toBe('');
    });

    it('should handle special characters', () => {
      const secretWithSpecialChars = 'secret!@#$%^&*()_+-=[]{}|;:,.<>?';

      const encrypted = service.encrypt(secretWithSpecialChars);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(secretWithSpecialChars);
    });

    it('should handle unicode characters', () => {
      const unicodeSecret = '秘密🔐';

      const encrypted = service.encrypt(unicodeSecret);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(unicodeSecret);
    });
  });

  describe('isConfigured', () => {
    it('should return true when properly configured', () => {
      mockConfigService.get.mockReturnValue({
        encryptionKey: 'properly-configured-key',
      });

      const _module = Test.createTestingModule({
        providers: [
          EncryptionService,
          { provide: ConfigService, useValue: mockConfigService },
        ],
      });

      // Service is configured in beforeEach, so this should work
      expect(service.isConfigured()).toBe(true);
    });
  });
});
