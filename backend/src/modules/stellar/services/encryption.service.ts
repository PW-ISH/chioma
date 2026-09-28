import { Injectable, Logger, OnModuleInit, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { HttpStatus } from '@nestjs/common';
import * as nacl from 'tweetnacl';
import { StellarConfig } from '../config/stellar.config';
import { ConfigurationError, BaseAppError, ErrorCode } from '../../../common/errors';
import { MetricsService } from '../../monitoring/metrics.service';

// ── Structured decryption error ──────────────────────────────────────────────

/** Discriminator for the root cause of a decryption failure. */
export type DecryptionFailureReason =
  | 'INVALID_FORMAT'   // base64 parse failed or payload too short to contain nonce
  | 'INVALID_KEY'      // key material is confirmed wrong (startup self-test path)
  | 'CORRUPTED_DATA'   // payload is well-formed but MAC verification failed
  | 'TAMPERING';       // structurally valid, full-length payload, MAC failed → likely tamper

export class DecryptionError extends BaseAppError {
  public readonly reason: DecryptionFailureReason;

  constructor(reason: DecryptionFailureReason, context?: Record<string, unknown>) {
    const messages: Record<DecryptionFailureReason, string> = {
      INVALID_FORMAT:  'Decryption failed: malformed or truncated ciphertext',
      INVALID_KEY:     'Decryption failed: incorrect encryption key',
      CORRUPTED_DATA:  'Decryption failed: ciphertext is corrupted',
      TAMPERING:       'Decryption failed: authentication tag mismatch — possible tampering',
    };
    super(
      ErrorCode.DECRYPTION_ERROR,
      HttpStatus.BAD_REQUEST,
      messages[reason],
      true,
      { reason, ...context },
    );
    this.reason = reason;
  }
}

/** Minimum length (chars) accepted for a raw encryption key string. */
const MIN_KEY_LENGTH = 32;

/** Sentinel value shipped in `stellar.config.ts` as the default. */
const DEFAULT_PLACEHOLDER = 'default-encryption-key-change-in-production';

@Injectable()
export class EncryptionService implements OnModuleInit {
  private readonly logger = new Logger(EncryptionService.name);
  private readonly encryptionKey: Uint8Array;

  /**
   * True when the key passed all validation checks at construction time.
   * Stored so that `isKeyValid()` and the health indicator can read it cheaply.
   */
  private readonly keyValid: boolean;

  /**
   * Human-readable reason the key failed validation, or `null` when valid.
   * Surfaced in health-check details without exposing key material.
   */
  private readonly keyInvalidReason: string | null;

  constructor(
    private readonly configService: ConfigService,
    @Optional() private readonly metricsService?: MetricsService,
  ) {
    const keyString =
      this.configService.get<StellarConfig>('stellar')?.encryptionKey ?? '';

    const { valid, reason } = EncryptionService.validateKeyString(keyString);
    this.keyValid = valid;
    this.keyInvalidReason = reason;

    // Always derive the key so the rest of the class stays consistent; runtime
    // operations throw immediately if keyValid is false.
    this.encryptionKey = this.deriveKey(keyString);

    if (!valid) {
      this.logger.error(
        `EncryptionService key validation failed: ${reason}. ` +
          'Encryption and decryption operations will throw until a valid key is configured.',
      );
    }
  }

  /**
   * NestJS lifecycle hook — runs after DI wiring is complete.
   * Throws `ConfigurationError` so the application refuses to start when the
   * key is absent or using the shipped placeholder.
   */
  onModuleInit(): void {
    if (!this.keyValid) {
      throw new ConfigurationError(
        `EncryptionService cannot start: ${this.keyInvalidReason}. ` +
          'Set STELLAR_ENCRYPTION_KEY to a random string of at least ' +
          `${MIN_KEY_LENGTH} characters before starting the application.`,
      );
    }

    // Perform a live round-trip to confirm the derived key material actually
    // works — catches encoding edge-cases that static checks miss.
    try {
      this.performRoundTrip();
    } catch (err) {
      throw new ConfigurationError(
        'EncryptionService round-trip self-test failed at startup. ' +
          'The configured key cannot encrypt/decrypt correctly. ' +
          `Underlying error: ${(err as Error).message}`,
      );
    }

    this.logger.log('EncryptionService key validation passed.');
  }

  // ── Public helpers for the health indicator ────────────────────────────────

  /**
   * Returns whether the key passed static validation at construction time.
   * Does NOT re-read from config — this is intentionally cheap.
   */
  isKeyValid(): boolean {
    return this.keyValid;
  }

  /**
   * Returns the validation failure reason, or `null` when the key is valid.
   * Safe to include in health-check payloads (contains no key material).
   */
  getKeyInvalidReason(): string | null {
    return this.keyInvalidReason;
  }

  /**
   * Performs a live encrypt → decrypt round-trip with a fixed test string.
   * Returns `true` on success; throws on any failure so callers can decide
   * whether to surface a hard error or a degraded warning.
   *
   * Used by `EncryptionHealthIndicator` and `onModuleInit`.
   */
  testRoundTrip(): true {
    this.assertKeyValid();
    return this.performRoundTrip();
  }

  // ── Core encrypt / decrypt ────────────────────────────────────────────────

  /**
   * Encrypts a secret key using NaCl secretbox.
   * @param secretKey - The secret key to encrypt
   * @returns Encrypted data as base64 string (nonce + ciphertext)
   */
  encrypt(secretKey: string): string {
    this.assertKeyValid();

    try {
      const encoder = new TextEncoder();
      const messageUint8 = encoder.encode(secretKey);

      // Generate a random nonce
      const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);

      // Encrypt the message
      const ciphertext = nacl.secretbox(
        messageUint8,
        nonce,
        this.encryptionKey,
      );

      if (!ciphertext) {
        throw new Error('Encryption failed');
      }

      // Combine nonce and ciphertext
      const combined = new Uint8Array(nonce.length + ciphertext.length);
      combined.set(nonce);
      combined.set(ciphertext, nonce.length);

      // Return as base64
      return Buffer.from(combined).toString('base64');
    } catch (error) {
      this.logger.error('Encryption failed', error);
      throw new Error('Failed to encrypt secret key');
    }
  }

  /**
   * Decrypts an encrypted secret key.
   * @param encryptedData - Base64 encoded encrypted data (nonce + ciphertext)
   * @returns Decrypted secret key
   * @throws {DecryptionError} with a discriminated `reason` field
   */
  decrypt(encryptedData: string): string {
    this.assertKeyValid();

    // ── 1. Parse & structural validation ──────────────────────────────────
    let combined: Buffer;
    try {
      combined = Buffer.from(encryptedData, 'base64');
    } catch {
      this.recordDecryptionFailure('INVALID_FORMAT');
      throw new DecryptionError('INVALID_FORMAT', { hint: 'base64 decode failed' });
    }

    if (combined.length <= nacl.secretbox.nonceLength) {
      this.recordDecryptionFailure('INVALID_FORMAT');
      throw new DecryptionError('INVALID_FORMAT', {
        hint: `payload length ${combined.length} ≤ nonce length ${nacl.secretbox.nonceLength}`,
      });
    }

    // ── 2. Extract nonce + ciphertext ──────────────────────────────────────
    const nonce = new Uint8Array(combined.buffer, combined.byteOffset, nacl.secretbox.nonceLength);
    const ciphertext = new Uint8Array(
      combined.buffer,
      combined.byteOffset + nacl.secretbox.nonceLength,
      combined.length - nacl.secretbox.nonceLength,
    );

    // ── 3. Attempt authenticated decryption ────────────────────────────────
    let decrypted: Uint8Array | null;
    try {
      decrypted = nacl.secretbox.open(ciphertext, nonce, this.encryptionKey);
    } catch (err) {
      // nacl itself threw — treat as corrupted
      this.recordDecryptionFailure('CORRUPTED_DATA');
      this.logger.error('nacl.secretbox.open threw unexpectedly', err);
      throw new DecryptionError('CORRUPTED_DATA', { hint: 'nacl threw during open' });
    }

    if (decrypted === null) {
      // NaCl Poly1305 MAC failure. Structurally valid payloads (correct length,
      // proper nonce) that fail MAC are most likely tampered; undersized or
      // truncated ciphertext sections indicate corruption.
      const minCiphertextLen = nacl.secretbox.overheadLength; // 16-byte tag minimum
      const reason: DecryptionFailureReason =
        ciphertext.length >= minCiphertextLen ? 'TAMPERING' : 'CORRUPTED_DATA';

      this.recordDecryptionFailure(reason);
      this.logger.warn(
        `Decryption MAC failure — classified as ${reason}. ` +
          `ciphertextLen=${ciphertext.length}, minExpected=${minCiphertextLen}`,
      );
      throw new DecryptionError(reason);
    }

    return new TextDecoder().decode(decrypted);
  }

  /**
   * Securely wipes a string from memory by overwriting it.
   * Note: JavaScript doesn't guarantee immediate garbage collection,
   * but this helps minimize exposure time.
   */
  secureWipe(_data: string): void {
    // In JavaScript, we can't truly wipe memory, but we can minimize exposure
    // by letting the variable go out of scope and be garbage collected.
    // This method is here for API completeness and to encourage good practices.
  }

  /**
   * Validates that the encryption service is properly configured.
   * @deprecated Prefer `isKeyValid()` which is evaluated once at construction
   *   time rather than re-reading config on every call.
   */
  isConfigured(): boolean {
    const keyString =
      this.configService.get<StellarConfig>('stellar')?.encryptionKey;
    return (
      !!keyString && keyString !== DEFAULT_PLACEHOLDER
    );
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  /**
   * Validates a raw key string before derivation.
   * Returns a `{ valid, reason }` tuple so both constructor and tests can
   * inspect the outcome without throwing.
   */
  static validateKeyString(keyString: string): {
    valid: boolean;
    reason: string | null;
  } {
    if (!keyString) {
      return { valid: false, reason: 'STELLAR_ENCRYPTION_KEY is not set' };
    }
    if (keyString === DEFAULT_PLACEHOLDER) {
      return {
        valid: false,
        reason:
          'STELLAR_ENCRYPTION_KEY is using the default placeholder value — ' +
          'replace it with a secret random string before deploying',
      };
    }
    if (keyString.length < MIN_KEY_LENGTH) {
      return {
        valid: false,
        reason:
          `STELLAR_ENCRYPTION_KEY is too short (${keyString.length} chars); ` +
          `minimum is ${MIN_KEY_LENGTH} characters`,
      };
    }
    return { valid: true, reason: null };
  }

  /**
   * Throws `ConfigurationError` when the key failed validation.
   * Called at the top of every operation that needs a working key.
   */
  private assertKeyValid(): void {
    if (!this.keyValid) {
      throw new ConfigurationError(
        `EncryptionService operation rejected: ${this.keyInvalidReason}`,
      );
    }
  }

  /**
   * Encrypts and immediately decrypts a known test string to confirm that the
   * derived key material is self-consistent.  Throws if the result does not
   * match the original.
   */
  private performRoundTrip(): true {
    const testPlaintext = 'encryption-self-test-chioma';
    const encrypted = this.encrypt(testPlaintext);
    const decrypted = this.decrypt(encrypted);

    if (decrypted !== testPlaintext) {
      throw new Error(
        `Round-trip produced "${decrypted}" instead of "${testPlaintext}"`,
      );
    }
    return true;
  }

  /**
   * Derives a 32-byte key from a string using SHA-512 (via NaCl) and
   * truncating to the secretbox key length.
   */
  private deriveKey(keyString: string): Uint8Array {
    const encoder = new TextEncoder();
    const hash = nacl.hash(encoder.encode(keyString));
    return hash.slice(0, nacl.secretbox.keyLength);
  }

  /** Records a decryption failure metric and logs a warning. */
  private recordDecryptionFailure(reason: DecryptionFailureReason): void {
    this.metricsService?.recordDecryptionFailure(reason);
    this.logger.warn(`Decryption failure: ${reason}`);
  }
}
