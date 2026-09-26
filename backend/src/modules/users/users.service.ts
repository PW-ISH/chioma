import {
  Injectable,
  Logger,
  BadRequestException,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { createHash, randomBytes } from 'crypto';
import * as bcrypt from 'bcryptjs';
import { User } from './entities/user.entity';
import {
  UpdateUserProfileDto,
  ChangeEmailDto,
  ChangePasswordDto,
} from './dto/update-user.dto';
import { UserRestoreDto } from './dto/user-restore.dto';
import { KycStatus } from '../kyc/kyc-status.enum';
import { AuditService } from '../audit/audit.service';
import {
  DEFAULT_NOTIFICATION_PREFERENCES,
  UserPreferences,
  UserNotificationPreference,
} from './entities/user-notification-preference.entity';
import {
  AuditAction,
  AuditLevel,
  AuditStatus,
} from '../audit/entities/audit-log.entity';

const SALT_ROUNDS = 12;

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(UserNotificationPreference)
    private readonly userNotificationPreferenceRepository: Repository<UserNotificationPreference>,
    private readonly auditService: AuditService,
  ) {}

  async getNotificationPreferences(userId: string): Promise<UserPreferences> {
    const existing = await this.userNotificationPreferenceRepository.findOne({
      where: { userId },
    });

    if (!existing) {
      return DEFAULT_NOTIFICATION_PREFERENCES;
    }

    return this.mergePreferences(existing.preferences);
  }

  async updateNotificationPreferences(
    userId: string,
    preferences: UserPreferences,
  ): Promise<UserPreferences> {
    const nextPreferences = this.mergePreferences(preferences);
    let record = await this.userNotificationPreferenceRepository.findOne({
      where: { userId },
    });

    if (!record) {
      record = this.userNotificationPreferenceRepository.create({
        userId,
        preferences: nextPreferences,
      });
    } else {
      record.preferences = nextPreferences;
    }

    await this.userNotificationPreferenceRepository.save(record);
    return nextPreferences;
  }

  async exportUserData(
    userId: string,
  ): Promise<Omit<User, 'password'> & Record<string, unknown>> {
    const user = await this.findById(userId);
    const { password, ...exportData } = user;
    void password;
    await this.auditService.log({
      action: AuditAction.DATA_EXPORT,
      entityType: 'User',
      entityId: user.id,
      performedBy: user.id,
      status: AuditStatus.SUCCESS,
      level: AuditLevel.SECURITY,
      metadata: { type: 'GDPR_EXPORT' },
    });
    this.logger.log(`GDPR export for user: ${user.id}`);
    return exportData;
  }

  async gdprDeleteAccount(userId: string): Promise<{ message: string }> {
    const user = await this.findById(userId);
    const anonEmail = `deleted_${user.id}@anonymized.local`;
    user.email = anonEmail;
    user.firstName = null;
    user.lastName = null;
    user.phoneNumber = null;
    user.emailHash = this.hashLookupValue(anonEmail);
    user.phoneNumberHash = null;
    user.password = await bcrypt.hash(
      randomBytes(32).toString('hex'),
      SALT_ROUNDS,
    );
    user.isActive = false;
    user.refreshToken = null;
    await this.userRepository.save(user);
    await this.userRepository.softDelete(userId);
    await this.auditService.log({
      action: AuditAction.DELETE,
      entityType: 'User',
      entityId: userId,
      performedBy: userId,
      status: AuditStatus.SUCCESS,
      level: AuditLevel.SECURITY,
      metadata: { type: 'GDPR_DELETE' },
    });
    this.logger.log(`GDPR account deletion for user: ${userId}`);
    return { message: 'Account deleted and data anonymized (GDPR)' };
  }

  async updateConsent(
    userId: string,
    consent: Record<string, unknown>,
  ): Promise<{ message: string }> {
    const user = await this.findById(userId);
    if (typeof consent.emailNotifications === 'boolean') {
      user.emailNotifications = consent.emailNotifications;
    }
    if (typeof consent.smsNotifications === 'boolean') {
      user.smsNotifications = consent.smsNotifications;
    }
    if (typeof consent.marketingOptIn === 'boolean') {
      user.marketingOptIn = consent.marketingOptIn;
    }
    await this.userRepository.save(user);
    await this.auditService.log({
      action: AuditAction.UPDATE,
      entityType: 'User',
      entityId: user.id,
      performedBy: user.id,
      status: AuditStatus.SUCCESS,
      level: AuditLevel.SECURITY,
      metadata: { type: 'GDPR_CONSENT', consent },
    });
    this.logger.log(`Consent updated for user: ${user.id}`);
    return { message: 'Consent updated' };
  }

  async getPrivacySettings(userId: string): Promise<{
    emailNotifications: boolean;
    smsNotifications: boolean;
    marketingOptIn: boolean;
    dataRetention: string;
  }> {
    const user = await this.findById(userId);
    return {
      emailNotifications: user.emailNotifications,
      smsNotifications: user.smsNotifications,
      marketingOptIn: user.marketingOptIn,
      dataRetention: 'standard',
    };
  }

  async findByEmail(email: string): Promise<User | null> {
    const normalizedEmail = email.trim().toLowerCase();
    const emailHash = this.hashLookupValue(normalizedEmail);
    return this.userRepository.findOne({
      where: [{ email: normalizedEmail }, { emailHash }],
    });
  }

  async updateProfile(
    userId: string,
    updateProfileDto: UpdateUserProfileDto,
  ): Promise<User> {
    const user = await this.findById(userId);
    Object.assign(user, updateProfileDto);
    if (updateProfileDto.phoneNumber !== undefined) {
      user.phoneNumberHash = updateProfileDto.phoneNumber
        ? this.hashLookupValue(updateProfileDto.phoneNumber)
        : null;
    }
    const updatedUser = await this.userRepository.save(user);
    this.logger.log(`Profile updated for user: ${user.email}`);
    return updatedUser;
  }

  async changeEmail(
    userId: string,
    changeEmailDto: ChangeEmailDto,
  ): Promise<{ message: string }> {
    const user = await this.findById(userId);

    const isPasswordValid = await bcrypt.compare(
      changeEmailDto.currentPassword,
      user.password,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    const normalizedNew = changeEmailDto.newEmail.trim().toLowerCase();
    const existingUser = await this.findByEmail(normalizedNew);
    if (existingUser) {
      throw new BadRequestException('Email already in use');
    }

    const verificationToken = randomBytes(32).toString('hex');

    await this.userRepository.update(userId, {
      email: normalizedNew,
      emailHash: this.hashLookupValue(normalizedNew),
      emailVerified: false,
      verificationToken,
    });

    this.logger.log(
      `Email changed for user: ${user.id} from ${user.email} to ${normalizedNew}`,
    );

    return { message: 'Email updated. Please verify your new email address.' };
  }

  async changePassword(
    userId: string,
    changePasswordDto: ChangePasswordDto,
  ): Promise<{ message: string }> {
    const user = await this.findById(userId);

    const isPasswordValid = await bcrypt.compare(
      changePasswordDto.currentPassword,
      user.password,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    if (changePasswordDto.currentPassword === changePasswordDto.newPassword) {
      throw new BadRequestException(
        'New password must be different from current password',
      );
    }

    const hashedPassword = await bcrypt.hash(
      changePasswordDto.newPassword,
      SALT_ROUNDS,
    );

    await this.userRepository.update(userId, {
      password: hashedPassword,
      refreshToken: null,
    });

    this.logger.log(`Password changed for user: ${user.email}`);

    return { message: 'Password changed successfully. Please login again.' };
  }

  async deactivateAccount(userId: string): Promise<{ message: string }> {
    const user = await this.findById(userId);

    await this.userRepository.update(userId, {
      isActive: false,
      refreshToken: null,
    });

    this.logger.log(`Account deactivated for user: ${user.email}`);

    return { message: 'Account deactivated successfully' };
  }

  async deleteAccount(userId: string): Promise<{ message: string }> {
    const user = await this.findById(userId);
    await this.userRepository.softDelete(userId);
    this.logger.log(`Account soft-deleted for user: ${user.email}`);
    return { message: 'Account deleted successfully' };
  }

  async restoreAccount(
    userRestoreDto: UserRestoreDto,
  ): Promise<{ message: string }> {
    const { email, password } = userRestoreDto;
    const normalized = email.trim().toLowerCase();

    const user = await this.userRepository.findOne({
      where: [
        { email: normalized },
        { emailHash: this.hashLookupValue(normalized) },
      ],
      withDeleted: true,
    });

    if (!user) throw new NotFoundException('User not found');
    if (!user.deletedAt)
      throw new BadRequestException('Account is not deleted');

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      throw new UnauthorizedException('Invalid credentials');

    await this.userRepository.restore(user.id);
    await this.userRepository.update(user.id, { isActive: true });

    this.logger.log(`Account restored for user: ${user.email}`);

    return { message: 'Account restored successfully. You can now log in.' };
  }

  async hardDeleteAccount(userId: string): Promise<{ message: string }> {
    const user = await this.findById(userId, true);
    await this.userRepository.delete(userId);
    this.logger.log(`Account permanently deleted for user: ${user.email}`);
    return { message: 'Account permanently deleted' };
  }

  async getUserActivity(userId: string): Promise<{
    lastLogin: Date | null;
    accountCreated: Date;
    emailVerified: boolean;
    isActive: boolean;
  }> {
    const user = await this.findById(userId);
    return {
      lastLogin: user.lastLoginAt,
      accountCreated: user.createdAt,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
    };
  }

  async setKycStatus(userId: string, status: KycStatus): Promise<void> {
    await this.userRepository.update(userId, { kycStatus: status });
    this.logger.log(`KYC status updated for user ${userId}: ${status}`);
  }

  private async findById(userId: string, withDeleted = false): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      withDeleted,
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async getUserById(userId: string, withDeleted = false): Promise<User> {
    return this.findById(userId, withDeleted);
  }

  /**
   * Record that the user has completed email onboarding.
   * Idempotent — safe to call multiple times.
   */
  async markEmailCollected(userId: string): Promise<{ emailCollectedAt: Date }> {
    const user = await this.findById(userId);
    if (!user.emailCollectedAt) {
      user.emailCollectedAt = new Date();
      await this.userRepository.save(user);
      this.logger.log(`Email onboarding completed for user: ${userId}`);
    }
    return { emailCollectedAt: user.emailCollectedAt };
  }

  /**
   * Return whether the user has completed email onboarding.
   */
  async getEmailOnboardingStatus(
    userId: string,
  ): Promise<{ emailCollected: boolean; emailCollectedAt: Date | null }> {
    const user = await this.findById(userId);
    return {
      emailCollected: !!user.emailCollectedAt,
      emailCollectedAt: user.emailCollectedAt ?? null,
    };
  }

  private hashLookupValue(value: string): string {
    return createHash('sha256')
      .update(value.trim().toLowerCase())
      .digest('hex');
  }

  private mergePreferences(
    preferences: Partial<UserPreferences> | null | undefined,
  ): UserPreferences {
    return {
      notifications: {
        email: {
          newPropertyMatches:
            preferences?.notifications?.email?.newPropertyMatches ??
            DEFAULT_NOTIFICATION_PREFERENCES.notifications.email
              .newPropertyMatches,
          paymentReminders:
            preferences?.notifications?.email?.paymentReminders ??
            DEFAULT_NOTIFICATION_PREFERENCES.notifications.email
              .paymentReminders,
          maintenanceUpdates:
            preferences?.notifications?.email?.maintenanceUpdates ??
            DEFAULT_NOTIFICATION_PREFERENCES.notifications.email
              .maintenanceUpdates,
        },
        push: {
          newMessages:
            preferences?.notifications?.push?.newMessages ??
            DEFAULT_NOTIFICATION_PREFERENCES.notifications.push.newMessages,
          criticalAlerts:
            preferences?.notifications?.push?.criticalAlerts ??
            DEFAULT_NOTIFICATION_PREFERENCES.notifications.push.criticalAlerts,
        },
        inAppSummary:
          preferences?.notifications?.inAppSummary ??
          DEFAULT_NOTIFICATION_PREFERENCES.notifications.inAppSummary,
      },
      appearanceTheme:
        preferences?.appearanceTheme ??
        DEFAULT_NOTIFICATION_PREFERENCES.appearanceTheme,
      language:
        preferences?.language ?? DEFAULT_NOTIFICATION_PREFERENCES.language,
      currency:
        preferences?.currency ?? DEFAULT_NOTIFICATION_PREFERENCES.currency,
    };
  }
}
