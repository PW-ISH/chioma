import { I18nService } from '../src/modules/i18n/i18n.service';
import { LoggerService } from '../src/common/services/logger.service';

const logger = new LoggerService(undefined, 'i18n-manage');

function run(): void {
  const i18n = new I18nService();
  const languages = i18n.getSupportedLanguages();

  logger.log('I18n Language Coverage Report');
  logger.log('============================');

  for (const language of languages) {
    const coverage = i18n.translationCoverage(language);
    logger.log(
      `${language}: ${coverage.percent}% (${coverage.translated}/${coverage.total})`,
    );
  }

  logger.log('Sample translation checks');
  logger.log(`en common.ok: ${i18n.t('common.ok', 'en')}`);
  logger.log(`fr common.ok: ${i18n.t('common.ok', 'fr')}`);
  logger.log(`es auth.loginSuccess: ${i18n.t('auth.loginSuccess', 'es')}`);
  logger.log(
    `ar security.accountLocked: ${i18n.t('security.accountLocked', 'ar')}`,
  );
}

run();
