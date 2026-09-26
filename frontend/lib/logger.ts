/**
 * Thin logger wrapper for frontend code.
 * Suppresses output in production to avoid information disclosure.
 */

const isDev = process.env.NODE_ENV !== 'production';

export const logger = {
  log: (message: string, ...args: unknown[]): void => {
    if (isDev) console.log(`[chioma] ${message}`, ...args);
  },
  warn: (message: string, ...args: unknown[]): void => {
    if (isDev) console.warn(`[chioma:warn] ${message}`, ...args);
  },
  error: (message: string, ...args: unknown[]): void => {
    // Always log errors, even in production, but without sensitive detail
    console.error(`[chioma:error] ${message}`, ...(isDev ? args : []));
  },
};
