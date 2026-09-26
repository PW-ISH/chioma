import eslint from '@eslint/js';

export default [
  eslint.configs.recommended,
  {
    rules: {
      'no-console': 'error',
    },
  },
];
