// The "what the suffix definition matches" examples, written ONCE for
// every test that pins a consumer of src/protected-names.ts to it: the baseline
// `secret.bash` reference rows (tests/secret-rules.test.ts) and the env-value
// detector (tests/env-value-rules.test.ts) both run over these same names, so a
// change to one definition that the other does not follow fails a test.
//
// The name definition: a name equal to, or ending in `_` plus, one of TOKEN PASSWORD
// PASSWD SECRET API_KEY APIKEY PRIVATE_KEY ACCESS_KEY CREDENTIALS.
export const PROTECTED_NAMES = [
  'TOKEN',
  'GITHUB_TOKEN',
  'ATLASSIAN_TOKEN',
  'SONARQUBE_TOKEN',
  'DEV_DB_PASSWORD',
  'DB_PASSWD',
  'STRIPE_API_KEY',
  'APIKEY',
  'MY_APIKEY',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_ACCESS_KEY',
  'ANTHROPIC_API_KEY',
  'SSH_PRIVATE_KEY',
  'GOOGLE_CREDENTIALS',
  'CLIENT_SECRET',
];

export const UNPROTECTED_NAMES = [
  'NODE_ENV',
  'HOME',
  'PATH',
  'CLAUDE_CONFIG_DIR',
  'TOKENIZER_PATH',
  'MY_TOKEN_FILE',
  'TOKENS',
  'MYTOKEN',
  'SECRET_KEY',
  'DB_PASS',
  'GPG_PASSPHRASE',
  'github_token',
  'Api_Token',
];
