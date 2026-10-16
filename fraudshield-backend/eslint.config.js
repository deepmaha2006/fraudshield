// ESLint flat config: correctness + Node/browser security rules.
const js = require('@eslint/js');
const security = require('eslint-plugin-security');
const globals = require('globals');

const hardening = {
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
    'no-script-url': 'error',
    'no-proto': 'error',
    'no-unused-vars': ['error', { args: 'none', caughtErrors: 'none' }],
};

module.exports = [
    { ignores: ['node_modules/**', 'data/**', 'backups/**', 'coverage/**'] },
    js.configs.recommended,
    security.configs.recommended,
    {
        files: ['**/*.js'],
        languageOptions: { ecmaVersion: 2024, sourceType: 'commonjs', globals: { ...globals.node } },
        rules: {
            ...hardening,
            // Dynamic property access on internal lookup tables is pervasive and safe here;
            // user-controlled keys are validated before use. Reviewed: see SECURITY_AUDIT.md.
            'security/detect-object-injection': 'off',
        },
    },
    {
        // Classic scripts sharing a few page-level namespaces (FS, Report, Drawer) defined by core/report/drawer.js.
        files: ['public/js/**/*.js'],
        languageOptions: { sourceType: 'script', globals: { ...globals.browser, FS: 'readonly', Report: 'readonly', Drawer: 'readonly', Chart: 'readonly' } },
        rules: {
            'no-redeclare': ['error', { builtinGlobals: false }],
            'no-unused-vars': ['error', { args: 'none', caughtErrors: 'none', varsIgnorePattern: '^(FS|Report|Drawer)$' }],
        },
    },
    {
        files: ['public/sw.js'],
        languageOptions: { sourceType: 'script', globals: { ...globals.serviceworker } },
    },
    {
        // Operator CLI scripts take paths from the operator by design.
        files: ['scripts/**/*.js'],
        rules: { 'security/detect-non-literal-fs-filename': 'off' },
    },
    {
        files: ['tests/**/*.js'],
        rules: { 'security/detect-non-literal-fs-filename': 'off', 'security/detect-child-process': 'off', 'no-script-url': 'off' },
    },
];
