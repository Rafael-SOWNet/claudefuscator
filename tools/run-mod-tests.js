'use strict';
/*
 * Runs `claude plugin validate` and `claude plugin test` for the mod.
 *
 * Exists to set CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1, which Claude Code
 * 2.1.288 requires before it will load a mod's hooks module at all - both
 * for `claude plugin test` and for `--plugin-dir`. The published docs say
 * v2.1.287+ ignores that variable; this build does not, and refuses with
 * "hooks modules are not turned on in this build yet (early access)".
 * Setting it here keeps the npm script honest on any shell.
 *
 * Drop this wrapper once the build stops asking for the flag.
 */

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const MOD = path.join(__dirname, '..', 'claude-mod');
const env = { ...process.env, CLAUDE_CODE_ENABLE_FUNCTION_HOOKS: '1' };

/*
 * Go through a shell with ONE pre-quoted command string, not an args array.
 * On Windows `claude` resolves to a `.cmd` shim that Node cannot spawn
 * directly (EINVAL), and passing an args array alongside `shell: true`
 * concatenates rather than escapes them, which Node warns about. Quoting the
 * one path that can contain spaces ourselves avoids both.
 */
const quoted = process.platform === 'win32' ? `"${MOD}"` : `'${MOD.replace(/'/g, "'\\''")}'`;

for (const sub of ['validate', 'test']) {
  const r = spawnSync(`claude plugin ${sub} ${quoted}`, { stdio: 'inherit', env, shell: true });
  if (r.error) {
    console.error(`could not run claude plugin ${sub}: ${r.error.message}`);
    process.exit(1);
  }
  if (r.status !== 0) process.exit(r.status === null ? 1 : r.status);
}
