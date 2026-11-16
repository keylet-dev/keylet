import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const KEYLET_SKILL_MD = `---
name: keylet
description: Manage Bitwarden / Vaultwarden secrets, TOTP codes, SSH keys, folders, vault imports, and zero-disk env injection via the keylet CLI. Use when a task needs credentials, API tokens, 2FA/TOTP codes, SSH signing, or running commands with injected environment variables.
---

# Keylet CLI Skill

Use \`keylet\` instead of storing or reading plaintext \`.env\` secrets on disk.

## Check Session First

\`\`\`bash
keylet auth status
\`\`\`

If locked, ask the user to unlock in their terminal (\`keylet auth unlock\`)—never ask the user to paste their Master Password into chat unless explicitly requested.

## Command Groups

### Auth & Session
\`\`\`bash
keylet auth login [--server <url>] [--email <email>] [--password-env <VAR>] [--2fa <code>]
keylet auth unlock [--password-env <VAR>]
keylet auth lock
keylet auth logout
keylet auth status
\`\`\`

### Items & TOTP
\`\`\`bash
keylet item list [--type login|note|card|ssh] [--format table|json|yaml] [--json-path <expr>] [query]
keylet item get <query> [--field password|username|totp|public|private|notes|all] [--json-path <expr>] [--json]
keylet item add --name <name> [--type login|note|ssh] [--username <u>] [--password <p>] [--uri <url>] [--totp <secret>] [--generate-ssh]
keylet item rm <query> [--permanent]
keylet item totp <query>
\`\`\`

### Folders
\`\`\`bash
keylet folder list [--format table|json|yaml] [--json-path <expr>]
keylet folder add <name>
keylet folder rm <nameOrId>
\`\`\`

### Vault Sync & Import
Supports Bitwarden JSON/CSV, 1Password \`.1pux\` / CSV / JSON, and Chrome/Edge CSV:
\`\`\`bash
keylet vault sync
keylet vault import <file.1pux|file.json|file.csv>
\`\`\`

### SSH Keys & In-Memory Agent
\`\`\`bash
keylet ssh add --name <name> --generate
keylet ssh list [--format table|json|yaml] [--json-path <expr>]
eval "$(keylet ssh agent)"
\`\`\`

### Zero-Disk Env Injection & Password Generation
\`\`\`bash
PGPASSWORD="keylet://Postgres/password" keylet run -- node app.js
keylet run --from "App Env" -- npm run dev
keylet generate --length 24 --avoid-ambiguous
\`\`\`

### Agent Skill Management
\`\`\`bash
keylet skills install [--global] [--dir <path>]
keylet skills show
keylet skills path [--global]
\`\`\`

## Security Rules

1. Never print, log, or commit decrypted passwords, private keys, or TOTP secrets into source files or terminal transcripts.
2. Prefer \`keylet run\` over writing secrets to \`.env\` files.
3. Lock the vault when finished (\`keylet auth lock\`).
`;

export function resolveSkillTargetDir(options: {
  dir?: string;
  global?: boolean;
  cwd?: string;
}): string {
  if (options.dir) {
    return path.resolve(options.dir, 'keylet');
  }
  if (options.global) {
    const antigravitySkills = path.join(
      os.homedir(),
      '.gemini',
      'antigravity-cli',
      'skills',
    );
    if (fs.existsSync(antigravitySkills)) {
      return path.join(antigravitySkills, 'keylet');
    }
    return path.join(os.homedir(), '.agents', 'skills', 'keylet');
  }
  return path.join(options.cwd ?? process.cwd(), '.agents', 'skills', 'keylet');
}

export function installSkill(options: {
  dir?: string;
  global?: boolean;
  cwd?: string;
}): string {
  const targetDir = resolveSkillTargetDir(options);
  fs.mkdirSync(targetDir, { recursive: true });
  const filePath = path.join(targetDir, 'SKILL.md');
  fs.writeFileSync(filePath, KEYLET_SKILL_MD, 'utf8');
  return filePath;
}
