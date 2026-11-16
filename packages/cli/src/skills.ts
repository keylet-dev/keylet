import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const KEYLET_SKILL_MD = `---
name: keylet
description: Manage Bitwarden / Vaultwarden secrets, TOTP codes, SSH keys, and zero-disk env injection via the keylet CLI. Use when a task needs credentials, API tokens, 2FA/TOTP codes, SSH signing, or running commands with injected environment variables.
---

# Keylet CLI Skill

Use \`keylet\` instead of storing or reading plaintext \`.env\` secrets on disk.

## Check Session First

\`\`\`bash
keylet auth status
\`\`\`

If locked, ask the user to unlock in their terminal (\`keylet auth unlock\`) or provide a session—never ask the user to paste their Master Password into chat unless explicitly requested.

## Common Workflows

- **Inject secrets into a subprocess (preferred)**:
  \`\`\`bash
  PGPASSWORD="keylet://Postgres/password" keylet run -- node app.js
  keylet run --from "App Env" -- npm run dev
  \`\`\`
- **Search / list items**:
  \`\`\`bash
  keylet item list --type login
  keylet item list --json <query>
  \`\`\`
- **Read a single field or TOTP**:
  \`\`\`bash
  keylet item get <query> --field username
  keylet item get <query> --field password
  keylet item totp <query>
  \`\`\`
- **Generate a strong password**:
  \`\`\`bash
  keylet generate --length 24 --avoid-ambiguous
  \`\`\`
- **SSH keys & in-memory agent**:
  \`\`\`bash
  keylet ssh list
  eval "$(keylet ssh agent)"
  \`\`\`
- **Import / Sync**:
  \`\`\`bash
  keylet vault sync
  keylet vault import <file.1pux|file.json|file.csv>
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
