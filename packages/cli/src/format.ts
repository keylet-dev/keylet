export type OutputFormat = 'table' | 'json' | 'yaml';

export function resolveOutputFormat(
  args: string[],
  defaultFormat: OutputFormat = 'table',
): OutputFormat {
  if (args.includes('--json')) return 'json';
  const idx = args.indexOf('--format');
  if (idx !== -1 && idx + 1 < args.length) {
    const raw = args[idx + 1]!.toLowerCase();
    if (raw === 'table' || raw === 'json' || raw === 'yaml') return raw;
    throw new Error(`Invalid format "${raw}". Expected table, json, or yaml.`);
  }
  return defaultFormat;
}

function truncate(val: string, max: number): string {
  if (val.length <= max) return val;
  return max > 1 ? val.slice(0, max - 1) + '…' : val.slice(0, max);
}

export interface TableColumn<T> {
  header: string;
  maxWidth?: number;
  value: (row: T) => string;
}

export function renderTable<T>(rows: T[], columns: TableColumn<T>[]): string {
  if (rows.length === 0) return '(empty)';

  const matrix = rows.map((row) =>
    columns.map((col) => {
      const raw = col.value(row).replace(/[\r\n]+/g, ' ');
      return col.maxWidth ? truncate(raw, col.maxWidth) : raw;
    }),
  );

  const widths = columns.map((col, colIdx) => {
    const maxData = matrix.reduce(
      (m, r) => Math.max(m, r[colIdx]?.length ?? 0),
      0,
    );
    return Math.max(col.header.length, maxData);
  });

  const formatRow = (cells: string[]) =>
    cells
      .map((cell, i) => cell.padEnd(widths[i] ?? cell.length))
      .join('  ')
      .trimEnd();

  const headerLine = formatRow(columns.map((c) => c.header));
  const sepLine = widths.map((w) => '-'.repeat(w)).join('  ');
  const bodyLines = matrix.map((r) => formatRow(r));

  return [headerLine, sepLine, ...bodyLines].join('\n');
}

function yamlScalar(val: unknown): string {
  if (val === null || val === undefined) return 'null';
  if (typeof val === 'number' || typeof val === 'boolean') return String(val);
  const str = String(val);
  if (
    str === '' ||
    /[:#\-\[\]\{\},&\*!|>'"%@`\n\r]/.test(str) ||
    /^(true|false|null|~|\d+(\.\d+)?)$/i.test(str) ||
    str.trim() !== str
  ) {
    return JSON.stringify(str);
  }
  return str;
}

export function toYaml(value: unknown, indent = 0): string {
  const pad = '  '.repeat(indent);
  if (Array.isArray(value)) {
    if (value.length === 0) return `${pad}[]`;
    return value
      .map((item) => {
        if (item !== null && typeof item === 'object') {
          const inner = toYaml(item, indent + 1).trimStart();
          return `${pad}- ${inner}`;
        }
        return `${pad}- ${yamlScalar(item)}`;
      })
      .join('\n');
  }
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).filter(
      ([, v]) => v !== undefined,
    );
    if (entries.length === 0) return `${pad}{}`;
    return entries
      .map(([k, v]) => {
        if (v !== null && typeof v === 'object') {
          if (Array.isArray(v) && v.length === 0) return `${pad}${k}: []`;
          if (!Array.isArray(v) && Object.keys(v).length === 0) {
            return `${pad}${k}: {}`;
          }
          return `${pad}${k}:\n${toYaml(v, indent + 1)}`;
        }
        return `${pad}${k}: ${yamlScalar(v)}`;
      })
      .join('\n');
  }
  return `${pad}${yamlScalar(value)}`;
}

type JsonPathToken =
  | { type: 'prop'; key: string }
  | { type: 'index'; idx: number }
  | { type: 'wildcard' }
  | { type: 'filter'; key: string; op: '==' | '!='; expected: string };

function tokenizeJsonPath(expr: string): JsonPathToken[] {
  const tokens: JsonPathToken[] = [];
  let s = expr.trim();
  if (s.startsWith('$')) s = s.slice(1);

  let i = 0;
  while (i < s.length) {
    const ch = s.charAt(i);
    if (ch === '.') {
      i++;
      if (s.charAt(i) === '*') {
        tokens.push({ type: 'wildcard' });
        i++;
      } else {
        const start = i;
        while (i < s.length && s.charAt(i) !== '.' && s.charAt(i) !== '[') i++;
        const key = s.slice(start, i);
        if (key) tokens.push({ type: 'prop', key });
      }
    } else if (ch === '[') {
      const close = s.indexOf(']', i);
      if (close === -1) throw new Error(`Unclosed bracket in JSONPath: ${expr}`);
      const inside = s.slice(i + 1, close).trim();
      i = close + 1;

      if (inside === '*') {
        tokens.push({ type: 'wildcard' });
      } else if (/^-?\d+$/.test(inside)) {
        tokens.push({ type: 'index', idx: Number(inside) });
      } else if (
        (inside.startsWith("'") && inside.endsWith("'")) ||
        (inside.startsWith('"') && inside.endsWith('"'))
      ) {
        tokens.push({ type: 'prop', key: inside.slice(1, -1) });
      } else {
        const m = /^\?\(\s*@\.([A-Za-z0-9_]+)\s*(==|!=)\s*(.+?)\s*\)$/.exec(
          inside,
        );
        if (!m) {
          throw new Error(`Unsupported JSONPath bracket expression: [${inside}]`);
        }
        let expected = m[3]!;
        if (
          (expected.startsWith('"') && expected.endsWith('"')) ||
          (expected.startsWith("'") && expected.endsWith("'"))
        ) {
          expected = expected.slice(1, -1);
        }
        tokens.push({
          type: 'filter',
          key: m[1]!,
          op: m[2] as '==' | '!=',
          expected,
        });
      }
    } else {
      const start = i;
      while (i < s.length && s.charAt(i) !== '.' && s.charAt(i) !== '[') i++;
      const key = s.slice(start, i);
      if (key) tokens.push({ type: 'prop', key });
    }
  }
  return tokens;
}

/** Minimal dependency-free JSONPath evaluator supporting `.prop`, `[idx]`, `[*]`, and `[?(@.k==v)]`. */
export function evalJsonPath(data: unknown, expr: string): unknown {
  const tokens = tokenizeJsonPath(expr);
  let current: unknown[] = [data];
  let multi = false;

  for (const tok of tokens) {
    const next: unknown[] = [];
    for (const node of current) {
      if (node === null || node === undefined) continue;
      if (tok.type === 'prop') {
        if (typeof node === 'object' && !Array.isArray(node)) {
          const val = (node as Record<string, unknown>)[tok.key];
          if (val !== undefined) next.push(val);
        }
      } else if (tok.type === 'index') {
        if (Array.isArray(node)) {
          const idx = tok.idx < 0 ? node.length + tok.idx : tok.idx;
          if (idx >= 0 && idx < node.length) next.push(node[idx]);
        }
      } else if (tok.type === 'wildcard') {
        multi = true;
        if (Array.isArray(node)) {
          next.push(...node);
        } else if (typeof node === 'object') {
          next.push(...Object.values(node as Record<string, unknown>));
        }
      } else if (tok.type === 'filter') {
        multi = true;
        if (Array.isArray(node)) {
          for (const item of node) {
            if (item && typeof item === 'object' && !Array.isArray(item)) {
              const actual = String(
                (item as Record<string, unknown>)[tok.key] ?? '',
              );
              const match =
                tok.op === '=='
                  ? actual === tok.expected
                  : actual !== tok.expected;
              if (match) next.push(item);
            }
          }
        }
      }
    }
    current = next;
  }

  if (multi) return current;
  return current.length <= 1 ? current[0] : current;
}

export function formatJsonPathResult(result: unknown): string {
  if (
    typeof result === 'string' ||
    typeof result === 'number' ||
    typeof result === 'boolean'
  ) {
    return String(result);
  }
  return JSON.stringify(result ?? null, null, 2);
}
