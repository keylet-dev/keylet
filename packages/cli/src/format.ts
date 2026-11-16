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
