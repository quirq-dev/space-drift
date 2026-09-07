import { lstat, opendir } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

const IGNORED_DIRECTORIES = new Set([
  'node_modules', 'dist', 'build', 'coverage', 'out', 'target', 'vendor',
  '__pycache__', 'venv', 'env', 'tmp', 'temp', 'cache', 'Caches',
]);
const SECRET_EXTENSIONS = new Set(['.pem', '.key', '.p12', '.pfx', '.keystore']);

function isIgnored(name, isDirectory) {
  return name.startsWith('.') || (isDirectory && IGNORED_DIRECTORIES.has(name)) ||
    SECRET_EXTENSIONS.has(path.extname(name).toLowerCase());
}

/** Read only names and stat metadata. Symlink entries are never traversed. */
export async function scanDirectory(directory, options = {}) {
  const rootPath = path.resolve(directory);
  const rootStat = await lstat(rootPath);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error('The selected root must be a directory, not a symbolic link.');
  }
  const maxFiles = options.maxFiles ?? 2500;
  const maxEntries = options.maxEntries ?? 25000;
  const maxDepth = options.maxDepth ?? 32;
  const maxDurationMs = options.maxDurationMs ?? 10000;
  const discoveryBudgetMs = Math.max(1, maxDurationMs * 0.65);
  const startedAt = Date.now();
  const queue = [{ absolute: rootPath, relative: '.', depth: 0 }];
  const records = new Map();
  const candidates = [];
  let inspected = 0;
  let truncated = false;
  let unreadable = 0;
  let complete = true;

  scan: for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const directoryEntry = queue[cursor];
    let handle;
    try {
      const directoryStat = await lstat(directoryEntry.absolute);
      if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) continue;
      handle = await opendir(directoryEntry.absolute);
    } catch {
      unreadable += 1;
      complete = false;
      continue;
    }
    for await (const entry of handle) {
      inspected += 1;
      if (inspected > maxEntries || Date.now() - startedAt > discoveryBudgetMs) {
        truncated = true;
        complete = false;
        break scan;
      }
      if (entry.isSymbolicLink() || isIgnored(entry.name, entry.isDirectory())) continue;
      const absolute = path.join(directoryEntry.absolute, entry.name);
      const relative = path.relative(rootPath, absolute).split(path.sep).join('/');
      let metadata = entry;
      // Directory entries normally tell us the type without a per-file stat.
      // Stat directories again before enqueueing; stat selected files below.
      if (entry.isDirectory() || !entry.isFile()) {
        try {
          metadata = await lstat(absolute);
        } catch {
          unreadable += 1;
          complete = false;
          continue;
        }
      }
      if (metadata.isSymbolicLink()) continue;
      if (metadata.isDirectory()) {
        if (isIgnored(entry.name, true)) continue;
        if (directoryEntry.depth >= maxDepth) {
          truncated = true;
          complete = false;
        } else {
          queue.push({ absolute, relative, depth: directoryEntry.depth + 1 });
        }
        continue;
      }
      if (!metadata.isFile()) continue;
      candidates.push({ absolute, relative, parent: directoryEntry.relative, name: entry.name });
    }
  }

  // Share the file budget among top-level folders, so a large dependency-free
  // folder cannot consume all 2,500 map objects before its neighbors appear.
  const byDistrict = new Map();
  for (const candidate of candidates) {
    const district = candidate.relative.includes('/') ? candidate.relative.split('/')[0] : '.';
    if (!byDistrict.has(district)) byDistrict.set(district, []);
    byDistrict.get(district).push(candidate);
  }
  const districts = [...byDistrict].sort(([a], [b]) => a.localeCompare(b))
    .map(([, files]) => files.sort((a, b) => a.relative.localeCompare(b.relative)));
  const selected = [];
  for (let round = 0; selected.length < Math.min(maxFiles, candidates.length); round += 1) {
    for (const district of districts) {
      if (district[round]) selected.push(district[round]);
      if (selected.length >= maxFiles) break;
    }
  }
  let omittedIsLowerBound = !complete;
  const omitted = candidates.length - selected.length;
  if (omitted > 0) {
    truncated = true;
    complete = false;
  }
  for (const candidate of selected) {
    if (Date.now() - startedAt > maxDurationMs) {
      truncated = true;
      complete = false;
      break;
    }
    let stat;
    try {
      stat = await lstat(candidate.absolute);
    } catch {
      unreadable += 1;
      complete = false;
      omittedIsLowerBound = true;
      continue;
    }
    if (!stat.isFile() || stat.isSymbolicLink()) continue;
    const file = {
      id: candidate.relative,
      path: candidate.relative,
      name: candidate.name,
      parent: candidate.parent,
      size: stat.size,
      modifiedAt: stat.mtime.toISOString(),
      extension: path.extname(candidate.name).toLowerCase().replace(/^\./, ''),
    };
    records.set(candidate.relative, {
      file,
      mtimeMs: stat.mtimeMs,
      ctimeMs: stat.ctimeMs,
      identity: stat.ino > 0 && stat.birthtimeMs > 0
        ? `${stat.dev}:${stat.ino}:${stat.birthtimeMs}` : null,
    });
  }
  const files = [...records.values()].map((record) => record.file)
    .sort((a, b) => a.path.localeCompare(b.path));
  return {
    world: {
      root: { name: path.basename(rootPath) || rootPath, path: rootPath },
      scannedAt: new Date().toISOString(),
      files,
      truncated,
      omitted: candidates.length - records.size,
      omittedIsLowerBound,
      unreadable,
    },
    records,
    complete,
  };
}

/** An incomplete scan never manufactures creation, deletion, or move events. */
export function diffSnapshots(previous, current) {
  if (!previous) return [];
  const events = [];
  const at = current.world.scannedAt;
  const event = (type, filePath, extra = {}) => ({
    id: randomUUID(), type, path: filePath, ...extra, at,
  });
  for (const [filePath, record] of current.records) {
    const before = previous.records.get(filePath);
    if (before && (before.mtimeMs !== record.mtimeMs || before.file.size !== record.file.size)) {
      events.push(event('modified', filePath));
    }
  }
  if (!previous.complete || !current.complete) return events;
  const removed = new Map([...previous.records].filter(([key]) => !current.records.has(key)));
  const added = new Map([...current.records].filter(([key]) => !previous.records.has(key)));
  const identityCounts = (records) => {
    const counts = new Map();
    for (const record of records.values()) {
      if (record.identity) counts.set(record.identity, (counts.get(record.identity) ?? 0) + 1);
    }
    return counts;
  };
  const beforeCounts = identityCounts(previous.records);
  const afterCounts = identityCounts(current.records);
  const removedByIdentity = new Map([...removed].map(([key, record]) => [record.identity, key]));
  for (const [filePath, record] of added) {
    const previousPath = record.identity && removedByIdentity.get(record.identity);
    if (previousPath && beforeCounts.get(record.identity) === 1 && afterCounts.get(record.identity) === 1) {
      events.push(event('moved', filePath, { previousPath }));
      removed.delete(previousPath);
    } else {
      events.push(event('created', filePath));
    }
  }
  for (const filePath of removed.keys()) events.push(event('deleted', filePath));
  return events;
}

/** Concurrent browser requests share one scan; history exists only in memory. */
export function createWorldReader(directory, options = {}) {
  let previous = null;
  let events = [];
  let pending = null;
  return function readWorld() {
    if (pending) return pending;
    pending = (async () => {
      const current = await scanDirectory(directory, options);
      events = [...diffSnapshots(previous, current).reverse(), ...events].slice(0, 40);
      previous = current;
      return { ...current.world, events };
    })().finally(() => { pending = null; });
    return pending;
  };
}
