import { access, copyFile, mkdir, readdir, readFile, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceRoot = path.join(projectRoot, 'node_modules', 'mermaid');
const sourceDist = path.join(sourceRoot, 'dist');
const targetRoot = path.join(projectRoot, 'assets', 'vendor', 'mermaid');

await access(path.join(sourceRoot, 'package.json')).catch(() => {
  throw new Error("Mermaid is not installed. Run 'npm ci' first.");
});

const projectPackage = JSON.parse(await readFile(path.join(projectRoot, 'package.json'), 'utf8'));
const installedPackage = JSON.parse(await readFile(path.join(sourceRoot, 'package.json'), 'utf8'));
const expectedVersion = projectPackage.devDependencies?.mermaid;

if (installedPackage.version !== expectedVersion) {
  throw new Error(
    `Installed Mermaid ${installedPackage.version} does not match package.json ${expectedVersion}. Run 'npm ci'.`
  );
}

await rm(targetRoot, { recursive: true, force: true });
await mkdir(path.join(targetRoot, 'chunks', 'mermaid.esm.min'), { recursive: true });
await copyFile(
  path.join(sourceDist, 'mermaid.esm.min.mjs'),
  path.join(targetRoot, 'mermaid.esm.min.mjs')
);
await copyFile(path.join(sourceRoot, 'LICENSE'), path.join(targetRoot, 'LICENSE'));

const chunkRoot = path.join(sourceDist, 'chunks', 'mermaid.esm.min');
let copiedFiles = 2;
let copiedBytes = (await stat(path.join(sourceDist, 'mermaid.esm.min.mjs'))).size;

for (const entry of await readdir(chunkRoot, { withFileTypes: true })) {
  if (!entry.isFile() || !entry.name.endsWith('.mjs')) continue;

  const source = path.join(chunkRoot, entry.name);
  const target = path.join(targetRoot, 'chunks', 'mermaid.esm.min', entry.name);
  await copyFile(source, target);
  copiedFiles += 1;
  copiedBytes += (await stat(source)).size;
}

console.log(
  `Vendored Mermaid ${installedPackage.version}: ${copiedFiles} files, ${(copiedBytes / 1024 / 1024).toFixed(2)} MiB.`
);
