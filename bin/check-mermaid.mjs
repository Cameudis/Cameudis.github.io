import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>');
globalThis.window = dom.window;
globalThis.document = dom.window.document;
globalThis.navigator = dom.window.navigator;
globalThis.Node = dom.window.Node;
globalThis.Element = dom.window.Element;
globalThis.HTMLElement = dom.window.HTMLElement;
globalThis.SVGElement = dom.window.SVGElement;
globalThis.DOMParser = dom.window.DOMParser;
globalThis.CSS = dom.window.CSS || { escape: value => String(value) };

const { default: mermaid } = await import('mermaid');

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ignoredDirectories = new Set([
  '.git',
  '.jekyll-cache',
  '.obsidian',
  'assets',
  'docs',
  'node_modules',
  'vendor'
]);

async function markdownFiles(directory) {
  const files = [];

  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.name.startsWith('.') && entry.name !== '.') {
      if (entry.isDirectory()) continue;
    }

    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) files.push(...await markdownFiles(absolutePath));
      continue;
    }

    if (/\.(?:md|markdown)$/i.test(entry.name)) files.push(absolutePath);
  }

  return files;
}

function diagramsIn(markdown, filename) {
  const lines = markdown.replace(/\r\n?/g, '\n').split('\n');
  const diagrams = [];
  let fence = null;

  lines.forEach((line, index) => {
    if (fence) {
      const closingFence = new RegExp(`^ {0,3}${fence.character}{${fence.length},}[\\t ]*$`);
      if (closingFence.test(line)) {
        if (fence.language === 'mermaid') {
          diagrams.push({
            filename,
            line: fence.line,
            source: fence.lines.join('\n').trim()
          });
        }
        fence = null;
      } else {
        fence.lines.push(line);
      }
      return;
    }

    const opening = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
    if (!opening) return;

    fence = {
      character: opening[1][0],
      length: opening[1].length,
      language: opening[2].trim().split(/[\t ]+/, 1)[0].toLowerCase(),
      line: index + 1,
      lines: []
    };
  });

  if (fence?.language === 'mermaid') {
    throw new Error(`${filename}:${fence.line}: Mermaid code fence is not closed.`);
  }

  return diagrams;
}

mermaid.initialize({ startOnLoad: false, logLevel: 'fatal', securityLevel: 'strict' });

const files = await markdownFiles(projectRoot);
const diagrams = [];
let failed = false;

for (const filename of files) {
  const relativeFilename = path.relative(projectRoot, filename);
  try {
    diagrams.push(...diagramsIn(await readFile(filename, 'utf8'), relativeFilename));
  } catch (error) {
    console.error(error.message);
    failed = true;
  }
}

for (const diagram of diagrams) {
  if (!diagram.source) {
    console.error(`${diagram.filename}:${diagram.line}: Mermaid diagram is empty.`);
    failed = true;
    continue;
  }

  try {
    await mermaid.parse(diagram.source);
  } catch (error) {
    const message = error?.str || error?.message || String(error);
    console.error(`${diagram.filename}:${diagram.line}: ${message}`);
    failed = true;
  }

  if (!/^\s*accTitle\s*:/m.test(diagram.source)) {
    console.warn(`${diagram.filename}:${diagram.line}: Mermaid diagram has no accTitle.`);
  }
}

if (failed) process.exitCode = 1;
else console.log(`Validated ${diagrams.length} Mermaid diagram${diagrams.length === 1 ? '' : 's'}.`);
