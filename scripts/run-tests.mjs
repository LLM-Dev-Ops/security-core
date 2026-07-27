// Test runner that cannot report a false green.
//
// `node --test dist/tests/*.test.js` exits 0 when the glob matches nothing, so
// a clean checkout with no dist/ used to report "tests 0" and pass. This runner
// fails when no test files are found and when fewer than MIN_TESTS execute.

import { readdirSync } from 'node:fs';
import path from 'node:path';
import { run } from 'node:test';
import { spec } from 'node:test/reporters';

const MIN_TESTS = 60;
const testDir = path.resolve(import.meta.dirname, '..', 'dist', 'tests');

let files;
try {
  files = readdirSync(testDir)
    .filter(name => name.endsWith('.test.js'))
    .map(name => path.join(testDir, name));
} catch {
  console.error(`FAIL: ${testDir} does not exist. Run "npm run build" first.`);
  process.exit(1);
}

if (files.length === 0) {
  console.error(`FAIL: no test files found in ${testDir}`);
  process.exit(1);
}

let passed = 0;
let failed = 0;

const stream = run({ files, concurrency: true });
const isSuite = event => event.details?.type === 'suite';
stream.on('test:pass', event => { if (!isSuite(event) && !event.skip && !event.todo) passed++; });
stream.on('test:fail', event => { if (!isSuite(event)) failed++; });

stream.compose(new spec()).pipe(process.stdout);

stream.on('end', () => {
  const total = passed + failed;
  console.log(`\ntest files: ${files.length}  executed: ${total}  passed: ${passed}  failed: ${failed}`);

  if (failed > 0) {
    console.error(`FAIL: ${failed} test(s) failed`);
    process.exit(1);
  }
  if (total < MIN_TESTS) {
    console.error(`FAIL: only ${total} tests executed, minimum is ${MIN_TESTS}`);
    process.exit(1);
  }
  process.exit(0);
});
