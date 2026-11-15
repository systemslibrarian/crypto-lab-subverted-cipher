#!/usr/bin/env node
// Applies, reverts, or JUDGES the recorded §4.1c mutations in
// e2e/verdict-mutations.json.
//
//   node scripts/mutate.mjs list
//   node scripts/mutate.mjs apply <id>
//   node scripts/mutate.mjs revert <id>
//   node scripts/mutate.mjs run [id...]      <- the judging loop
//
// WHY A JUDGING LOOP AND NOT JUST apply/revert
//
// apply/revert leaves the judgement to a person, and the judgement is the part
// that goes wrong. A mutated run can go red for reasons that are not the claim:
// a build error, a server that never started, a port answered by an unmutated
// checkout. Each looks exactly like a kill in a terminal and is not one. Worse,
// a patch whose anchor no longer matches applies nothing at all, the suite stays
// green, and "the mutation survived" is indistinguishable from "the harness does
// not bite" -- a mistake made twice in this fleet before anything checked for it.
//
// THE FOUR RULES A KILL HAS TO CLEAR, all enforced below:
//
//   1. the owning test PASSED unmutated, in this same run;
//   2. the patch actually CHANGED the file (anchor unique, bytes different);
//   3. the run served the MUTATED code -- proved two ways, because one is not
//      enough: the built bundle's hash must move, and the failure must not match
//      a shape that means the code never ran at all;
//   4. the failure is the owning test's, named in the output.
//
// A patch that does not compile is DOES NOT BUILD and is never a kill. Fix the
// patch -- `|| true` rather than deleting a used local -- and re-run.
//
// The run happens in an isolated `git archive HEAD` tree with node_modules
// symlinked, so nothing is judged against the working copy and a crash cannot
// strand an inverted condition in a file that also holds real work. CI=1 forces
// playwright.config.ts's `reuseExistingServer: !process.env.CI` to false, so
// port 4239 cannot be answered by a server an earlier, unmutated run left up.
//
// TWO RUNNERS. A mutation of the cryptography is owned by a Vitest test and a
// mutation of what the page RENDERS is owned by a Playwright claims test; each
// entry says which. The browser ones run the WHOLE claims suite, never `-g` on
// one test, because e2e/global-teardown.ts fails a run in which a recorded kill
// was not executed -- a single-test run would trip that on the other twenty and
// report a fact about the command rather than about the lab.
//
// This loop DOES write its results back into the ledger's `observed` field,
// because the README quotes them. The enforcement is the teardown, not the
// archive: an unperformed record already fails the suite without this file.

import { execFileSync, execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url)).replace(/\/$/, '');
const LEDGER = join(root, 'e2e', 'verdict-mutations.json');
const registry = JSON.parse(readFileSync(LEDGER, 'utf8'));
const [command, ...rest] = process.argv.slice(2);

if (command === 'list' || !command) {
  for (const [id, entry] of Object.entries(registry.mutations)) {
    console.log(`${id}  ${entry.file}`);
    console.log(`  killed by ${entry.killedBy.runner}: ${entry.killedBy.test}`);
    if (entry.killedBy.marker) console.log(`  asserting marker: ${entry.killedBy.marker}`);
    console.log(`  ${entry.why}\n`);
  }
  process.exit(0);
}

/* ---- apply / revert: one edit, in the working tree ----------------------- */
if (command === 'apply' || command === 'revert') {
  const id = rest[0];
  const entry = registry.mutations[id];
  if (!entry) {
    console.error(`unknown mutation: ${id}`);
    process.exit(2);
  }
  const path = join(root, entry.file);
  const source = readFileSync(path, 'utf8');
  const [from, to] = command === 'apply' ? [entry.find, entry.replace] : [entry.replace, entry.find];
  const occurrences = source.split(from).length - 1;
  if (occurrences !== 1) {
    console.error(`refusing: ${entry.file} matched ${occurrences}x, want exactly 1`);
    process.exit(2);
  }
  writeFileSync(path, source.replace(from, to));
  console.log(`${command} ${id} -> ${entry.file}`);
  process.exit(0);
}

if (command !== 'run') {
  console.error(`unknown command: ${command}. Try list, apply, revert or run.`);
  process.exit(2);
}

/* ---- run: the judging loop ---------------------------------------------- */

const ids = rest.length ? rest : Object.keys(registry.mutations);
const unknown = ids.filter((id) => !registry.mutations[id]);
if (unknown.length) {
  console.error(`unknown mutation(s): ${unknown.join(', ')}`);
  process.exit(2);
}

const git = (...a) => execFileSync('git', ['-C', root, ...a], { encoding: 'utf8' }).trim();

// `git archive HEAD` cannot see uncommitted work, so a dirty tree would produce
// results about a tree nobody has.
const dirty = git('status', '--porcelain', '--untracked-files=no');
if (dirty && !process.env.MUTATION_ALLOW_DIRTY) {
  console.error('Refusing to run: uncommitted changes to tracked files.\n');
  console.error(dirty);
  console.error('\nThe isolated tree is archived from HEAD and would not contain them.');
  console.error('Commit first. MUTATION_ALLOW_DIRTY=1 overrides, knowing that.');
  process.exit(2);
}
const sha = git('rev-parse', 'HEAD');
const shortSha = sha.slice(0, 7);

/* Rule 2, checked for every selected patch BEFORE any is applied. An
   unreversible patch strands a mutated file and turns every later result into a
   verdict about that file rather than about its own mutation. */
const invalid = [];
for (const id of ids) {
  const entry = registry.mutations[id];
  const text = readFileSync(join(root, entry.file), 'utf8');
  const anchors = text.split(entry.find).length - 1;
  if (anchors !== 1) {
    invalid.push(`${id}: find occurs ${anchors} times in ${entry.file}, expected 1`);
    continue;
  }
  const after = text.replace(entry.find, entry.replace);
  if (after === text) invalid.push(`${id}: the patch is a no-op, it would not change ${entry.file}`);
  else if (after.split(entry.replace).length - 1 !== 1) {
    invalid.push(`${id}: replace occurs more than once after applying, so it cannot be reverted`);
  }
}
if (invalid.length) {
  console.error('Refusing to run: these patches cannot make the round trip.\n');
  for (const line of invalid) console.error(`  ${line}`);
  process.exit(2);
}

const TREE = mkdtempSync(join(tmpdir(), 'subverted-mutation-'));
console.log(`isolated tree: ${TREE}`);
console.log(`archived from: ${shortSha}`);
console.log(`${ids.length} patches make the round trip.\n`);
execSync(`git -C ${root} archive HEAD | tar -x -C ${TREE}`, { stdio: 'pipe' });
symlinkSync(join(root, 'node_modules'), join(TREE, 'node_modules'));

const sh = (cmd) =>
  execSync(cmd, {
    cwd: TREE,
    stdio: 'pipe',
    encoding: 'utf8',
    env: { ...process.env, CI: '1' },
    maxBuffer: 64 * 1024 * 1024,
  });

const DIST = join(TREE, 'dist', 'assets');
function bundleHash() {
  if (!existsSync(DIST)) return null;
  const h = createHash('sha256');
  for (const f of readdirSync(DIST).sort()) h.update(f).update(readFileSync(join(DIST, f)));
  return h.digest('hex').slice(0, 12);
}
const md5 = (rel) => createHash('md5').update(readFileSync(join(TREE, rel))).digest('hex').slice(0, 12);

function build() {
  try {
    sh('npm run build');
    return true;
  } catch {
    return false;
  }
}

const strip = (s) => s.replace(/\[[0-9;]*m/g, '');

/** Rule 3's second half. Red for one of these reasons means the code never ran. */
const NOT_A_KILL = [
  { pattern: /error TS\d+|Build failed|Transform failed|Could not resolve/i, label: 'build error' },
  { pattern: /webServer.*did not start|Timeout .* exceeded while running "beforeAll"/i, label: 'server never started' },
  { pattern: /net::ERR_CONNECTION_REFUSED/i, label: 'nothing served on the port' },
];
const notAKill = (output) => NOT_A_KILL.find(({ pattern }) => pattern.test(strip(output)))?.label ?? null;

function runOwner(entry) {
  const { runner, spec, test } = entry.killedBy;
  const cmd =
    runner === 'vitest'
      ? `npx vitest run ${spec} -t ${JSON.stringify(test)}`
      : // The WHOLE claims suite: see the note at the top of this file.
        `npx playwright test --project=claims --reporter=list --retries=0`;
  try {
    return { failed: false, output: sh(cmd) };
  } catch (err) {
    return { failed: true, output: `${err.stdout ?? ''}${err.stderr ?? ''}` };
  }
}

/** Did the OWNING test fail, as opposed to the suite going red somewhere else? */
function ownerFailed(entry, output) {
  const text = strip(output);
  if (entry.killedBy.runner === 'vitest') {
    // Vitest prints `× <file> > <name>` for a failure and `✓` for a pass.
    return new RegExp(`[×✗x]\\s[^\\n]*${escapeRe(entry.killedBy.test)}`).test(text) || /FAIL/.test(text);
  }
  const titles = [...text.matchAll(/^\s*\d+\)\s+(.+?)(?:\s*[─-]{3,})?\s*$/gm)].map((m) => m[1].trim());
  return titles.some((t) => t.includes(entry.killedBy.test));
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function apply(entry, forward) {
  const [from, to] = forward ? [entry.find, entry.replace] : [entry.replace, entry.find];
  const path = join(TREE, entry.file);
  const before = readFileSync(path, 'utf8');
  if (before.split(from).length - 1 !== 1) throw new Error(`${entry.file}: anchor no longer unique`);
  const after = before.replace(from, to);
  if (after === before) throw new Error('the patch produced an identical file: it did not apply');
  writeFileSync(path, after);
}

const passCount = (output) => (strip(output).match(/(\d+)\s+passed/) || [])[1] ?? '?';

/** The failure line naming the owning test, or the first assertion line. */
function failureLine(output, needle) {
  const lines = strip(output)
    .split('\n')
    .map((l) => l.trimEnd());
  const at = lines.findIndex((l) => l.includes(needle));
  if (at >= 0) return lines[at].trim().slice(0, 240);
  const err = lines.findIndex((l) => /Error:|expect\(|AssertionError/.test(l));
  return (err >= 0 ? lines[err] : lines.slice(-3).join(' ')).trim().slice(0, 240);
}

console.log('building the baseline in the isolated tree...');
if (!build()) {
  console.error('The baseline build fails in the isolated tree. Nothing below would mean anything.');
  rmSync(TREE, { recursive: true, force: true });
  process.exit(2);
}
const baselineHash = bundleHash();
console.log(`baseline bundle ${baselineHash}\n`);

// Rule 1, cached per owning command: the tree is unmutated at that moment, so
// two mutations sharing a runner and spec share one honest baseline.
const baselines = new Map();
function baselineFor(entry) {
  const key =
    entry.killedBy.runner === 'vitest' ? `vitest::${entry.killedBy.spec}::${entry.killedBy.test}` : 'playwright::claims';
  if (!baselines.has(key)) {
    process.stdout.write(`  baseline for ${key} ... `);
    const r = runOwner(entry);
    console.log(r.failed ? 'FAILED' : `${passCount(r.output)} passed`);
    baselines.set(key, r);
  }
  return baselines.get(key);
}

const results = [];
for (const id of ids) {
  const entry = registry.mutations[id];
  console.log(`${id}  ${entry.file}`);
  try {
    const base = baselineFor(entry);
    const beforeMd5 = md5(entry.file);
    apply(entry, true);
    const afterMd5 = md5(entry.file);
    const built = build();
    const mutatedHash = built ? bundleHash() : null;
    const run = built ? runOwner(entry) : { failed: false, output: '' };
    apply(entry, false);
    build();
    const restoredHash = bundleHash();
    if (md5(entry.file) !== beforeMd5) {
      console.log('  NOT RESTORED');
      console.error(`\n${id}: ${entry.file} did not return to md5 ${beforeMd5}. Aborting: every`);
      console.error('later result would be a verdict about this file, not about its own mutation.');
      rmSync(TREE, { recursive: true, force: true });
      process.exit(2);
    }

    const shape = built ? notAKill(run.output) : null;
    const verdict = base.failed
      ? 'BASELINE ALREADY RED'
      : !built
        ? 'DOES NOT BUILD'
        : mutatedHash === baselineHash
          ? 'BUNDLE UNCHANGED'
          : shape
            ? `NOT A KILL (${shape})`
            : !run.failed
              ? 'SURVIVED'
              : !ownerFailed(entry, run.output)
                ? 'FAILED FOR THE WRONG REASON'
                : restoredHash !== baselineHash
                  ? 'NOT RESTORED'
                  : 'KILLED';

    entry.observed = [
      `re-derived ${new Date().toISOString().slice(0, 10)} by scripts/mutate.mjs at ${shortSha},`,
      'in an isolated `git archive HEAD` tree with node_modules symlinked and CI=1,',
      `so the ${entry.killedBy.runner} run judged the mutated build itself.`,
      `Baseline (unmutated, same session): ${base.failed ? 'FAILED' : `${passCount(base.output)} passed`}.`,
      `${entry.file} md5 ${beforeMd5} -> ${afterMd5};`,
      `bundle ${baselineHash} -> ${mutatedHash ?? 'no build'} -> ${restoredHash}.`,
      verdict === 'KILLED'
        ? `Mutated run FAILED in "${entry.killedBy.test}": ${failureLine(run.output, entry.killedBy.test)}`
        : `VERDICT ${verdict}: ${failureLine(run.output, entry.killedBy.test)}`,
    ].join(' ');

    results.push({ id, verdict });
    console.log(
      verdict === 'KILLED'
        ? `  KILLED   ${baselineHash} -> ${mutatedHash} -> ${restoredHash}   baseline ${passCount(base.output)} passed`
        : `  ${verdict}`,
    );
  } catch (err) {
    console.log(`  ERROR  ${err.message}`);
    console.error('\nAborting: a mutated file left in place makes every later verdict a statement about it.');
    rmSync(TREE, { recursive: true, force: true });
    process.exit(2);
  }
}

writeFileSync(LEDGER, `${JSON.stringify(registry, null, 2)}\n`);
rmSync(TREE, { recursive: true, force: true });
const bad = results.filter((r) => r.verdict !== 'KILLED');
console.log(`\n${results.length - bad.length}/${results.length} mutations were killed by the test that owns them.`);
if (bad.length) {
  console.log('\nNot killed:');
  for (const r of bad) console.log(`  ${r.id}: ${r.verdict}`);
  console.log('\nDOES NOT BUILD is a broken PATCH, not a surviving mutation: fix the patch and re-run.');
  console.log('SURVIVED is evidence about the SOURCE or the test, and is the one worth stopping for.');
}
process.exit(bad.length ? 1 : 0);
