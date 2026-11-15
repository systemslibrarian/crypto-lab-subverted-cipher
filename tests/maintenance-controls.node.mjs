import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import test from 'node:test';

/**
 * The four dependency-automation controls the template requires -- grouping,
 * auto-merge, the pull-request gate and workflow_dispatch -- asserted rather
 * than claimed, plus the properties that make them safe. `npm run build` runs
 * this first, so the deploy cannot ship a workflow that has quietly lost one.
 *
 * Node's built-in test runner and nothing else, so this needs no dependency of
 * its own.
 */

const root = new URL('../', import.meta.url);
const workflow = readFileSync(new URL('.github/workflows/deploy.yml', root), 'utf8');
const dependabot = readFileSync(new URL('.github/dependabot.yml', root), 'utf8');
const packageJson = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));
const packageLock = JSON.parse(readFileSync(new URL('package-lock.json', root), 'utf8'));
const gitignore = readFileSync(new URL('.gitignore', root), 'utf8');
const playwrightConfig = readFileSync(new URL('playwright.config.ts', root), 'utf8');
const viteConfig = readFileSync(new URL('vite.config.ts', root), 'utf8');
const ledger = JSON.parse(readFileSync(new URL('e2e/verdict-mutations.json', root), 'utf8'));

function job(name) {
  const pattern = '\\n  ' + name + ':\\n[\\s\\S]*?(?=\\n  [a-z][a-z0-9-]*:\\n|$)';
  const match = workflow.match(new RegExp(pattern));
  assert.ok(match, `missing ${name} job`);
  return match[0];
}

test('one workflow owns the pull-request gate and the Pages deployment', () => {
  assert.equal(existsSync(new URL('.github/workflows/ci.yml', root)), false);
  assert.match(workflow, /push:\n\s+branches: \[main\]/);
  assert.match(workflow, /pull_request:.*\n\s+branches: \[main\]/);
  assert.match(workflow, /workflow_dispatch:/);
});

test('the concurrency group is per-ref, so a pull request cannot cancel a live deploy', () => {
  assert.match(workflow, /group: pages-\$\{\{ github\.ref \}\}/);
  assert.doesNotMatch(workflow, /group: pages\n/);
});

test('only the deploy job can mint Pages credentials', () => {
  const header = workflow.slice(0, workflow.indexOf('\njobs:'));
  assert.match(header, /permissions:\n  contents: read\n/);
  assert.doesNotMatch(header, /pages: write|id-token: write/);
  assert.doesNotMatch(job('build'), /pages: write|id-token: write/);
  assert.match(job('deploy'), /permissions:\n      contents: read\n      pages: write\n      id-token: write\n/);
});

test('every third-party action is pinned to an immutable commit', () => {
  // Both step shapes: `- uses:` and a `uses:` under a `- name:`. A declared
  // denominator, so a step in a shape neither pattern reads fails here instead
  // of passing unseen.
  const actions = [...workflow.matchAll(/^[ \t]*(?:-[ \t]+)?uses:[ \t]+([^@\s]+)@([^\s]+)/gm)];
  const present = workflow.match(/^[ \t]*(?:-[ \t]+)?uses:/gm) ?? [];
  assert.equal(actions.length, present.length, `${present.length - actions.length} uses: line(s) this control cannot read`);
  assert.ok(actions.length > 0, 'workflow has no actions');
  for (const [, action, reference] of actions) {
    assert.match(reference, /^[0-9a-f]{40}$/, `${action} is not commit-pinned`);
  }
});

test('pull requests run the complete gate without packaging Pages', () => {
  const build = job('build');
  const browser = job('browser-gate');
  assert.match(build, /run: npm ci/);
  assert.match(build, /run: npm test/, 'the whole unit suite blocks a publish, not just the browser half');
  assert.match(build, /run: npm run build/);
  assert.match(browser, /run: npx playwright test/);
  assert.match(
    build,
    /name: Upload Pages artifact\n\s+if: github\.event_name != 'pull_request'\n\s+uses: actions\/upload-pages-artifact@[0-9a-f]{40}/,
  );
  assert.match(job('deploy'), /needs: \[build, browser-gate\]/);
  // The gate a bump auto-merges against must be the gate the deploy runs.
  assert.match(job('dependabot-auto-merge'), /needs: \[build, browser-gate\]/);
});

test('the deploy is gated on != pull_request, never on == push', () => {
  assert.match(job('deploy'), /if: github\.event_name != 'pull_request'/);
  assert.doesNotMatch(job('deploy'), /github\.event_name == 'push'/);
});

test('the browser image matches the installed Playwright and is immutable', () => {
  const version = packageLock.packages['node_modules/@playwright/test'].version;
  assert.equal(version, packageLock.packages['node_modules/playwright-core'].version);
  assert.match(
    job('browser-gate'),
    new RegExp(`image: mcr\\.microsoft\\.com/playwright:v${version}-noble@sha256:[0-9a-f]{64}`),
  );
});

test('Dependabot groups minor and patch bumps, and leaves majors individual', () => {
  assert.match(dependabot, /package-ecosystem: "npm"/);
  assert.match(dependabot, /npm-minor-and-patch:/);
  assert.match(dependabot, /update-types:\n\s+- "minor"\n\s+- "patch"/);
  assert.doesNotMatch(dependabot, /- "major"/);
  assert.match(dependabot, /package-ecosystem: "github-actions"/);
  assert.match(dependabot, /github-actions:\n\s+patterns:\n\s+- "\*"/);
});

test('post-merge behaviour is direct, fail-closed, and dispatches a file that exists', () => {
  const autoMerge = job('dependabot-auto-merge');
  assert.doesNotMatch(autoMerge, /dependabot\/fetch-metadata/);
  assert.match(autoMerge, /set -eu/);
  assert.match(autoMerge, /exit 1/);
  const dispatched = /gh workflow run ([\w.-]+) --repo/.exec(autoMerge);
  assert.ok(dispatched, 'the merge step must dispatch the deploy explicitly');
  assert.ok(
    existsSync(new URL(`.github/workflows/${dispatched[1]}`, root)),
    `the dispatch names ${dispatched[1]}, which does not exist in this repo`,
  );
  assert.doesNotMatch(autoMerge, /gh workflow run[^\n]*(?:\|\||continue-on-error)/);
  // The rationale paragraph is part of the block, not decoration: deleting it
  // and deleting the dispatch it defends are the same edit six months apart.
  assert.match(autoMerge, /raises no push event/);
});

test('a deployment carries and verifies exact source provenance', () => {
  assert.match(job('build'), /public\/deployment\.json/);
  assert.match(gitignore, /^public\/deployment\.json$/m);
  assert.match(job('deploy'), /deployment\.json\?sha=\$\{GITHUB_SHA\}/);
  assert.match(job('deploy'), /p\.source_sha===process\.argv\[2\]/);
  assert.match(job('deploy'), /grep -Fq 'id="app"'/);
});

test('every job has an explicit timeout, and node is pinned to 22', () => {
  for (const name of ['build', 'browser-gate', 'deploy', 'dependabot-auto-merge']) {
    assert.match(job(name), /timeout-minutes: \d+/);
  }
  assert.equal((workflow.match(/node-version: 22/g) ?? []).length, 2);
});

test('the Playwright port is this lab\'s own, strict, and builds before it serves', () => {
  assert.match(playwrightConfig, /--port 4239 --strictPort/);
  // Every port this config actually USES -- the served one and both URLs --
  // must be 4239. Grepping the file for "4173" would instead be satisfied or
  // broken by a comment, which is not where a port lives.
  const ports = [
    ...playwrightConfig.matchAll(/--port (\d+)/g),
    ...playwrightConfig.matchAll(/localhost:(\d+)/g),
  ].map((m) => m[1]);
  assert.ok(ports.length >= 3, `expected the port in at least three places, found ${ports.length}`);
  for (const port of ports) assert.equal(port, '4239', 'the Vite default 4173 collides across the fleet');
  assert.match(playwrightConfig, /command: 'npm run build && npm run preview/);
  assert.match(playwrightConfig, /reuseExistingServer: !process\.env\.CI/);
});

test('Vitest collects the colocated unit tests and never the Playwright specs', () => {
  assert.match(viteConfig, /include: \['src\/\*\*\/\*\.test\.ts'\]/);
  assert.match(viteConfig, /exclude: \[\.\.\.configDefaults\.exclude, 'e2e\/\*\*'\]/);
  assert.match(viteConfig, /base: '\/crypto-lab-subverted-cipher\/'/);
});

test('the mutation ledger is concrete patches, and every patch still applies exactly once', () => {
  const ids = Object.keys(ledger.mutations);
  assert.ok(ids.length >= 8, `expected at least 8 mutations, found ${ids.length}`);
  for (const [id, m] of Object.entries(ledger.mutations)) {
    assert.ok(m.file && m.find && m.replace, `${id} must be a concrete patch, not a sentence`);
    const source = readFileSync(new URL(m.file, root), 'utf8');
    const occurrences = source.split(m.find).length - 1;
    assert.equal(occurrences, 1, `${id}: its anchor occurs ${occurrences} times in ${m.file}, expected exactly 1`);
    assert.notEqual(m.find, m.replace, `${id}: the patch is a no-op`);
    assert.ok(['vitest', 'playwright'].includes(m.killedBy.runner), `${id}: unknown runner`);
    if (m.killedBy.runner === 'playwright') {
      assert.ok(m.killedBy.marker, `${id}: a browser-killed mutation must name the marker its test asserts`);
      assert.ok(ledger.markers[m.killedBy.marker], `${id}: marker ${m.killedBy.marker} is not declared`);
    }
  }
});

test('the production build runs these controls first', () => {
  assert.equal(packageJson.scripts['test:maintenance'], 'node --test tests/maintenance-controls.node.mjs');
  assert.match(packageJson.scripts.build, /npm run test:maintenance/);
});

test('the auto-merge path reads the bump type from the pull request and fails closed', async () => {
  const autoMerge = job('dependabot-auto-merge');
  assert.match(autoMerge, /\.github\/scripts\/bump-type\.mjs/);
  assert.match(autoMerge, /if:\s*steps\.bump\.outputs\.bump\s*==\s*'non-major'/);
  const { bumpType } = await import('../.github/scripts/bump-type.mjs');
  // Fails closed, which is the property that matters: anything it cannot read
  // is 'unknown', and 'unknown' does not merge.
  assert.equal(bumpType({ title: 'Bump the npm group across 1 directory', body: 'no versions here' }), 'unknown');
  assert.equal(bumpType({ title: 'Bump x from 1.2.3 to 2.0.0', body: undefined }), 'unknown');
  assert.equal(bumpType({ title: 'Bump x from one to two', body: 'b' }), 'unknown');
  assert.equal(bumpType({ title: 'Bump vitest from 5.0.5 to 5.1.0', body: 'b' }), 'non-major');
  assert.equal(bumpType({ title: 'Bump next from 15.5.27 to 16.4.2', body: 'b' }), 'major');
  assert.equal(bumpType({ title: 'Bump zod from 0.4.1 to 0.5.0', body: 'b' }), 'major', '0.x minor is breaking');
});
