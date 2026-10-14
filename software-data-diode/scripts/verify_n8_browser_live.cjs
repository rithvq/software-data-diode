// Live research UI only. A bounded Monitoring API outage is restored in finally.
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const [url, output, executablePath, docker] = process.argv.slice(2);
const container = 'software-data-diode-coverage-monitoring-api-1';
(async () => {
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ executablePath, headless: true });
  const checks = [], opacitySamples = [];
  let stopped = false, page;
  const check = (name, value) => { assert(value, name); checks.push({ check: name, passed: true }); };
  const dockerCommand = command => execFileSync(docker, [command, container], { timeout: 40000, windowsHide: true });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1100 } });
    await context.route('**/*', route => {
      const target = new URL(route.request().url());
      return ['127.0.0.1', 'localhost'].includes(target.hostname) || ['data:', 'blob:'].includes(target.protocol)
        ? route.continue() : route.abort();
    });
    page = await context.newPage();
    await page.goto(url);
    await page.getByText('Evidence Coverage', { exact: true }).click();
    await page.getByText('UNKNOWN: Insufficient', { exact: false }).waitFor();
    await page.getByRole('button', { name: /JSON$/ }).nth(1).waitFor();
    check('live unknown is explained', await page.getByText('Reasons:', { exact: false }).isVisible());
    const selected = () => page.getByRole('combobox', { name: 'Inspect rule window' }).innerText();
    const pinned = await selected();
    for (let i = 0; i < 12; i++) {
      opacitySamples.push(await page.locator('[data-testid="stMetric"]').first().evaluate(el => {
        let value = 1;
        for (let p = el; p; p = p.parentElement) value *= Number(getComputedStyle(p).opacity);
        return value;
      }));
      await page.waitForTimeout(350);
    }
    check('live fragment reruns do not dim metrics', opacitySamples.every(v => v === 1));
    check('selection survives live timer', await selected() === pinned);
    await page.getByText('5s', { exact: true }).click();
    await page.getByText('Every 5s', { exact: true }).waitFor();
    const updated = () => page.getByText(/^Updated \d\d:\d\d:\d\d UTC$/).innerText();
    const beforeCadence = await updated();
    await page.waitForTimeout(6800);
    check('live 5-second cadence updates data', await updated() !== beforeCadence);
    await page.getByText('Auto refresh', { exact: true }).click();
    await page.getByText('Paused', { exact: true }).waitFor();
    await page.waitForTimeout(700);
    const paused = await updated();
    await page.waitForTimeout(5700);
    check('live pause cancels previous timer', await updated() === paused);
    await page.getByRole('button', { name: 'Refresh now' }).click();
    await page.waitForTimeout(2000);
    check('live manual refresh while paused', await updated() !== paused);
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: /JSON$/ }).first().click();
    const download = await downloadPromise;
    await download.saveAs(path.join(output, 'snapshot.json'));
    const snapshot = JSON.parse(fs.readFileSync(path.join(output, 'snapshot.json'), 'utf8'));
    check('live JSON includes actual PostgreSQL decision page', snapshot.page.items.length > 0 && snapshot.overview.assurance === 'AUTHENTICATED_SUMMARY');
    await page.screenshot({ path: path.join(output, 'desktop.png'), fullPage: true });
    check('live desktop no document overflow', await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    // Only this research API container is stopped. No Edge or baseline commands.
    dockerCommand('stop'); stopped = true;
    await page.getByRole('button', { name: 'Refresh now' }).click();
    await page.getByText('Coverage API timeout/unavailable.', { exact: false }).first().waitFor({ timeout: 20000 });
    check('real API outage keeps pinned decision', await selected() === pinned);
    check('real API outage keeps evidence explanation', await page.getByText('UNKNOWN: Insufficient', { exact: false }).isVisible());
    await page.getByText('UNKNOWN: Insufficient', { exact: false }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(output, 'outage-detail.png'), fullPage: true });
    dockerCommand('start'); stopped = false;
    await page.waitForTimeout(2000);
    await page.getByRole('button', { name: 'Refresh now' }).click();
    await page.getByText('Live', { exact: true }).waitFor();
    check('manual recovery without losing selected window', await selected() === pinned);
    await page.locator('[data-testid="stSidebarCollapseButton"] button').click();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(800);
    await page.getByText('Evidence Coverage', { exact: true }).first().scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(output, 'mobile.png'), fullPage: true });
    check('live mobile no document overflow', await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.getByText('UNKNOWN: Insufficient', { exact: false }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(output, 'mobile-detail.png'), fullPage: true });
    fs.writeFileSync(path.join(output, 'results.json'), JSON.stringify({ mode: 'LIVE_COVERAGE_DOCKER_POSTGRES',
      checks, opacity_samples: opacitySamples, viewports: [[1440,1100],[390,844]] }, null, 2));
    console.log(JSON.stringify({ passed: checks.length, output }));
    await context.close();
  } catch (error) {
    if (page) {
      await page.screenshot({ path: path.join(output, 'failure.png'), fullPage: true });
      fs.writeFileSync(path.join(output, 'failure.txt'), await page.locator('body').innerText());
    }
    throw error;
  } finally {
    if (stopped) dockerCommand('start');
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
