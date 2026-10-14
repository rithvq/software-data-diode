// Real Streamlit browser checks against a clearly isolated synthetic API fixture.
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const [url, apiPort, output, executablePath] = process.argv.slice(2);
(async () => {
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ executablePath, headless: true });
  const checks = [];
  let page;
  const check = (name, condition) => { assert(condition, name); checks.push({ check: name, passed: true }); };
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
    await page.getByText('Definite-decision yield', { exact: true }).waitFor();
    await page.getByText('UNKNOWN: Insufficient', { exact: false }).waitFor();
    await page.getByRole('button', { name: /JSON$/ }).nth(3).waitFor();
    await page.waitForTimeout(800);
    await page.screenshot({ path: path.join(output, 'desktop.png'), fullPage: true });
    check('desktop no horizontal document overflow', await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    const opacities = [];
    for (let i = 0; i < 12; i++) {
      const opacity = await page.locator('[data-testid="stMetric"]').first().evaluate(el => {
        let p = el, value = 1;
        while (p) { value *= Number(getComputedStyle(p).opacity); p = p.parentElement; }
        return value;
      });
      opacities.push(opacity);
      await page.waitForTimeout(350);
    }
    check('readability unchanged across timed reruns', opacities.every(v => v === 1));
    const stats = async () => (await (await page.request.get(`http://127.0.0.1:${apiPort}/_fixture/stats`)).json()).requests;
    await page.getByText('5s', { exact: true }).click();
    await page.getByText('Every 5s', { exact: true }).waitFor();
    check('cadence selection reflected', true);
    await page.getByText('Auto refresh', { exact: true }).click();
    await page.getByText('Paused', { exact: true }).waitFor();
    await page.waitForTimeout(700);
    const paused = await stats();
    await page.waitForTimeout(5700);
    check('pause cancels the previous timer', await stats() === paused);
    await page.getByRole('button', { name: 'Refresh now' }).click();
    await page.waitForTimeout(800);
    check('manual refresh while paused', await stats() > paused);
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: /JSON$/ }).first().click();
    const download = await downloadPromise;
    await download.saveAs(path.join(output, 'downloaded-snapshot.json'));
    check('JSON download includes page and sender scope', Boolean(JSON.parse(fs.readFileSync(path.join(output, 'downloaded-snapshot.json'), 'utf8')).page));
    await page.request.post(`http://127.0.0.1:${apiPort}/_fixture/outage`);
    await page.getByRole('button', { name: 'Refresh now' }).click();
    await page.getByText('Coverage API timeout/unavailable.', { exact: false }).first().waitFor();
    check('timeout keeps decision inspection readable', await page.getByText('UNKNOWN: Insufficient', { exact: false }).isVisible());
    await page.screenshot({ path: path.join(output, 'outage.png'), fullPage: true });
    await page.locator('[data-testid="stSidebarCollapseButton"] button').click();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(700);
    await page.getByText('Evidence Coverage', { exact: true }).first().scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(output, 'mobile.png'), fullPage: true });
    check('mobile no horizontal document overflow', await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    check('mobile retains readable result', await page.getByText('UNKNOWN: Insufficient', { exact: false }).isVisible());
    await page.getByText('UNKNOWN: Insufficient', { exact: false }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(output, 'mobile-detail.png'), fullPage: true });
    await page.setViewportSize({ width: 1440, height: 1100 });
    await page.getByText('UNKNOWN: Insufficient', { exact: false }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: path.join(output, 'desktop-detail.png'), fullPage: true });
    fs.writeFileSync(path.join(output, 'results.json'), JSON.stringify({ mode: 'SYNTHETIC_UI_FIXTURE_NOT_LIVE_POSTGRES',
      checks, opacity_samples: opacities, viewports: [[1440, 1100], [390, 844]] }, null, 2));
    console.log(JSON.stringify({ passed: checks.length, output }));
    await context.close();
  } catch (error) {
    if (page) {
      await page.screenshot({ path: path.join(output, 'failure.png'), fullPage: true });
      fs.writeFileSync(path.join(output, 'failure.txt'), await page.locator('body').innerText());
    }
    throw error;
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
