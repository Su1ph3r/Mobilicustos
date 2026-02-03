const { chromium } = require('playwright');

async function takeScreenshots() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 2, // Retina quality
  });
  const page = await context.newPage();

  const baseUrl = 'http://localhost:3000';
  const screenshotDir = './screenshots';

  const views = [
    { path: '/', name: 'dashboard', wait: 2000 },
    { path: '/findings', name: 'findings', wait: 3000 },
    { path: '/apps', name: 'apps', wait: 2000 },
    { path: '/scans', name: 'scans', wait: 2000 },
    { path: '/devices', name: 'devices', wait: 2000 },
  ];

  for (const view of views) {
    try {
      console.log(`Taking screenshot of ${view.name}...`);
      await page.goto(`${baseUrl}${view.path}`, { waitUntil: 'networkidle', timeout: 30000 });
      await page.waitForTimeout(view.wait);

      await page.screenshot({
        path: `${screenshotDir}/${view.name}.png`,
        fullPage: false,
      });
      console.log(`  Saved ${view.name}.png`);
    } catch (e) {
      console.error(`  Failed to capture ${view.name}: ${e.message}`);
    }
  }

  // Try to expand a finding row if on findings page
  try {
    console.log('Taking screenshot of finding detail...');
    await page.goto(`${baseUrl}/findings`, { waitUntil: 'networkidle', timeout: 30000 });
    await page.waitForTimeout(2000);

    // Click on the first expandable row
    const expander = await page.$('.p-row-toggler');
    if (expander) {
      await expander.click();
      await page.waitForTimeout(1000);
      await page.screenshot({
        path: `${screenshotDir}/finding-detail.png`,
        fullPage: false,
      });
      console.log('  Saved finding-detail.png');
    }
  } catch (e) {
    console.error(`  Failed to capture finding detail: ${e.message}`);
  }

  await browser.close();
  console.log('Screenshots complete!');
}

takeScreenshots().catch(console.error);
