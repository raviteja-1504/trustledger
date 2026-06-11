const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
  await page.goto('http://localhost:3000/audit', { waitUntil: 'load', timeout: 90000 });
  await page.evaluate(() => localStorage.setItem('tl_force_seed', '1'));
  await page.reload({ waitUntil: 'load', timeout: 90000 });
  await page.waitForTimeout(2000);
  await page.screenshot({ path: '/tmp/audit_header.png', fullPage: false });
  const exportBtn = page.locator('button:has-text("Export")');
  await exportBtn.click();
  await page.waitForTimeout(300);
  await page.screenshot({ path: '/tmp/audit_export_open.png', fullPage: false });
  await browser.close();
})();
