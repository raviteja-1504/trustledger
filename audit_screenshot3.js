const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 }, deviceScaleFactor: 2 });
  await page.goto('http://localhost:3000/audit', { waitUntil: 'load', timeout: 90000 });
  await page.evaluate(() => localStorage.setItem('tl_force_seed', '1'));
  await page.reload({ waitUntil: 'load', timeout: 90000 });
  await page.waitForTimeout(2000);
  const exportBtn = page.getByRole('button', { name: 'Export', exact: true });
  await exportBtn.click();
  await page.waitForTimeout(300);
  await page.screenshot({ path: '/tmp/audit_export_zoom2.png', clip: { x: 950, y: 70, width: 330, height: 200 } });

  // Also check narrower viewport
  await page.setViewportSize({ width: 768, height: 1000 });
  await page.waitForTimeout(500);
  await page.screenshot({ path: '/tmp/audit_768_open.png', clip: {x:0,y:0,width:768,height:300} });
  await browser.close();
})();
