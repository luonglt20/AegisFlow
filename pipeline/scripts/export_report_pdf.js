const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const reportUrl = 'file://' + path.resolve('DevSecOps_CaseStudy_Report.html');

  await page.goto(reportUrl, { waitUntil: 'networkidle' });
  await page.pdf({
    path: 'DevSecOps_CaseStudy_Report.pdf',
    format: 'A4',
    printBackground: true,
    margin: {
      top: '12mm',
      right: '12mm',
      bottom: '12mm',
      left: '12mm'
    }
  });

  await browser.close();
})();
