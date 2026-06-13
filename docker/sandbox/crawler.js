'use strict';
const puppeteer = require('puppeteer');

async function crawl(targetUrl) {
  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });
  const page = await browser.newPage();
  const redirects = [];
  const scripts = [];
  page.on('response', r => {
    if (r.status() >= 300 && r.status() < 400) redirects.push(r.url());
  });
  page.on('requestfinished', req => {
    if (req.resourceType() == 'script') scripts.push(req.url());
  });
  let finalUrl = targetUrl;
  try {
    const resp = await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 25000 });
    finalUrl = page.url();
  } catch (e) { console.error(e.message); }
  const title = await page.title();
  const domHtml = await page.content();
  const screenshot = await page.screenshot({ encoding: 'base64' });
  const formData = await page.evaluate(() => {
    return Array.from(document.querySelectorAll('form')).map(f => ({
      action: f.action, method: f.method,
      fields: Array.from(f.elements).map(el => ({ name: el.name, type: el.type }))
    }));
  });
  await browser.close();
  return { url: targetUrl, final_url: finalUrl, title, dom_html: domHtml,
           scripts, redirects, form_data: formData, screenshot_b64: screenshot };
}

crawl(process.argv[2]).then(result => {
  console.log(JSON.stringify(result));
}).catch(e => {
  console.error(e.message);
  process.exit(1);
});
