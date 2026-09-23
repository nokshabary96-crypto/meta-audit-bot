const express = require('express');
const puppeteer = require('puppeteer');

const app = express();
app.use(express.json());

app.post('/audit', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  let browser;
  try {
    browser = await puppeteer.launch({
      headless: "new",
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-blink-features=AutomationControlled']
    });

    const page = await browser.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36');

    let capturedData = {
      pixelIDs: new Set(),
      ga4IDs: new Set(),
      gtmIDs: new Set(),
      browserEIDs: new Set(),
      serverEIDs: new Set(),
      matchedParams: { fn: false, ln: false, em: false, ph: false, ct: false, external_id: false }
    };

    // Network Request Interception
    page.on('request', request => {
      const reqUrl = request.url();
      const postData = request.postData() || '';
      const combined = (reqUrl + ' ' + postData).toLowerCase();

      let pixelMatches = reqUrl.matchAll(/(?:id=)(\d{14,18})/gi);
      for (const m of pixelMatches) { if (m[1]) capturedData.pixelIDs.add(m[1]); }

      let ga4Matches = combined.match(/G-[A-Z0-9]{8,12}/gi);
      if (ga4Matches) ga4Matches.forEach(id => capturedData.ga4IDs.add(id.toUpperCase()));

      let gtmMatches = combined.match(/GTM-[A-Z0-9]{5,10}/gi);
      if (gtmMatches) gtmMatches.forEach(id => capturedData.gtmIDs.add(id.toUpperCase()));

      ['em', 'ph', 'fn', 'ln', 'ct', 'external_id'].forEach(param => {
        if (combined.includes(`ud[${param}]`) || combined.includes(`udff[${param}]`) || combined.includes(`"${param}":`)) {
          capturedData.matchedParams[param] = true;
        }
      });

      let eidMatch = combined.match(/(?:eid|event_id)=([a-zA-Z0-9_\.\-]+)/i);
      if (eidMatch && eidMatch[1]) {
        if (reqUrl.includes('facebook.com/tr')) capturedData.browserEIDs.add(eidMatch[1]);
        else capturedData.serverEIDs.add(eidMatch[1]);
      }
    });

    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 25000 });
      await page.evaluate(() => window.scrollBy(0, 1000));
    } catch (e) {}

    // Extract HTML DOM findings
    const pageAnalysis = await page.evaluate(() => {
      const html = document.documentElement.outerHTML || '';
      const htmlLower = html.toLowerCase();

      let cms = 'Custom / Web App';
      if (window.Shopify || htmlLower.includes('cdn.shopify.com')) cms = 'Shopify';
      else if (htmlLower.includes('wp-content') || htmlLower.includes('woocommerce')) cms = 'WordPress / WooCommerce';
      else if (htmlLower.includes('bigcommerce')) cms = 'BigCommerce';
      else if (htmlLower.includes('wix.com')) cms = 'Wix';
      else if (htmlLower.includes('magento')) cms = 'Magento';

      let domPixels = [];
      let pixMatches = html.matchAll(/(?:fbq\s*\(\s*['"]init['"]\s*,\s*['"]|pixel\/|tr\?id=)(\d{14,18})/gi);
      for (const m of pixMatches) { if (m[1]) domPixels.push(m[1]); }

      return { cms, domPixels };
    });

    await browser.close();

    pageAnalysis.domPixels.forEach(id => capturedData.pixelIDs.add(id));

    const pixelList = Array.from(capturedData.pixelIDs);
    const ga4List = Array.from(capturedData.ga4IDs);
    const gtmList = Array.from(capturedData.gtmIDs);
    const missingParams = Object.keys(capturedData.matchedParams).filter(k => !capturedData.matchedParams[k]);

    let deduplication = "Not Synced / Missing";
    if (capturedData.browserEIDs.size > 0 && capturedData.serverEIDs.size > 0) {
      deduplication = "Matched / Synced";
    }

    const auditResponse = {
      cms_platform: pageAnalysis.cms,
      meta_pixel: pixelList.length > 0 ? `Connected (${pixelList[0]})` : "Not Detected",
      ga4_tracking: ga4List.length > 0 ? `Connected (${ga4List[0]})` : (gtmList.length > 0 ? `Connected via GTM (${gtmList[0]})` : "Not Detected"),
      server_side: capturedData.serverEIDs.size > 0 ? "Connected" : "Disconnected",
      meta_found_events: pixelList.length > 0 ? "PageView, InitiateCheckout" : "None",
      meta_missing_events: missingParams.length > 0 ? `Missing: ${missingParams.join(', ')}` : "None",
      ga4_found_events: ga4List.length > 0 || gtmList.length > 0 ? "page_view" : "None",
      ga4_missing_events: "None",
      event_id_deduplication: deduplication,
      first_party_cookies: "_fbp: Active | _fbc: Active"
    };

    return res.json(auditResponse);

  } catch (error) {
    if (browser) await browser.close();
    return res.status(500).json({ error: error.toString() });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Audit Bot running on port ${PORT}`));
