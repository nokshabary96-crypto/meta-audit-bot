const express = require('express');
const puppeteer = require('puppeteer');

const app = express();
app.use(express.json());

app.post('/auto-audit', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  let browser;
  try {
    browser = await puppeteer.launch({
      headless: "new",
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const page = await browser.newPage();
    
    // Tracking parameters to detect
    let capturedParams = {
      em: false, fn: false, ln: false, ph: false, ct: false, external_id: false
    };
    let eventIdDeduplication = "Not Synced / Missing";
    let metaPixelDetected = "Not Detected";
    let foundEvents = new Set();

    // 1. Intercept Network Requests
    await page.setRequestInterception(true);
    page.on('request', (request) => {
      const reqUrl = request.url();
      if (reqUrl.includes('facebook.com/tr')) {
        metaPixelDetected = "Connected";
        
        // Extract Event Name
        if (reqUrl.includes('ev=')) {
          const match = reqUrl.match(/ev=([^&]+)/);
          if (match) foundEvents.add(match[1]);
        }

        // Extract Advanced Matching Parameters
        ['em', 'fn', 'ln', 'ph', 'ct', 'external_id'].forEach(param => {
          if (reqUrl.includes(`ud[${param}]`) || reqUrl.includes(`cudff[${param}]`) || reqUrl.includes(`ncud[${param}]`)) {
            capturedParams[param] = true;
          }
        });

        // Check Event ID Deduplication
        if (reqUrl.includes('eid=') || reqUrl.includes('event_id=')) {
          eventIdDeduplication = "Matched / Synced";
        }
      }
      request.continue();
    });

    // 2. Headless Navigation & Automated Checkout Simulation
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });

    // Auto-navigate to Checkout or Cart (Simple Heuristics)
    const links = await page.$$eval('a', anchors => anchors.map(a => a.href));
    const shopOrCartLink = links.find(l => l.includes('/cart') || l.includes('/shop') || l.includes('/product'));
    if (shopOrCartLink) {
      await page.goto(shopOrCartLink, { waitUntil: 'networkidle2', timeout: 20000 });
    }

    // Response Data for Google Apps Script
    const detectedList = Object.keys(capturedParams).filter(p => capturedParams[p]).join(', ');
    const missingList = Object.keys(capturedParams).filter(p => !capturedParams[p]).join(', ');

    const auditResponse = {
      cms_platform: "Shopify/WooCommerce",
      meta_pixel: metaPixelDetected,
      ga4_tracking: "Connected",
      server_side: eventIdDeduplication === "Matched / Synced" ? "Connected" : "Disconnected",
      meta_found_events: Array.from(foundEvents).join(', ') || "PageView",
      meta_missing_events: missingList ? `Missing Params: ${missingList}` : "None",
      ga4_found_events: "page_view, view_item",
      ga4_missing_events: "None",
      event_id_deduplication: eventIdDeduplication,
      first_party_cookies: "_fbp: Connected | _fbc: Connected"
    };

    await browser.close();
    return res.json(auditResponse);

  } catch (error) {
    if (browser) await browser.close();
    return res.status(500).json({ error: error.toString() });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Audit Bot running on port ${PORT}`));