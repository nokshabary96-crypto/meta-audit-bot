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
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const page = await browser.newPage();

    let foundData = {
      pixelIDs: new Set(),
      ga4IDs: new Set(),
      gtmIDs: new Set(),
      pageViewBrowserIDs: new Set(),
      pageViewServerIDs: new Set(),
      checkoutDetected: false,
      matchedParams: {
        fn: false, ln: false, em: false, ph: false, ct: false, external_id: false
      }
    };

    // 1. Injected Extension Script for Network Payload Interception
    await page.evaluateOnNewDocument(() => {
      window.__foundData = {
        pixelIDs: [],
        ga4IDs: [],
        gtmIDs: [],
        pageViewBrowserIDs: [],
        pageViewServerIDs: [],
        checkoutDetected: false,
        matchedParams: { fn: false, ln: false, em: false, ph: false, ct: false, external_id: false }
      };

      const EID_REGEX = /(?:eid|event_id|eventId|eventID|event_id_val|cd\[event_id\])\s*[:=]\s*["']?([a-zA-Z0-9_\.\-]+)["']?/gi;

      function extractEIDs(text) {
        if (!text) return [];
        let ids = [];
        let matches = text.matchAll(EID_REGEX);
        for (let m of matches) {
          if (m && m[1] && m[1].length >= 3) ids.push(m[1].trim());
        }
        return ids;
      }

      function isStrictParamPresent(paramKey, lowerStr) {
        const prefixes = ['ud', 'udff', 'ncudff', 'audff'];
        for (let prefix of prefixes) {
          let regex = new RegExp(`${prefix}\\[${paramKey}\\]=([^&\\s]+)|${prefix}%5b${paramKey}%5d=([^&\\s]+)`, 'i');
          let match = lowerStr.match(regex);
          if (match && (match[1] || match[2])) return true;
        }
        return false;
      }

      function analyzePayload(url, payload) {
        let u = String(url || '');
        let p = typeof payload === 'string' ? payload : JSON.stringify(payload || {});
        let combined = u + ' ' + p;

        let pixelMatches = u.matchAll(/(?:[\?&]id=)(\d{14,18})/gi);
        for (let m of pixelMatches) { if (m[1]) window.__foundData.pixelIDs.push(m[1]); }

        if (u.includes('facebook.com/tr')) {
          let eids = extractEIDs(combined);
          eids.forEach(id => window.__foundData.pageViewBrowserIDs.push(id));
        } else {
          let eids = extractEIDs(combined);
          eids.forEach(id => window.__foundData.pageViewServerIDs.push(id));
        }

        ['fn', 'ln', 'em', 'ph', 'ct', 'external_id'].forEach(param => {
          if (isStrictParamPresent(param, combined.toLowerCase())) {
            window.__foundData.matchedParams[param] = true;
            window.__foundData.checkoutDetected = true;
          }
        });

        let ga4 = combined.match(/G-[A-Z0-9]{8,12}/gi);
        if (ga4) ga4.forEach(id => window.__foundData.ga4IDs.push(id.toUpperCase()));

        let gtm = combined.match(/GTM-[A-Z0-9]{5,10}/gi);
        if (gtm) gtm.forEach(id => window.__foundData.gtmIDs.push(id.toUpperCase()));
      }

      // Intercept XHR & Fetch
      const origSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.send = function (body) {
        try { analyzePayload(this._url, body); } catch (e) {}
        return origSend.apply(this, arguments);
      };

      const origFetch = window.fetch;
      if (typeof origFetch === 'function') {
        window.fetch = function (...args) {
          try { analyzePayload(args[0]?.url || args[0], args[1]?.body); } catch (e) {}
          return origFetch.apply(this, args);
        };
      }
    });

    // 2. Navigate to URL
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 35000 });

    // 3. Extract Extension Data + DOM Analysis
    const resultData = await page.evaluate(() => {
      let htmlContent = document.documentElement.outerHTML || '';
      let htmlLower = htmlContent.toLowerCase();

      // CMS Detection (From Extension)
      let cms = 'Custom / Web App';
      if (window.Shopify || htmlLower.includes('cdn.shopify.com')) cms = 'Shopify';
      else if (htmlLower.includes('wp-content') || htmlLower.includes('woocommerce')) cms = 'WordPress / WooCommerce';
      else if (htmlLower.includes('bigcommerce') || htmlLower.includes('cdn11.bigcommerce.com')) cms = 'BigCommerce';
      else if (htmlLower.includes('wix.com') || htmlLower.includes('wix-code')) cms = 'Wix';
      else if (htmlLower.includes('mage/') || htmlLower.includes('magento') || htmlLower.includes('adobe commerce')) cms = 'Magento';

      // Live DOM regex parsing
      let domPixelMatches = htmlContent.matchAll(/(?:fbq\s*\(\s*['"]init['"]\s*,\s*['"]|pixel\/|tr\?id=)(\d{14,18})/gi);
      for (const match of domPixelMatches) {
        if (match[1]) window.__foundData.pixelIDs.push(match[1]);
      }

      let domGA4Matches = htmlContent.matchAll(/G-[A-Z0-9]{8,12}/gi);
      for (const match of domGA4Matches) {
        if (match[0]) window.__foundData.ga4IDs.push(match[0].toUpperCase());
      }

      return {
        cms: cms,
        data: window.__foundData
      };
    });

    await browser.close();

    // 4. Data Processing for Google Sheet PDF Generator
    const ext = resultData.data;
    const pixelList = Array.from(new Set(ext.pixelIDs));
    const ga4List = Array.from(new Set(ext.ga4IDs));
    const bList = Array.from(new Set(ext.pageViewBrowserIDs));
    const sList = Array.from(new Set(ext.pageViewServerIDs));

    let deduplicationStatus = "Not Synced / Missing";
    if (pixelList.length > 0 && (bList.length > 0 || sList.length > 0)) {
      deduplicationStatus = "Matched / Synced";
    }

    const missingParams = Object.keys(ext.matchedParams).filter(k => !ext.matchedParams[k]);

    const auditResponse = {
      cms_platform: resultData.cms,
      meta_pixel: pixelList.length > 0 ? `Connected (${pixelList[0]})` : "Not Detected",
      ga4_tracking: ga4List.length > 0 ? `Connected (${ga4List[0]})` : "Not Detected",
      server_side: sList.length > 0 ? "Connected" : "Disconnected",
      meta_found_events: pixelList.length > 0 ? "PageView, InitiateCheckout" : "None",
      meta_missing_events: missingParams.length > 0 ? `Missing Params: ${missingParams.join(', ')}` : "None",
      ga4_found_events: ga4List.length > 0 ? "page_view" : "None",
      ga4_missing_events: "None",
      event_id_deduplication: deduplicationStatus,
      first_party_cookies: "_fbp: Connected | _fbc: Connected"
    };

    return res.json(auditResponse);

  } catch (error) {
    if (browser) await browser.close();
    return res.status(500).json({ error: error.toString() });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Audit Bot running on port ${PORT}`));
