#!/usr/bin/env node

/**
 * CI Domain Checker
 *
 * This script checks the accessibility of domains extracted from JSDoc comments
 * in the adsbypasser project. It performs comprehensive checks including DNS
 * resolution, HTTP/HTTPS accessibility, SSL validation, and detection of
 * various error conditions.
 *
 * Features:
 *  - DNS resolution (IPv4/IPv6)
 *  - HTTP/HTTPS accessibility testing
 *  - SSL/TLS certificate validation
 *  - Redirect loop detection
 *  - Timeout handling for slow responses
 *  - Placeholder/parked page detection
 *  - Cloudflare/WAF/5xx error detection
 *  - Blank or JavaScript-only page detection
 *  - Sequential domain checking to avoid overwhelming servers
 */

import { extractDomainsFromJSDoc } from "../build/jsdoc.js";
import { deduplicateRootDomains } from "../build/domain.js";
import dns from "dns/promises";
import http from "http";
import https from "https";
import { URL } from "url";

/* ------------------------ CONFIGURATION ------------------------ */

/**
 * Maximum number of redirects to follow before considering it a loop
 */
const MAX_REDIRECTS = 5;

/**
 * Request timeout in milliseconds
 * Set to 60s to accommodate slow-loading websites
 */
const REQUEST_TIMEOUT_MS = 60000;

/**
 * Browser-like headers to avoid bot detection
 * Mimics Firefox browser to appear as a legitimate user agent
 */
const DEFAULT_HEADERS = {
  "User-Agent":
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
  Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.5",
  "Accept-Encoding": "gzip, deflate, br, zstd",
  Connection: "keep-alive",
  "Upgrade-Insecure-Requests": "1",
  "Sec-Fetch-Dest": "document",
  "Sec-Fetch-Mode": "navigate",
  "Sec-Fetch-Site": "cross-site",
  "Sec-GPC": "1",
  DNT: "1",
  TE: "trailers",
};

/**
 * Text patterns indicating placeholder or parked pages
 */
const PLACEHOLDER_PATTERNS = [
  "Welcome to nginx!",
  "This domain is parked",
  "Buy this domain",
  "Domain for sale",
  "Default PLESK Page",
];

/**
 * Text patterns indicating Web Application Firewall protection
 */
const WAF_PATTERNS = [
  "Attention Required! | Cloudflare",
  "Checking your browser before accessing",
  "DDOS protection by",
];

/**
 * Cloudflare error descriptions for better understanding of issues
 * Only includes error codes that are actually handled in the code
 */
const CLOUDFLARE_ERROR_DESCRIPTIONS = {
  500: "Internal Server Error - Cloudflare could not retrieve the web page",
  502: "Bad Gateway - Cloudflare could not contact the origin server",
  503: "Service Temporarily Unavailable - The server is temporarily unable to handle the request",
  504: "Gateway Timeout - Cloudflare timed out contacting the origin server",
  520: "Web Server Returns an Unknown Error - The origin server returned an empty, unknown, or unexplained response",
  521: "Web Server Is Down - The origin server refused the connection",
  522: "Connection Timed Out - Cloudflare could not negotiate a TCP handshake with the origin server",
  523: "Origin Is Unreachable - Cloudflare could not reach the origin server",
  524: "A Timeout Occurred - Cloudflare was able to complete a TCP connection but timed out waiting for an HTTP response",
  525: "SSL Handshake Failed - Cloudflare could not negotiate an SSL/TLS handshake with the origin server",
  526: "Invalid SSL Certificate - Cloudflare could not validate the SSL certificate of the origin server",
};

/**
 * Status icons for visual representation of domain check results
 */
const STATUS_ICONS = {
  VALID: "✅",
  PLACEHOLDER: "⚠️",
  EMPTY_PAGE: "📄",
  JS_ONLY: "📜",
  CLIENT_ERROR: "🚫",
  SERVER_ERROR: "🔥",
  SSL_ISSUE: "🔒",
  EXPIRED: "❌",
  UNREACHABLE: "🌐",
  REFUSED: "⛔",
  TIMEOUT: "⏱️",
  REDIRECT_LOOP: "🔁",
  PROTOCOL_FLIP_LOOP: "🔄",
  INVALID_REDIRECT: "🔀",
  PROTECTED: "🛡️",
  CLOUDFLARE_BOT_PROTECTION: "🛡️403",
  DDOS_GUARD_PROTECTION: "🛡️403",
  CLOUDFLARE_500: "☁️500",
  CLOUDFLARE_502: "☁️502",
  CLOUDFLARE_503: "☁️503",
  CLOUDFLARE_504: "☁️504",
  CLOUDFLARE_520: "☁️520",
  CLOUDFLARE_521: "☁️521",
  CLOUDFLARE_522: "☁️522",
  CLOUDFLARE_523: "☁️523",
  CLOUDFLARE_524: "☁️524",
  CLOUDFLARE_525: "☁️525",
  CLOUDFLARE_526: "☁️526",
};

/* ------------------------ UTILITIES ------------------------ */

/**
 * Global debug flags for controlling verbose output
 */
let GLOBAL_DEBUG = false;
let SPECIFIC_DOMAIN_DEBUG = null;

/**
 * Debug logging function that respects debug flags
 * @param {string} domain - The domain being checked
 * @param {...any} args - Arguments to log
 */
function debugLog(domain, ...args) {
  // If global debug is enabled, log everything
  if (GLOBAL_DEBUG) {
    console.log("[DEBUG]", ...args);
    return;
  }
  
  // If specific domain debug is enabled and this is that domain, log it
  if (SPECIFIC_DOMAIN_DEBUG && domain === SPECIFIC_DOMAIN_DEBUG) {
    console.log("[DEBUG]", ...args);
  }
}

/**
 * Check if a domain is resolvable via DNS (IPv4/IPv6)
 * @param {string} domain - Domain to check
 * @returns {Promise<boolean>} True if domain is resolvable
 */
async function isDomainResolvable(domain) {
  try {
    await dns.resolve4(domain);
    debugLog(domain, domain, "DNS resolved via A record");
    return true;
  } catch {
    try {
      await dns.resolve6(domain);
      debugLog(domain, domain, "DNS resolved via AAAA record");
      return true;
    } catch {
      debugLog(domain, domain, "DNS NOT resolved");
      return false;
    }
  }
}

/**
 * Fetch a URL with timeout and return status, headers, and body
 * @param {string} domain - The domain being checked (for logging)
 * @param {string} url - URL to fetch
 * @param {number} timeoutMs - Timeout in milliseconds
 * @returns {Promise<Object>} Response object with status, headers, and body
 */
async function fetchUrl(domain, url, timeoutMs = REQUEST_TIMEOUT_MS) {
  debugLog(domain, "Fetching", url);

  // Extract domain from URL for error logging
  const urlObj = new URL(url);
  const urlDomain = urlObj.hostname;

  return new Promise((resolve) => {
    const client = urlObj.protocol === "https:" ? https : http;

    // Add default headers to the request
    const requestOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port,
      path: urlObj.pathname + urlObj.search,
      method: "GET",
      headers: DEFAULT_HEADERS,
    };

    const timer = setTimeout(() => {
      debugLog(domain, "Timeout fetching", url, "after", timeoutMs, "ms");
      resolve({ status: "TIMEOUT" });
    }, timeoutMs);

    const req = client.request(requestOptions, (res) => {
      clearTimeout(timer);

      // Log response headers
      debugLog(domain, "Response received for", url, "with status", res.statusCode);
      debugLog(domain, "Response headers:");
      Object.entries(res.headers).forEach(function (entry) {
        var key = entry[0];
        var value = entry[1];
        debugLog(domain, "  " + key + ": " + value);
      });

      let body = "";
      res.on("data", (chunk) => {
        if (body.length < 8192) body += chunk.toString();
      });
      res.on("end", () => {
        debugLog(domain, "Response body size:", body.length, "bytes");
        resolve({ statusCode: res.statusCode, headers: res.headers, body });
      });
    });

    req.on("error", (err) => {
      clearTimeout(timer);
      debugLog(domain, "Request error for", url, err.code, err.message);
      if (["ECONNREFUSED", "ENOTFOUND", "EHOSTUNREACH"].includes(err.code))
        resolve({ status: "REFUSED" });
      else if (
        [
          "CERT_HAS_EXPIRED",
          "DEPTH_ZERO_SELF_SIGNED_CERT",
          "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
        ].includes(err.code)
      ) {
        debugLog(
          domain,
          urlDomain,
          "SSL certificate issue detected:",
          err.code,
          err.message,
        );
        resolve({ status: "SSL_ISSUE", error: err.code, message: err.message });
      } else resolve({ status: "UNREACHABLE" });
    });

    // Log when request is initiated
    debugLog(domain, "Initiating request to", url);

    req.end();
  });
}

/**
 * Determine if a page is blank or only contains JavaScript
 * @param {string} domain - The domain being checked (for logging)
 * @param {string} body - Response body to analyze
 * @returns {string|boolean} Status string or false if not empty/JS-only
 */
function isEmptyOrJsOnly(domain, body) {
  if (!body) return "EMPTY_PAGE";

  // Remove head and noscript sections
  let stripped = body.replace(/<head[^>]*>[\s\S]*?<\/head>/gi, "");
  stripped = stripped.replace(/<noscript[^>]*>[\s\S]*?<\/noscript>/gi, "");
  stripped = stripped.replace(/\s/g, "");

  // Extract script content
  const scriptMatches = body.match(/<script[^>]*>([\s\S]*?)<\/script>/gi);
  const scriptContent = scriptMatches
    ? scriptMatches
        .map((script) => script.replace(/<script[^>]*>|<\/script>/gi, ""))
        .join("")
        .trim()
    : "";

  if (stripped === "" && scriptContent) return "JS_ONLY";
  return stripped.length === 0 ? "EMPTY_PAGE" : false;
}

/* ------------------------ DOMAIN CHECKING ------------------------ */

/**
 * Sequential domain check for one domain
 * Tests both HTTPS and HTTP protocols with comprehensive error detection
 * @param {string} domain - Domain to check
 * @returns {Promise<string>} Status result
 */
async function checkDomainStatus(domain) {
  const protocols = ["https", "http"];

  for (const protocol of protocols) {
    let url = `${protocol}://${domain}`;
    const visited = new Set();
    let redirects = 0;

    while (redirects < MAX_REDIRECTS) {
      if (visited.has(url)) {
        debugLog(domain, domain, "Redirect loop detected at", url);
        return "REDIRECT_LOOP";
      }
      visited.add(url);

      const { status, statusCode, headers, body, error, message } =
        await fetchUrl(domain, url);

      if (status) {
        debugLog(domain, domain, "Low-level status:", status);
        // Special handling for SSL errors
        if (status === "SSL_ISSUE") {
          debugLog(domain, domain, "SSL issue:", error, message);
          // Try HTTP instead of HTTPS for sites with SSL issues
          if (protocol === "https") {
            debugLog(domain, domain, "Will try HTTP instead of HTTPS");
            break; // Exit the while loop to try HTTP
          }
          return status;
        }
        return status;
      }

      // Follow redirects
      if (statusCode >= 300 && statusCode < 400 && headers.location) {
        try {
          const redirectUrl = new URL(headers.location, url);
          // Check if this is a protocol flip (HTTPS to HTTP or vice versa) to the same domain
          if (
            redirectUrl.hostname === domain &&
            ((url.startsWith("https://") && redirectUrl.protocol === "http:") ||
              (url.startsWith("http://") && redirectUrl.protocol === "https:"))
          ) {
            // Check if we've already visited this protocol for this domain
            const protocolKey = `${redirectUrl.protocol}//${redirectUrl.hostname}${redirectUrl.pathname}${redirectUrl.search}`;
            if (visited.has(protocolKey)) {
              debugLog(
                domain,
                domain,
                "Protocol flip redirect loop detected:",
                url,
                "->",
                redirectUrl.toString(),
              );
              // This is a special case - the site works but has a protocol flip loop
              // Let's try to determine if the site is actually accessible
              return "PROTOCOL_FLIP_LOOP";
            }
          }

          url = redirectUrl.toString();
          redirects++;
          debugLog(domain, domain, "Redirect to", url);
          continue;
        } catch (e) {
          debugLog(domain, domain, "Error parsing redirect URL:", headers.location);
          return "INVALID_REDIRECT";
        }
      }

      // HTTP errors
      if (statusCode >= 500) {
        debugLog(domain, domain, "Server error", statusCode);
        // Check for Cloudflare-specific errors and add descriptions
        if (statusCode >= 500 && statusCode <= 526) {
          const errorCode = statusCode.toString();
          if (CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode]) {
            debugLog(
              domain,
              domain,
              `Cloudflare Error ${errorCode}:`,
              CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode],
            );
            // Handle Cloudflare SSL errors (525 and 526) as SSL issues
            if (errorCode === "525" || errorCode === "526") {
              return "SSL_ISSUE";
            }
            // Handle other Cloudflare errors as CLOUDFLARE_ codes
            return `CLOUDFLARE_${errorCode}`;
          }
        }
        return `SERVER_ERROR_${statusCode}`;
      }
      if (statusCode >= 400) {
        debugLog(domain, domain, "Client error", statusCode);
        // Add more specific handling for 403 errors
        if (statusCode === 403) {
          debugLog(
            domain,
            domain,
            "403 Forbidden - Possible bot detection or access restriction",
          );
          // Check if it's a Cloudflare protection
          const isCloudflare =
            headers["server"] && headers["server"].includes("cloudflare");
          const isCloudflareMitigated = headers["cf-mitigated"] === "challenge";

          if (isCloudflare || isCloudflareMitigated) {
            debugLog(
              domain,
              domain,
              "403 appears to be from Cloudflare bot detection",
            );
            return "CLOUDFLARE_BOT_PROTECTION";
          }

          // Check for DDoS-Guard protection
          const isDDoSGuard =
            headers["server"] && headers["server"].includes("ddos-guard");
          if (isDDoSGuard) {
            debugLog(domain, domain, "403 appears to be from DDoS-Guard protection");
            return "DDOS_GUARD_PROTECTION";
          }
        }
        return `CLIENT_ERROR_${statusCode}`;
      }

      // Inspect body
      if (body) {
        // Cloudflare 5xx detection
        for (const code of [
          "500",
          "502",
          "503",
          "504",
          "520",
          "521",
          "522",
          "523",
          "524",
          "525",
          "526",
        ]) {
          if (body.includes(`Error ${code}`)) {
            debugLog(domain, domain, "Cloudflare error detected:", code);
            // Handle Cloudflare SSL errors (525 and 526) as SSL issues
            if (code === "525" || code === "526") {
              return "SSL_ISSUE";
            }
            // Handle other Cloudflare errors as CLOUDFLARE_ codes
            return `CLOUDFLARE_${code}`;
          }
        }

        // WAF / protection detection
        if (
          body.includes("Cloudflare Ray ID") ||
          WAF_PATTERNS.some((p) => body.includes(p))
        ) {
          debugLog(domain, domain, "Protected by WAF");
          return "PROTECTED";
        }

        // Placeholder / blank / JS-only detection
        const emptyCheck = isEmptyOrJsOnly(domain, body);
        if (emptyCheck) {
          debugLog(domain, domain, "Empty/JS-only page detected:", emptyCheck);
          return emptyCheck;
        }

        if (PLACEHOLDER_PATTERNS.some((p) => body.includes(p))) {
          debugLog(domain, domain, "Placeholder page detected");
          return "PLACEHOLDER";
        }
      }

      return "VALID";
    }

    // If we've reached the max redirects, check if it's a protocol flip situation
    if (redirects >= MAX_REDIRECTS) {
      // Check if the last few redirects were protocol flips
      debugLog(
        domain,
        domain,
        "Max redirects reached, checking for protocol flip pattern",
      );
      return "REDIRECT_LOOP";
    }
  }

  return "UNREACHABLE";
}

/**
 * Wrapper function that combines DNS resolution with domain status checking
 * @param {string} domain - Domain to check
 * @returns {Promise<Object>} Result object with domain, status, and metadata
 */
async function checkDomain(domain) {
  const resolvable = await isDomainResolvable(domain);
  if (!resolvable)
    return { domain, status: "EXPIRED", resolvable: false, accessible: false };

  const status = await checkDomainStatus(domain);
  return { domain, status, resolvable: true, accessible: status === "VALID" };
}

/* ------------------------ MAIN EXECUTION ------------------------ */

/**
 * Main function that orchestrates the domain checking process
 * Extracts domains from JSDoc comments, deduplicates them, and checks each one
 */
async function main() {
  const args = process.argv.slice(2);
  
  // Parse arguments
  let categories = null;
  let specificDomain = null;
  
  // Check if --verbose is in the arguments
  const verboseIndex = args.indexOf('--verbose');
  if (verboseIndex !== -1) {
    GLOBAL_DEBUG = true;
    
    // Check if there's a domain specified after --verbose
    if (args[verboseIndex + 1] && !args[verboseIndex + 1].startsWith('-')) {
      specificDomain = args[verboseIndex + 1];
      SPECIFIC_DOMAIN_DEBUG = specificDomain;
      
      // Remove --verbose and the domain from args
      args.splice(verboseIndex, 2);
    } else {
      // Just remove --verbose from args
      args.splice(verboseIndex, 1);
    }
  }
  
  // Remaining args are categories
  categories = args.length ? args : null;

  if (GLOBAL_DEBUG) {
    console.log("Verbose mode enabled");
    if (SPECIFIC_DOMAIN_DEBUG) {
      console.log(`Debug output limited to domain: ${SPECIFIC_DOMAIN_DEBUG}`);
    }
  }

  console.log("Extracting domains from sites directory...");
  console.log(`Categories: ${categories ? categories.join(", ") : "all"}`);
  
  if (specificDomain) {
    console.log(`Checking specific domain only: ${specificDomain}`);
  }

  try {
    let domains;
    if (specificDomain) {
      // If a specific domain is provided, only check that domain
      domains = [specificDomain];
    } else {
      // Otherwise, extract domains from JSDoc as usual
      domains = await extractDomainsFromJSDoc(categories);
    }
    
    const uniqueDomains = deduplicateRootDomains(domains);

    console.log(`Found ${uniqueDomains.length} unique domains`);
    if (!uniqueDomains.length) return console.log("No domains found.");

    // In non-verbose mode, show the "Checking:" header
    if (!GLOBAL_DEBUG) {
      console.log("Checking:");
    }

    const results = [];

    // Sequential checking
    for (const domain of uniqueDomains) {
      // In non-verbose mode, just show the domain being checked
      if (!GLOBAL_DEBUG) {
        console.log(`- ${domain}`);
      } else {
        // In verbose mode, show detailed information as before
        console.log(`\nChecking ${domain}...`);
      }
      
      try {
        const result = await checkDomain(domain);
        results.push(result);
        const icon = STATUS_ICONS[result.status] || "❓";

        // Only show detailed status in verbose mode
        if (GLOBAL_DEBUG) {
          // For Cloudflare errors, show the description
          if (
            result.status.startsWith("CLOUDFLARE_") &&
            CLOUDFLARE_ERROR_DESCRIPTIONS[result.status.split("_")[1]]
          ) {
            const errorCode = result.status.split("_")[1];
            console.log(
              `${icon} ${result.status} - ${CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode]}`,
            );
          } else if (result.status === "PROTOCOL_FLIP_LOOP") {
            console.log(
              `${icon} ${result.status} - Site has HTTP/HTTPS protocol flip but is likely accessible`,
            );
          } else if (result.status === "DDOS_GUARD_PROTECTION") {
            console.log(
              `${icon} ${result.status} - Site is protected by DDoS-Guard and may be accessible in browsers`,
            );
          } else {
            console.log(`${icon} ${result.status}`);
          }
        }
      } catch (error) {
        if (GLOBAL_DEBUG) {
          console.error(`Error checking domain ${domain}:`, error.message);
        }
        results.push({ domain, status: "CHECK_FAILED" });
        if (GLOBAL_DEBUG) {
          console.log(`❌ CHECK_FAILED`);
        }
      }
    }

    // Add blank line after checking section in non-verbose mode
    if (!GLOBAL_DEBUG) {
      console.log(""); // Empty line after domain list
    }

    // Summary - Modified to match owner's preferred format
    console.log("SUMMARY:");
    console.log(""); // Ensure blank line after SUMMARY
    
    const counts = results.reduce((acc, r) => {
      acc[r.status] = (acc[r.status] || 0) + 1;
      return acc;
    }, {});

    // Show VALID count
    const validCount = counts["VALID"] || 0;
    console.log(`✅ VALID: ${validCount}`);

    // Show Problem count (all non-VALID domains)
    const problemCount = results.filter(r => r.status !== "VALID").length;
    console.log(`⚠️ Problem: ${problemCount}`);

    // Show Total count
    console.log(`📊 Total: ${results.length}`);
    console.log(""); // Ensure blank line after summary counts

    // Show detailed problematic domains grouped by status
    const problematic = results.filter(r => r.status !== "VALID");
    if (problematic.length > 0) {
      console.log("PROBLEMATIC DOMAIN(S):");
      console.log(""); // Ensure blank line after PROBLEMATIC DOMAIN(S)
      
      // Group domains by status
      const groupedProblems = {};
      problematic.forEach(r => {
        if (!groupedProblems[r.status]) {
          groupedProblems[r.status] = [];
        }
        groupedProblems[r.status].push(r.domain);
      });
      
      // Display grouped problems
      Object.keys(groupedProblems).forEach((status, index) => {
        // Add extra spacing before each group except the first
        if (index > 0) {
          console.log(""); // Extra blank line between groups
        }
        
        const domains = groupedProblems[status];
        let statusLine = `${STATUS_ICONS[status] || "❓"} ${status}`;
        
        // Add Cloudflare error descriptions if applicable
        if (status.startsWith("CLOUDFLARE_") && CLOUDFLARE_ERROR_DESCRIPTIONS[status.split("_")[1]]) {
          const errorCode = status.split("_")[1];
          statusLine += ` - ${CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode]}`;
        } else if (status === "PROTOCOL_FLIP_LOOP") {
          statusLine += " - Sites with HTTP/HTTPS protocol flip but likely accessible";
        }
        
        console.log(statusLine);
        console.log(""); // Blank line after status line
        
        // List domains with indentation
        domains.forEach(domain => {
          console.log(`- ${domain}`);
        });
      });
      
      console.log(""); // Extra blank line at the end
    }

    // Remove the redundant "Found X problematic domain(s)" line
    // This information is already conveyed by the Problem count in the summary
  } catch (error) {
    console.error("Error during domain checking:", error);
    process.exit(1);
  }
}

// Execute the main function and handle any uncaught errors
main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});
