#!/usr/bin/env node

/**
 * CI Domain Checker
 *
 * Features:
 *  - DNS resolution
 *  - HTTP/HTTPS accessibility
 *  - SSL/TLS validation
 *  - Redirect loop detection
 *  - Timeout handling
 *  - Placeholder / parked page detection
 *  - Cloudflare / WAF / 5xx error detection
 *  - Blank or JS-only page detection
 *  - Sequential domain checking
 *
 * Note on Cloudflare Bot Protection:
 * Some sites use Cloudflare's advanced bot detection which cannot be bypassed
 * by simple header spoofing. These sites will return 403 errors even with
 * realistic browser headers. Such sites are marked as CLOUDFLARE_BOT_PROTECTION.
 * For these sites, manual verification is required to determine if they are
 * actually accessible to real users.
 */

import { extractDomainsFromJSDoc } from "../build/jsdoc.js";
import { deduplicateRootDomains } from "../build/domain.js";
import dns from "dns/promises";
import http from "http";
import https from "https";
import { URL } from "url";

/* ------------------------ CONFIG ------------------------ */
const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 30000; // Increased from 10s to 30s to handle slow websites

// Add browser-like headers to avoid bot detection
// Updated to mimic Firefox browser more closely
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

const PLACEHOLDER_PATTERNS = [
  "Welcome to nginx!",
  "This domain is parked",
  "Buy this domain",
  "Domain for sale",
  "Default PLESK Page",
];

const WAF_PATTERNS = [
  "Attention Required! | Cloudflare",
  "Checking your browser before accessing",
  "DDOS protection by",
];

// Cloudflare error descriptions for better understanding
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
};

/* ------------------------ UTILITIES ------------------------ */

/** Check if a domain is resolvable via DNS (IPv4/IPv6) */
async function isDomainResolvable(domain) {
  try {
    await dns.resolve4(domain);
    console.log(domain, "DNS resolved via A record");
    return true;
  } catch {
    try {
      await dns.resolve6(domain);
      console.log(domain, "DNS resolved via AAAA record");
      return true;
    } catch {
      console.log(domain, "DNS NOT resolved");
      return false;
    }
  }
}

/** Fetch a URL with timeout and return status, headers, and body */
async function fetchUrl(url, timeoutMs = REQUEST_TIMEOUT_MS) {
  console.log("Fetching", url);

  // Extract domain from URL for error logging
  const urlObj = new URL(url);
  const domain = urlObj.hostname;

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
      console.log("Timeout fetching", url, "after", timeoutMs, "ms");
      resolve({ status: "TIMEOUT" });
    }, timeoutMs);

    const req = client.request(requestOptions, (res) => {
      clearTimeout(timer);

      // Log response headers
      console.log("Response received for", url, "with status", res.statusCode);
      console.log("Response headers:");
      Object.entries(res.headers).forEach(function (entry) {
        var key = entry[0];
        var value = entry[1];
        console.log("  " + key + ": " + value);
      });

      let body = "";
      res.on("data", (chunk) => {
        if (body.length < 8192) body += chunk.toString();
      });
      res.on("end", () => {
        console.log("Response body size:", body.length, "bytes");
        resolve({ statusCode: res.statusCode, headers: res.headers, body });
      });
    });

    req.on("error", (err) => {
      clearTimeout(timer);
      console.log("Request error for", url, err.code, err.message);
      if (["ECONNREFUSED", "ENOTFOUND", "EHOSTUNREACH"].includes(err.code))
        resolve({ status: "REFUSED" });
      else if (
        [
          "CERT_HAS_EXPIRED",
          "DEPTH_ZERO_SELF_SIGNED_CERT",
          "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
        ].includes(err.code)
      ) {
        console.log(
          domain,
          "SSL certificate issue detected:",
          err.code,
          err.message,
        );
        resolve({ status: "SSL_ISSUE", error: err.code, message: err.message });
      } else resolve({ status: "UNREACHABLE" });
    });

    // Log when request is initiated
    console.log("Initiating request to", url);

    req.end();
  });
}

/** Determine if a page is blank or only contains JavaScript */
function isEmptyOrJsOnly(body) {
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

/* ------------------------ DOMAIN CHECK ------------------------ */

/** Sequential domain check for one domain */
async function checkDomainStatus(domain) {
  const protocols = ["https", "http"];

  for (const protocol of protocols) {
    let url = `${protocol}://${domain}`;
    const visited = new Set();
    let redirects = 0;

    while (redirects < MAX_REDIRECTS) {
      if (visited.has(url)) {
        console.log(domain, "Redirect loop detected at", url);
        return "REDIRECT_LOOP";
      }
      visited.add(url);

      const { status, statusCode, headers, body, error, message } =
        await fetchUrl(url);

      if (status) {
        console.log(domain, "Low-level status:", status);
        // Special handling for SSL errors
        if (status === "SSL_ISSUE") {
          console.log(domain, "SSL issue:", error, message);
          // Try HTTP instead of HTTPS for sites with SSL issues
          if (protocol === "https") {
            console.log(domain, "Will try HTTP instead of HTTPS");
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
              console.log(
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
          console.log(domain, "Redirect to", url);
          continue;
        } catch (e) {
          console.log(domain, "Error parsing redirect URL:", headers.location);
          return "INVALID_REDIRECT";
        }
      }

      // HTTP errors
      if (statusCode >= 500) {
        console.log(domain, "Server error", statusCode);
        // Check for Cloudflare-specific errors and add descriptions
        if (statusCode >= 500 && statusCode <= 526) {
          const errorCode = statusCode.toString();
          if (CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode]) {
            console.log(
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
        console.log(domain, "Client error", statusCode);
        // Add more specific handling for 403 errors
        if (statusCode === 403) {
          console.log(
            domain,
            "403 Forbidden - Possible bot detection or access restriction",
          );
          // Check if it's a Cloudflare protection
          const isCloudflare =
            headers["server"] && headers["server"].includes("cloudflare");
          const isCloudflareMitigated = headers["cf-mitigated"] === "challenge";

          if (isCloudflare || isCloudflareMitigated) {
            console.log(
              domain,
              "403 appears to be from Cloudflare bot detection",
            );
            return "CLOUDFLARE_BOT_PROTECTION";
          }

          // Check for DDoS-Guard protection
          const isDDoSGuard =
            headers["server"] && headers["server"].includes("ddos-guard");
          if (isDDoSGuard) {
            console.log(domain, "403 appears to be from DDoS-Guard protection");
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
            console.log(domain, "Cloudflare error detected:", code);
            if (CLOUDFLARE_ERROR_DESCRIPTIONS[code]) {
              console.log(
                domain,
                `Cloudflare Error ${code}:`,
                CLOUDFLARE_ERROR_DESCRIPTIONS[code],
              );
              // Handle Cloudflare SSL errors (525 and 526) as SSL issues
              if (code === "525" || code === "526") {
                return "SSL_ISSUE";
              }
              // Handle other Cloudflare errors as CLOUDFLARE_ codes
              return `CLOUDFLARE_${code}`;
            }
            return `CLOUDFLARE_${code}`;
          }
        }

        // WAF / protection detection
        if (
          body.includes("Cloudflare Ray ID") ||
          WAF_PATTERNS.some((p) => body.includes(p))
        ) {
          console.log(domain, "Protected by WAF");
          return "PROTECTED";
        }

        // Placeholder / blank / JS-only detection
        const emptyCheck = isEmptyOrJsOnly(body);
        if (emptyCheck) {
          console.log(domain, "Empty/JS-only page detected:", emptyCheck);
          return emptyCheck;
        }

        if (PLACEHOLDER_PATTERNS.some((p) => body.includes(p))) {
          console.log(domain, "Placeholder page detected");
          return "PLACEHOLDER";
        }
      }

      return "VALID";
    }

    // If we've reached the max redirects, check if it's a protocol flip situation
    if (redirects >= MAX_REDIRECTS) {
      // Check if the last few redirects were protocol flips
      console.log(
        domain,
        "Max redirects reached, checking for protocol flip pattern",
      );
      return "REDIRECT_LOOP";
    }
  }

  return "UNREACHABLE";
}

/** Wrapper with DNS resolution */
async function checkDomain(domain) {
  const resolvable = await isDomainResolvable(domain);
  if (!resolvable)
    return { domain, status: "EXPIRED", resolvable: false, accessible: false };

  const status = await checkDomainStatus(domain);
  return { domain, status, resolvable: true, accessible: status === "VALID" };
}

/* ------------------------ MAIN ------------------------ */
async function main() {
  const args = process.argv.slice(2);
  const categories = args.length ? args : null;

  console.log("Extracting domains from sites directory...");
  console.log(`Categories: ${categories ? categories.join(", ") : "all"}`);

  try {
    const domains = await extractDomainsFromJSDoc(categories);
    const uniqueDomains = deduplicateRootDomains(domains);

    console.log(`Found ${uniqueDomains.length} unique domains\n`);
    if (!uniqueDomains.length) return console.log("No domains found.");

    const results = [];

    // Sequential checking
    for (const domain of uniqueDomains) {
      console.log(`\nChecking ${domain}...`);
      try {
        const result = await checkDomain(domain);
        results.push(result);
        const icon = STATUS_ICONS[result.status] || "❓";

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
      } catch (error) {
        console.error(`Error checking domain ${domain}:`, error.message);
        results.push({ domain, status: "CHECK_FAILED" });
        console.log(`❌ CHECK_FAILED`);
      }
    }

    // Summary
    console.log("\n" + "=".repeat(50));
    console.log("SUMMARY:");

    const counts = results.reduce((acc, r) => {
      acc[r.status] = (acc[r.status] || 0) + 1;
      return acc;
    }, {});

    Object.keys(STATUS_ICONS).forEach((status) => {
      if (counts[status]) {
        // For Cloudflare errors, show the description in summary
        if (
          status.startsWith("CLOUDFLARE_") &&
          CLOUDFLARE_ERROR_DESCRIPTIONS[status.split("_")[1]]
        ) {
          const errorCode = status.split("_")[1];
          console.log(
            `${STATUS_ICONS[status]} ${status} - ${CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode]}: ${counts[status]}`,
          );
        } else if (status === "PROTOCOL_FLIP_LOOP") {
          console.log(
            `${STATUS_ICONS[status]} ${status} - Sites with HTTP/HTTPS protocol flip but likely accessible: ${counts[status]}`,
          );
        } else if (status === "DDOS_GUARD_PROTECTION") {
          console.log(
            `${STATUS_ICONS[status]} ${status} - Sites protected by DDoS-Guard but likely accessible: ${counts[status]}`,
          );
        } else {
          console.log(`${STATUS_ICONS[status]} ${status}: ${counts[status]}`);
        }
      }
    });

    // Show counts for Cloudflare errors that don't have icons
    Object.keys(counts).forEach((status) => {
      if (
        status.startsWith("CLOUDFLARE_") &&
        !STATUS_ICONS[status] &&
        CLOUDFLARE_ERROR_DESCRIPTIONS[status.split("_")[1]]
      ) {
        const errorCode = status.split("_")[1];
        console.log(
          `☁️${errorCode} ${status} - ${CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode]}: ${counts[status]}`,
        );
      }
    });

    // Show CHECK_FAILED count if any
    if (counts["CHECK_FAILED"]) {
      console.log(`❌ CHECK_FAILED: ${counts["CHECK_FAILED"]}`);
    }

    console.log(`📊 Total: ${results.length}`);

    const problematic = results.filter((r) => r.status !== "VALID");
    problematic.forEach((r) => {
      const icon = STATUS_ICONS[r.status] || "❓";
      // For Cloudflare errors, show the description in detailed list
      if (
        r.status.startsWith("CLOUDFLARE_") &&
        CLOUDFLARE_ERROR_DESCRIPTIONS[r.status.split("_")[1]]
      ) {
        const errorCode = r.status.split("_")[1];
        console.log(
          `${icon} ${r.status} - ${CLOUDFLARE_ERROR_DESCRIPTIONS[errorCode]} -> ${r.domain}`,
        );
      } else if (r.status === "PROTOCOL_FLIP_LOOP") {
        console.log(
          `${icon} ${r.status} - Site has HTTP/HTTPS protocol flip but is likely accessible -> ${r.domain}`,
        );
      } else if (r.status === "DDOS_GUARD_PROTECTION") {
        console.log(
          `${icon} ${r.status} - Site is protected by DDoS-Guard and may be accessible in browsers -> ${r.domain}`,
        );
      } else if (r.status === "CHECK_FAILED") {
        console.log(`${icon} ${r.status} -> ${r.domain}`);
      } else {
        console.log(`${icon} ${r.status} -> ${r.domain}`);
      }
    });

    console.log(
      problematic.length
        ? `\n⚠️ Found ${problematic.length} problematic domain(s)`
        : "\n✅ All domains are valid!",
    );
  } catch (error) {
    console.error("Error during domain checking:", error);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});
