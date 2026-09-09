import { chromium, BrowserContext, Page } from 'playwright';
import { homedir } from 'os';
import { join } from 'path';
import { existsSync } from 'fs';

const SESSION_PATH = join(homedir(), '.d2l-session');
const D2L_HOST = process.env.D2L_HOST || 'learn.ul.ie';
const HOME_URL = `https://${D2L_HOST}/d2l/home`;

// Some D2L instances federate to several identity providers and show a picker
// (a <select id="entityId"> plus a "Go" button) instead of a single SSO button.
// Broward College (bconline.broward.edu) is one of these. D2L_SSO_IDP chooses
// which provider to submit; leave it unset to accept whatever the page defaults to.
const SSO_IDP = process.env.D2L_SSO_IDP;

// Playwright ships its own Chromium, pinned to whatever version that Playwright
// release was built against. It never auto-updates, so it steadily falls behind
// real Chrome, and D2L eventually rejects it as an unsupported browser.
// Driving the locally installed Google Chrome instead keeps us on a browser that
// updates itself. Set D2L_BROWSER_CHANNEL=bundled to force Playwright's Chromium.
const BROWSER_CHANNEL = process.env.D2L_BROWSER_CHANNEL || 'chrome';

// How long to allow when a human is actually typing at the identity provider.
// Institutional SSO often adds MFA - a push notification or a code from a phone -
// which routinely takes longer than a minute. Time out too early and the browser
// closes after the IdP has authenticated but before it redirects back to D2L,
// leaving IdP cookies saved but no D2L session at all.
const MANUAL_LOGIN_TIMEOUT = Number(process.env.D2L_LOGIN_TIMEOUT_MS) || 300000;

/**
 * Open the persistent D2L session profile. Prefers the system Chrome channel and
 * falls back to Playwright's bundled Chromium if that channel is not installed.
 */
async function launchContext(headless: boolean): Promise<BrowserContext> {
  const options = { headless, viewport: { width: 1280, height: 720 } };

  if (BROWSER_CHANNEL !== 'bundled') {
    try {
      return await chromium.launchPersistentContext(SESSION_PATH, {
        ...options,
        channel: BROWSER_CHANNEL,
      });
    } catch (error) {
      const reason = (error as Error).message.split('\n')[0];
      console.error(
        `Could not launch browser channel "${BROWSER_CHANNEL}" (${reason}). ` +
        `Falling back to Playwright's bundled Chromium, which D2L may reject as out of date.`
      );
    }
  }

  return chromium.launchPersistentContext(SESSION_PATH, options);
}

interface TokenCache {
  token: string;
  expiresAt: number;
}

let tokenCache: TokenCache = { token: '', expiresAt: 0 };

function isLoginPage(url: string): boolean {
  return url.includes('login') || url.includes('microsoftonline') || url.includes('sso') || url.includes('adfs');
}

/**
 * Kick off whichever SSO entry point this D2L instance uses, then wait until we
 * land on a non-login URL. Returns false if no known entry point is on the page,
 * which means the user has to complete the login by hand.
 */
async function startSsoLogin(page: Page, timeout: number): Promise<boolean> {
  // Identity-provider picker (Broward College and other SAML-federated instances).
  const idpSelect = page.locator('select#entityId');
  if (await idpSelect.isVisible({ timeout: 2000 }).catch(() => false)) {
    if (SSO_IDP) {
      await idpSelect.selectOption(SSO_IDP);
    }
    // The Go button's id is generated per-render, so match on class + label instead.
    await page.locator('button.d2l-button:has-text("Go"), button:has-text("Go")').first().click();
    await page.waitForURL((url) => !isLoginPage(url.toString()), { timeout });
    return true;
  }

  // Single-button SSO (University of Limerick and similar).
  const ssoButton = page.locator('button.d2l-button-sso-1, button:has-text("Student & Staff Login")');
  if (await ssoButton.isVisible({ timeout: 2000 }).catch(() => false)) {
    await ssoButton.click();
    await page.waitForURL((url) => !isLoginPage(url.toString()), { timeout });
    return true;
  }

  return false;
}

export async function getToken(): Promise<string> {
  // Return cached token if still valid (with 5 min buffer)
  if (tokenCache.token && Date.now() < tokenCache.expiresAt - 300000) {
    return tokenCache.token;
  }

  const hasExistingSession = existsSync(SESSION_PATH);

  // Always try headless first if session exists - only show browser if login needed
  let context = await launchContext(hasExistingSession);

  try {
    const result = await captureToken(context, hasExistingSession);
    
    // If we need to login and were running headless, restart with headed browser
    if (result.needsLogin && hasExistingSession) {
      await context.close();
      console.error('Session expired, opening browser for login...');
      context = await launchContext(false);
      const retryResult = await captureToken(context, false);
      tokenCache = {
        token: retryResult.token,
        expiresAt: Date.now() + 3600000,
      };
      return retryResult.token;
    }

    tokenCache = {
      token: result.token,
      expiresAt: Date.now() + 3600000, // 1 hour
    };
    return result.token;
  } finally {
    await context.close();
  }
}

async function captureToken(context: BrowserContext, quickCheck: boolean): Promise<{ token: string; needsLogin: boolean }> {
  const page = await context.newPage();
  let capturedToken = '';

  // Listen for requests to capture Authorization header from any D2L API call
  page.on('request', (request) => {
    const url = request.url();
    if (url.includes('/d2l/api/')) {
      const auth = request.headers()['authorization'];
      if (auth?.startsWith('Bearer ')) {
        capturedToken = auth.slice(7);
      }
    }
  });

  // Go to home page
  await page.goto(HOME_URL, { waitUntil: 'networkidle' });

  // Check if we're on login page
  let currentUrl = page.url();
  if (isLoginPage(currentUrl)) {
    // Try to start SSO automatically.
    // The saved browser session should carry us through the IdP without user interaction.
    try {
      const started = await startSsoLogin(page, quickCheck ? 15000 : MANUAL_LOGIN_TIMEOUT);
      if (started) {
        await page.waitForLoadState('networkidle');
      } else if (quickCheck) {
        // Nothing we recognise to click, and we're headless - hand off to a real browser.
        await page.close();
        return { token: '', needsLogin: true };
      }
    } catch {
      // SSO auto-login failed (needs user interaction)
      if (quickCheck) {
        await page.close();
        return { token: '', needsLogin: true };
      }
    }
  }

  // Wait for token capture
  const maxWait = quickCheck ? 10000 : MANUAL_LOGIN_TIMEOUT;
  const startTime = Date.now();

  while (Date.now() - startTime < maxWait) {
    currentUrl = page.url();

    if (!isLoginPage(currentUrl)) {
      // We're logged in, wait for API calls
      if (!capturedToken) {
        await page.waitForTimeout(2000);
        // Try scrolling to trigger more API calls. The page can navigate out from
        // under us mid-SSO, which destroys the execution context - that is a normal
        // race here, not a failure, so keep waiting rather than aborting the run.
        try {
          await page.evaluate(() => window.scrollBy(0, 100));
        } catch {
          // navigated while evaluating; the loop will re-check on the next pass
        }
        await page.waitForTimeout(1000);
      }

      if (capturedToken) {
        break;
      }
    } else if (!quickCheck) {
      // Wait for user to login
      await page.waitForTimeout(2000);
    } else {
      break;
    }
  }

  await page.close();

  if (!capturedToken) {
    if (quickCheck) {
      return { token: '', needsLogin: true };
    }
    throw new Error('Failed to capture authentication token. Please try again.');
  }

  return { token: capturedToken, needsLogin: false };
}

export async function refreshTokenIfNeeded(): Promise<string> {
  return getToken();
}

export function clearTokenCache(): void {
  tokenCache = { token: '', expiresAt: 0 };
}

export function getTokenExpiry(): number {
  return tokenCache.expiresAt;
}

export async function getAuthenticatedContext(): Promise<BrowserContext> {
  const hasExistingSession = existsSync(SESSION_PATH);

  let context = await launchContext(hasExistingSession);

  const page = await context.newPage();
  
  // Go to home to check auth status
  await page.goto(HOME_URL, { waitUntil: 'domcontentloaded' });
  
  let currentUrl = page.url();
  if (isLoginPage(currentUrl)) {
    // Try SSO auto-login
    try {
      const started = await startSsoLogin(page, hasExistingSession ? 15000 : MANUAL_LOGIN_TIMEOUT);
      if (!started) {
        throw new Error('No recognised SSO entry point on the login page');
      }
      await page.waitForLoadState('domcontentloaded');
    } catch {
      // If headless failed to auto-login, restart with visible browser
      if (hasExistingSession) {
        await context.close();
        console.error('Session expired, opening browser for login...');
        context = await launchContext(false);
        const newPage = await context.newPage();
        await newPage.goto(HOME_URL, { waitUntil: 'domcontentloaded' });
        
        // Wait for user to complete login
        await newPage.waitForURL(url => !isLoginPage(url.toString()), { timeout: MANUAL_LOGIN_TIMEOUT });
        await newPage.close();
      }
    }
  }
  
  await page.close();
  return context;
}
