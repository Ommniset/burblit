/**
 * Response security headers.
 *
 * Written out rather than delegated to a middleware package. The headers a
 * particular application needs depend on what that application does, and a
 * default set applied without examination would be configuration by habit;
 * each directive here is chosen for a reason recorded beside it. `helmet` is
 * the conventional choice in production and would be appropriate once the
 * reasoning has been settled.
 *
 * These headers defend the browser-side surface. They have no bearing on the
 * end-to-end encryption, which is not something a header can affect, and the
 * distinction matters: an automated scan of this application exercises its
 * web surface and says nothing about its cryptography.
 */

import type { NextFunction, Request, Response } from 'express';

/**
 * Content Security Policy.
 *
 * The strictness available here was bought on day 2, when the inline script
 * and the inline event handlers were removed from the document: a policy
 * without `unsafe-inline` would be impossible otherwise, and `unsafe-inline`
 * would defeat most of the point, since it is precisely injected inline
 * script that cross-site scripting relies on.
 *
 * One relaxation is unavoidable and is a direct consequence of a design
 * decision. `wasm-unsafe-eval` is required because the post-quantum
 * implementation is WebAssembly, and browsers treat instantiating a WASM
 * module as a form of code generation that a strict policy forbids. Choosing
 * liboqs therefore costs a slightly weaker policy than a pure-JavaScript
 * implementation would have required. The token is narrower than
 * `unsafe-eval`, permitting WebAssembly compilation but not `eval` of
 * JavaScript, so the exposure is bounded.
 *
 * `frame-ancestors 'none'` is what actually prevents clickjacking in a modern
 * browser; `X-Frame-Options` below is the same instruction for older ones.
 *
 * Everything the page loads is same-origin, including the liboqs modules
 * copied into the served directory during the build, so `default-src 'self'`
 * needs no exceptions. WebSocket connections to the page's own origin are
 * covered by `connect-src 'self'`.
 */
const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "img-src 'self'",
  "connect-src 'self'",
  "font-src 'self'",
  // Nothing in this application embeds a plugin or another document, and
  // nothing posts a form, so each of these is closed off entirely.
  "object-src 'none'",
  "frame-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'none'",
  // Prevents a `<base>` element injected into the document from redirecting
  // every relative URL, including the script tag, to an attacker's origin.
  "base-uri 'none'",
].join('; ');

/**
 * Applies the response headers to every request.
 *
 * Registered before the static file handler so that it covers the served
 * assets as well as the API, which is where the scan found the omission:
 * the headers were absent from five responses, not one.
 */
export function securityHeaders(request: Request, response: Response, next: NextFunction): void {
  response.setHeader('Content-Security-Policy', CONTENT_SECURITY_POLICY);

  // Stops a browser from disregarding the declared Content-Type and guessing
  // from the bytes instead, which is how a file served as text can end up
  // being executed as script.
  response.setHeader('X-Content-Type-Options', 'nosniff');

  // The same instruction as frame-ancestors, for browsers that predate it.
  response.setHeader('X-Frame-Options', 'DENY');

  // Sends no referrer to another origin. This application has no outbound
  // links, but a username in a path should not become something a third
  // party learns if one is added later.
  response.setHeader('Referrer-Policy', 'no-referrer');

  // None of these device capabilities is used, and a policy that denies what
  // is unused costs nothing while removing it from the attack surface.
  response.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(), usb=()'
  );

  // Strict-Transport-Security is meaningful only over TLS, and a browser
  // ignores it on a plaintext response. Setting it unconditionally would
  // suggest a protection the development configuration does not have.
  if (request.secure) {
    response.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  next();
}
