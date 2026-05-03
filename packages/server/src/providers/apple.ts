import type { IdentityClaims, IdentityProvider } from '../types.js';

/**
 * @todo implement
 *
 * Apple Sign In ID token verifier.
 *
 * What this needs:
 *  - Fetch JWKS from https://appleid.apple.com/auth/keys
 *  - Verify ID token using `jose` jwtVerify with the matching key
 *  - Verify `iss` === 'https://appleid.apple.com'
 *  - Verify `aud` === your Service ID (or App ID for native flows)
 *  - Map claims:
 *      sub → claims.sub
 *      email → claims.email (note: only present on first sign-in)
 *      email_verified → claims.emailVerified
 *      Apple does NOT provide `name` or `picture` in the ID token.
 *      Names come from the initial Sign-In With Apple POST body and
 *      must be persisted by the client SDK on first auth.
 *
 * Docs: https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api
 */
export interface AppleIdProviderOptions {
  /** Apple Service ID (web) or App ID (native). Used as audience. */
  clientId: string;
}

export class AppleIdProvider implements IdentityProvider {
  readonly name = 'apple';
  constructor(_opts: AppleIdProviderOptions) {}
  async verifyToken(_token: string): Promise<IdentityClaims> {
    throw new Error('AppleIdProvider not implemented yet — contributions welcome!');
  }
}
