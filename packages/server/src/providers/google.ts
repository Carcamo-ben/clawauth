import { OAuth2Client } from 'google-auth-library';
import type { IdentityClaims, IdentityProvider } from '../types.js';

export interface GoogleIdTokenProviderOptions {
  /** Your Google OAuth Client ID. Required — used as the audience. */
  clientId: string;
  /**
   * Optional list of additional accepted audiences (e.g. iOS/Android variants).
   * The primary `clientId` is always accepted.
   */
  additionalAudiences?: string[];
}

/**
 * Verifies a Google-issued ID token (the `credential` you get from Google
 * Identity Services / "Sign in with Google"). Uses google-auth-library
 * which handles JWKS fetching, signature, expiry, and audience checks.
 *
 * Docs: https://developers.google.com/identity/sign-in/web/backend-auth
 */
export class GoogleIdTokenProvider implements IdentityProvider {
  readonly name = 'google';
  private client: OAuth2Client;
  private audiences: string[];

  constructor(opts: GoogleIdTokenProviderOptions) {
    if (!opts.clientId) throw new Error('GoogleIdTokenProvider requires clientId');
    this.client = new OAuth2Client(opts.clientId);
    this.audiences = [opts.clientId, ...(opts.additionalAudiences ?? [])];
  }

  async verifyToken(token: string): Promise<IdentityClaims> {
    const ticket = await this.client.verifyIdToken({
      idToken: token,
      audience: this.audiences
    });
    const payload = ticket.getPayload();
    if (!payload) throw new Error('Google token has no payload');
    if (!payload.sub) throw new Error('Google token missing sub');
    return {
      sub: payload.sub,
      email: payload.email ?? null,
      emailVerified: payload.email_verified ?? false,
      name: payload.name ?? null,
      picture: payload.picture ?? null,
      raw: payload
    };
  }
}
