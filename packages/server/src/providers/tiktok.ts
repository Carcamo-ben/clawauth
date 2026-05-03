import type { IdentityClaims, IdentityProvider } from '../types.js';

/**
 * @todo implement
 *
 * TikTok Login Kit OAuth provider.
 *
 * What this needs:
 *  - Exchange authorization code for access token via:
 *      POST https://open.tiktokapis.com/v2/oauth/token/
 *      body: client_key, client_secret, code, grant_type=authorization_code, redirect_uri
 *  - Fetch user info:
 *      GET https://open.tiktokapis.com/v2/user/info/?fields=open_id,union_id,avatar_url,display_name
 *      Authorization: Bearer <access_token>
 *  - Map: open_id → claims.sub (per-app stable id)
 *         display_name → claims.name
 *         avatar_url → claims.picture
 *         email is NOT provided by TikTok — leave null.
 *
 * Docs: https://developers.tiktok.com/doc/login-kit-web/
 */
export interface TikTokOAuthProviderOptions {
  clientKey: string;
  clientSecret: string;
  redirectUri: string;
}

export class TikTokOAuthProvider implements IdentityProvider {
  readonly name = 'tiktok';
  constructor(_opts: TikTokOAuthProviderOptions) {}
  async verifyToken(_token: string): Promise<IdentityClaims> {
    throw new Error('TikTokOAuthProvider not implemented yet — contributions welcome!');
  }
}
