import type { IdentityClaims, IdentityProvider } from '../types.js';

/**
 * @todo implement
 *
 * Meta (Facebook) OAuth identity provider.
 *
 * What this needs:
 *  - Accept either a short-lived user access token from Facebook Login JS SDK
 *    or an authorization code (for server-side flow).
 *  - For access token flow:
 *      GET https://graph.facebook.com/debug_token?input_token=<TOKEN>&access_token=<APP_ID>|<APP_SECRET>
 *      Verify the response: app_id matches, is_valid=true, not expired.
 *      Then GET https://graph.facebook.com/me?fields=id,name,email,picture&access_token=<TOKEN>
 *  - Map: id → claims.sub, etc.
 *  - Note: Meta doesn't always return email (user can decline). Treat null gracefully.
 *
 * Docs: https://developers.facebook.com/docs/facebook-login/guides/access-tokens/debugging
 */
export interface MetaOAuthProviderOptions {
  appId: string;
  appSecret: string;
}

export class MetaOAuthProvider implements IdentityProvider {
  readonly name = 'meta';
  constructor(_opts: MetaOAuthProviderOptions) {}
  async verifyToken(_token: string): Promise<IdentityClaims> {
    throw new Error('MetaOAuthProvider not implemented yet — contributions welcome!');
  }
}
