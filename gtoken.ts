import { SignJWT } from "https://deno.land/x/jose@v4.10.4/jwt/sign.ts";
import type { KeyLike } from "https://deno.land/x/jose@v4.10.4/types.d.ts";
import { fromPKCS8 } from "https://deno.land/x/jose@v4.10.4/runtime/asn1.ts";

export type Scopes = string | string[];

export interface Credentials {
  // type: string;
  // project_id: string;
  // private_key_id: string;
  private_key: string;
  client_email: string;
  // client_id: string;
  // auth_uri: string;
  // token_uri: string;
  // auth_provider_x509_cert_url: string;
  // client_x509_cert_url: string;
}

interface TokenResponse {
  access_token: string;
  id_token: string;
  expires_in: number;
}

type TokenCache = [number, string];

const TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token";

export interface GTokenScopesOption {
  scopes?: Scopes;
}

export interface GTokenAudienceOption {
  target_audience?: string;
}

export type GTokenOptions = GTokenScopesOption | GTokenAudienceOption;

function isScopes(options: GTokenOptions): options is GTokenScopesOption {
  return Object.prototype.hasOwnProperty.call(options, "scopes");
}

function makeTokenCache(res: TokenResponse): TokenCache {
  if (res.id_token) {
    const claims = JSON.parse(atob(res.id_token.split(".")[1]));
    const expires = claims.exp * 1000;
    return [expires, res.id_token];
  }

  if (res.access_token) {
    const expires = Date.now() + (res.expires_in - 60) * 1000;
    return [expires, res.access_token];
  }

  throw new Error("unexpected gtoken response: " + JSON.stringify(res));
}

export default class GToken {
  private _baseClaims: Record<string, unknown> = { aud: TOKEN_URL };
  private _signer: ReturnType<typeof fromPKCS8>;
  private _cachedToken: Promise<TokenCache> = Promise.resolve([0, ""]);

  constructor(creds: Credentials, opts: GTokenOptions);
  constructor(
    clientEmail: string,
    key: KeyLike | Promise<KeyLike>,
    opts: GTokenOptions,
  );
  constructor(
    ...args: [Credentials, GTokenOptions] | [
      string,
      KeyLike | Promise<KeyLike>,
      GTokenOptions,
    ]
  ) {
    let opts: GTokenOptions;
    if (typeof args[0] === "string") {
      this._baseClaims.iss = args[0];
      this._signer = args[1] as KeyLike;
      opts = args[2] as GTokenOptions;
    } else {
      this._baseClaims.iss = args[0].client_email;
      this._signer = fromPKCS8(args[0].private_key, "RS256");
      opts = args[1] as GTokenOptions;
    }

    if (isScopes(opts)) {
      this._baseClaims.scope = Array.isArray(opts.scopes)
        ? opts.scopes.join(" ")
        : opts.scopes;
    } else {
      this._baseClaims.target_audience = opts.target_audience || undefined;
    }
  }

  public async token(): Promise<string> {
    const cachedToken = await this._cachedToken;

    const now = Date.now();
    if (now < cachedToken[0]) {
      return cachedToken[1];
    }

    return (await (this._cachedToken = this.requestToken().then(
      makeTokenCache,
    )))[1];
  }

  private async buildToken(): Promise<string> {
    return await new SignJWT(this._baseClaims)
      .setProtectedHeader({ alg: "RS256" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(await this._signer);
  }

  private async requestToken(): Promise<TokenResponse> {
    const res = await fetch(TOKEN_URL, {
      body: new URLSearchParams({
        assertion: await this.buildToken(),
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      }),
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      method: "POST",
    });

    return res.json();
  }
}
