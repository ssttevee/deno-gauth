import GToken, { Credentials, GTokenOptions } from "./gtoken.ts";

export default class GClient {
  private _token: GToken;
  constructor(credentials: GToken);
  constructor(credentials: Credentials | string, options: GTokenOptions);
  constructor(
    credentials: GToken | Credentials | string,
    options?: GTokenOptions,
  ) {
    if (typeof credentials === "string") {
      credentials = JSON.parse(credentials) as Credentials;
    }

    if (!(credentials instanceof GToken)) {
      if (!options) {
        throw new Error("missing gtoken options");
      }

      credentials = new GToken(credentials, options);
    }

    this._token = credentials;
  }

  public token() {
    return this._token.token();
  }

  public async sign(
    input: RequestInfo | URL,
    init?: RequestInit,
  ) {
    const req = new Request(input, init);
    req.headers.set("Authorization", `Bearer ${await this.token()}`);
    return req;
  }

  public async fetch(
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> {
    return fetch(await this.sign(input, init));
  }
}
