(() => {
  // Abort early if the Credential Management API is unavailable
  if (!('credentials' in navigator)) return;

  // The single remaining log message
  console.log('[Injector] WebAuthn injector initialized');

  /***************************
   * Utility helpers
   ***************************/

  /** base64url‑encoded string → ArrayBuffer */
  const toArrayBuffer = (b64: string): ArrayBuffer => {
    const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
    const len = bin.length;
    const view = new Uint8Array(len);
    for (let i = 0; i < len; ++i) view[i] = bin.charCodeAt(i);
    return view.buffer;
  };

  /** ArrayBuffer → base64url‑encoded string */
  const toBase64url = (buf: ArrayBuffer): string => {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; ++i) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };

  /** Strip AbortSignal to avoid DataClone errors */
  const stripSignal = <T extends { signal?: unknown }>(obj: T): Omit<T, 'signal'> => {
    const { signal, ...rest } = obj as any;
    return rest;
  };

  /** Serialize PublicKeyCredential…Options (ArrayBuffers → base64url) */
  const serializeOptions = (opts: any): any => {
    const out = { ...opts, origin: location.origin };
    if (!out.publicKey) return out;

    const pk = (out.publicKey = { ...out.publicKey });

    if (pk.challenge instanceof ArrayBuffer) pk.challenge = toBase64url(pk.challenge);

    if (pk.user?.id instanceof ArrayBuffer) {
      pk.user = { ...pk.user, id: toBase64url(pk.user.id) };
    }

    const rewrite = (arr?: any[]) =>
      arr?.map((d) => ({ ...d, id: toBase64url(d.id) }));

    pk.allowCredentials = rewrite(pk.allowCredentials);
    pk.excludeCredentials = rewrite(pk.excludeCredentials);

    return out;
  };

  /***************************
   * Transformation helpers
   ***************************/

  const asAuthenticatorResponse = (
    src: any,
  ): AuthenticatorAttestationResponse | AuthenticatorAssertionResponse => {
    if ('attestationObject' in src) {
      // Attestation response
      const att: any = {
        clientDataJSON: toArrayBuffer(src.clientDataJSON),
        attestationObject: toArrayBuffer(src.attestationObject),
        getTransports: () => ['internal', 'hybrid'],
      };

      if (src.publicKeyDER) att.getPublicKey = () => toArrayBuffer(src.publicKeyDER);
      if (src.authenticatorData) att.getAuthenticatorData = () => toArrayBuffer(src.authenticatorData);
      if (src.publicKeyAlgorithm !== undefined)
        att.getPublicKeyAlgorithm = () => src.publicKeyAlgorithm;

      Object.setPrototypeOf(att, AuthenticatorAttestationResponse.prototype);
      return att;
    }

    // Assertion response
    const asr: any = {
      clientDataJSON: toArrayBuffer(src.clientDataJSON),
      authenticatorData: toArrayBuffer(src.authenticatorData),
      signature: toArrayBuffer(src.signature),
      userHandle: src.userHandle ? toArrayBuffer(src.userHandle) : null,
    };
    Object.setPrototypeOf(asr, AuthenticatorAssertionResponse.prototype);
    return asr;
  };

  const asPublicKeyCredential = (raw: any): PublicKeyCredential => {
    const cred: any = {
      id: raw.id,
      rawId: toArrayBuffer(raw.rawId),
      response: asAuthenticatorResponse(raw.response),
      type: raw.type ?? 'public-key',
      authenticatorAttachment: raw.authenticatorAttachment,
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    };
    Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
    return cred;
  };

  /***************************
   * Generic messaging wrapper
   ***************************/

  type Op = 'create' | 'get';

  const wrap =
    (
      op: Op,
      original: (o?: any) => Promise<any>,
    ) =>
    (options?: any): Promise<any> => {
      // Bypass for non‑WebAuthn calls
      if (!options || !('publicKey' in options)) return original.call(navigator.credentials, options);

      const base = `webauthn-${op}`;
      const RESPONSE = `${base}-response`;
      const ERROR = `${base}-error`;
      const FALLBACK = `${base}-fallback`;

      return new Promise((resolve, reject) => {
        const handler = (e: MessageEvent) => {
          if (e.source !== window) return;
          const { type, response, error } = e.data || {};
          switch (type) {
            case RESPONSE:
              window.removeEventListener('message', handler);
              try {
                resolve(asPublicKeyCredential(response));
              } catch (err: any) {
                reject(new DOMException(`Error transforming credential: ${err.message}`, 'NotAllowedError'));
              }
              break;

            case ERROR:
              window.removeEventListener('message', handler);
              reject(new DOMException(error, 'NotAllowedError'));
              break;

            case FALLBACK:
              window.removeEventListener('message', handler);
              original.call(navigator.credentials, options).then(resolve).catch(reject);
              break;
          }
        };

        window.addEventListener('message', handler);
        const payload = serializeOptions(stripSignal(options));
        window.postMessage({ type: base, options: payload }, '*');
      });
    };

  /***************************
   * Custom credentials object
   ***************************/

  type CredsLike = typeof navigator.credentials & {
    store?: typeof navigator.credentials.store;
    preventSilentAccess?: typeof navigator.credentials.preventSilentAccess;
  };

  const orig = navigator.credentials;
  const nydiaCredentials: CredsLike = {
    create: wrap('create', orig.create.bind(orig)),
    get: wrap('get', orig.get.bind(orig)),
    store: orig.store?.bind(orig),
    preventSilentAccess: orig.preventSilentAccess?.bind(orig),
  };

  Object.defineProperty(navigator, 'credentials', {
    value: nydiaCredentials,
    writable: true,
    configurable: true,
  });

  /***************************
   * Static feature overrides
   ***************************/

  if ('PublicKeyCredential' in window) {
    const pkc: any = window.PublicKeyCredential;
    pkc.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
    pkc.isConditionalMediationAvailable = async () => true;
  }
})();
