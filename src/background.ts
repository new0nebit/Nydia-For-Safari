import {
  createCredential,
  getAvailableCredentials,
  handleGetAssertion,
} from './authenticator';
import { logDebug, logError, logInfo } from './logger';
import {
  handleMessageInBackground,
  getRootKeyIfAvailable,
  setRootKey,
} from './store';
import { enqueueUpload } from './sync/uploader';
import { handleFullSync } from './sync/syncer';
import {
  BackgroundMessage,
  CredentialCreationOptions,
  GetAssertionOptions,
  SerializedCreationOptions,
  SerializedCredentialDescriptor,
  SerializedRequestOptions,
} from './types';
import { toArrayBuffer } from './utils/buffer';

// RSA wrapping key pair for secure key transfer
let wrappingKeyPair: CryptoKeyPair | null = null;

// RSA key pair generation for secure key transfer
async function initializeWrappingKey(): Promise<CryptoKeyPair> {
  logDebug('[Background] Generating RSA-OAEP key pair for secure transfer');

  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    false, // private key not extractable
    ['wrapKey', 'unwrapKey'],
  );

  logDebug('[Background] RSA-OAEP key pair generated');
  return keyPair;
}

function secureCleanup(data: Uint8Array | null): void {
  data?.fill(0);
}

function normalizeDescriptor(
  descriptors?: SerializedCredentialDescriptor[],
): PublicKeyCredentialDescriptor[] | undefined {
  return descriptors?.map((descriptor) => ({
    type: (descriptor.type ?? 'public-key') as PublicKeyCredentialType,
    id: toArrayBuffer(descriptor.id),
    transports: descriptor.transports as AuthenticatorTransport[] | undefined,
  }));
}

function toCreationOptions(options: SerializedCreationOptions): CredentialCreationOptions {
  const { publicKey } = options;
  const { origin } = options;

  if (!publicKey?.challenge) {
    throw new Error('Invalid options: challenge is required');
  }
  if (!publicKey.user) {
    throw new Error('Invalid options: user is required');
  }
  if (!publicKey.pubKeyCredParams) {
    throw new Error('Invalid options: pubKeyCredParams is required');
  }

  if (!publicKey.rp?.name) {
    throw new Error('Invalid options: rp.name is required');
  }

  if (!origin) {
    throw new Error('Invalid options: origin is required');
  }

  const rpId = publicKey.rp.id ?? new URL(origin).hostname;

  const rpEntity: PublicKeyCredentialRpEntity = {
    id: rpId,
    name: publicKey.rp.name,
  };

  return {
    publicKey: {
      rp: rpEntity,
      rpId,
      challenge: toArrayBuffer(publicKey.challenge),
      user: {
        ...(publicKey.user as CredentialCreationOptions['publicKey']['user']),
        id: toArrayBuffer(publicKey.user.id),
      },
      pubKeyCredParams: publicKey.pubKeyCredParams,
      excludeCredentials: normalizeDescriptor(publicKey.excludeCredentials),
    },
    origin,
  };
}

function toGetAssertionOptions(options: SerializedRequestOptions): GetAssertionOptions {
  const { publicKey } = options;
  const { origin } = options;

  if (!publicKey?.challenge) {
    throw new Error('Invalid options: challenge is required');
  }

  if (!origin) {
    throw new Error('Invalid options: origin is required');
  }

  const rpId = publicKey.rpId ?? new URL(origin).hostname;

  return {
    publicKey: {
      ...publicKey,
      rpId,
      challenge: toArrayBuffer(publicKey.challenge),
      allowCredentials: normalizeDescriptor(publicKey.allowCredentials),
    },
    origin,
  };
}

// Type guard for BackgroundMessage
function isBackgroundMessage(message: unknown): message is BackgroundMessage {
  return (
    typeof message === 'object' &&
    message !== null &&
    'type' in message &&
    typeof (message as { type: unknown }).type === 'string'
  );
}

async function handleGetWrappingPublicKey() {
  try {
    if (!wrappingKeyPair) {
      wrappingKeyPair = await initializeWrappingKey();
    }

    const publicKeyBuffer = await crypto.subtle.exportKey('spki', wrappingKeyPair.publicKey);

    return {
      publicKey: Array.from(new Uint8Array(publicKeyBuffer)),
      algorithm: 'RSA-OAEP',
      hash: 'SHA-256',
    };
  } catch (error: unknown) {
    logError('[Background] Failed to export public key', error);
    return { error: 'Failed to generate wrapping key' };
  }
}

async function handleStoreWrappedKey(wrappedKey: unknown) {
  if (!Array.isArray(wrappedKey)) {
    return { error: 'Invalid wrapped key format' };
  }

  if (!wrappingKeyPair) {
    return { error: 'Wrapping key pair not initialized' };
  }

  let wrappedKeyBytes: Uint8Array | null = null;

  try {
    wrappedKeyBytes = new Uint8Array(wrappedKey);

    const rootKey = await crypto.subtle.unwrapKey(
      'raw',
      wrappedKeyBytes as BufferSource,
      wrappingKeyPair.privateKey,
      { name: 'RSA-OAEP' },
      { name: 'HKDF' },
      false,
      ['deriveKey'],
    );

    await setRootKey(rootKey);
    wrappingKeyPair = null;

    logDebug('[Background] Root key securely stored and RSA keys cleaned up');
    return { status: 'ok' };
  } catch (error: unknown) {
    logError('[Background] Failed to unwrap and store key', error);
    wrappingKeyPair = null;

    if (error instanceof DOMException) {
      switch (error.name) {
        case 'OperationError':
          return { error: 'Failed to unwrap key - invalid or corrupted data' };
        case 'DataError':
          return { error: 'Invalid key format' };
        default:
          return { error: `Crypto operation failed: ${error.name}` };
      }
    }

    return { error: 'Failed to store key securely' };
  } finally {
    secureCleanup(wrappedKeyBytes);
  }
}

// Router
async function router(message: BackgroundMessage): Promise<unknown> {
  try {
    switch (message.type) {
      case 'createCredential':
        if (!(await getRootKeyIfAvailable())) {
          logDebug('[Background] createCredential blocked: rootKeyMissing');
          return { error: 'rootKeyMissing' };
        }
        if (!message.options?.publicKey) {
          logDebug('[Background] createCredential blocked: Invalid options: publicKey is required');
          return { error: 'Invalid options: publicKey is required' };
        }
        return await createCredential(toCreationOptions(message.options as SerializedCreationOptions));

      case 'handleGetAssertion':
        if (!message.options?.publicKey) {
          logDebug('[Background] handleGetAssertion blocked: Invalid options: publicKey is required');
          return { error: 'Invalid options: publicKey is required' };
        }
        if (!message.selectedUniqueId) {
          logDebug('[Background] handleGetAssertion blocked: Missing selectedUniqueId');
          return { error: 'Missing selectedUniqueId' };
        }
        return await handleGetAssertion(
          toGetAssertionOptions(message.options as SerializedRequestOptions),
          message.selectedUniqueId,
        );

      case 'getAvailableCredentials':
        if (!(await getRootKeyIfAvailable())) {
          logDebug('[Background] getAvailableCredentials blocked: rootKeyMissing');
          return { error: 'rootKeyMissing' };
        }
        return await getAvailableCredentials(
          message.rpId!,
          Array.isArray(message.allowCredentialIds) ? message.allowCredentialIds : undefined,
        );

      case 'uploadToSia':
        if (!message.uniqueId) return { success: false, error: 'Missing uniqueId' };
        return await enqueueUpload(message.uniqueId);

      case 'fullSync':
        return await handleFullSync();

      case 'getWrappingPublicKey':
        return await handleGetWrappingPublicKey();

      case 'storeWrappedKey':
        return await handleStoreWrappedKey(message.wrappedKey);

      // proxy → store.ts
      default:
        return await handleMessageInBackground(message);
    }
  } catch (error: unknown) {
    const isExpectedInvalidStateError =
      error instanceof DOMException && error.name === 'InvalidStateError';

    if (!isExpectedInvalidStateError) {
      logError('[Background] router error', error);
    }

    const errorMessage = error instanceof Error ? error.message : String(error);
    return { error: errorMessage };
  }
}

// Bootstrap
logInfo('[Background] bootstrap');
browser.runtime.onMessage.addListener((message: unknown) => {
  if (!isBackgroundMessage(message)) {
    logError('[Background] Invalid message format', message);
    return Promise.resolve({ error: 'Invalid message format' });
  }
  return router(message);
});

getRootKeyIfAvailable().catch(logError);
logInfo('[Background] ready');
