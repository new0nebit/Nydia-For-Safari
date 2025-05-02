import { Ed25519, ES256, RS256, SigningAlgorithm } from './algorithms';
import { base64UrlDecode, base64UrlEncode } from './base64url';
import { logError, logInfo } from './logger';
import { uploadPasskeyDirect } from './sia';
import { RenterdSettings, StoredCredential } from './types';

// Web Crypto API
const crypto = self.crypto;
const subtle = crypto.subtle;

/* ================================================
   Helper Functions
================================================ */

// Determines if the current execution context is a background script.
function isBackgroundContext(): boolean {
  try {
    return (
      typeof browser !== 'undefined' &&
      typeof browser.runtime.getBackgroundPage === 'function'
    );
  } catch (error) {
    console.error('Error in isBackgroundContext:', error);
    return false;
  }
}

// Sends a message to the background script or handles it directly if in the background context.
async function sendMessageToExtension(message: any): Promise<any> {
  try {
    if (isBackgroundContext()) {
      logInfo('[store] direct call:', message.type);
      return await handleMessageInBackground(message);
    } else {
      logInfo('[store] runtime.sendMessage →', message.type);
      return await browser.runtime.sendMessage(message);
    }
  } catch (error) {
    logError('Error in sendMessageToExtension:', error);
    throw error;
  }
}

/* ================================================
   IndexedDB Operations
================================================ */

const DB_NAME = 'NydiaDB';
const DB_VERSION = 3;
const STORE_NAME = 'storedCredentials';

// Opens the IndexedDB database.
function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      let objectStore: IDBObjectStore;

      if (!db.objectStoreNames.contains(STORE_NAME)) {
        objectStore = db.createObjectStore(STORE_NAME, { keyPath: 'uniqueId' });
        console.log('Created new object store:', STORE_NAME);
      } else {
        const transaction = request.transaction;
        if (!transaction) {
          const error = new Error('Transaction is undefined in onupgradeneeded event.');
          console.error(error);
          reject(error);
          return;
        }
        objectStore = transaction.objectStore(STORE_NAME);
        console.log('Using existing object store:', STORE_NAME);
      }

      if (!objectStore.indexNames.contains('credentialId')) {
        objectStore.createIndex('credentialId', 'credentialId', { unique: true });
        console.log('Created credentialId index');
      }
      if (!objectStore.indexNames.contains('rpId')) {
        objectStore.createIndex('rpId', 'rpId', { unique: false });
        console.log('Created rpId index');
      }

      if (!db.objectStoreNames.contains('settings')) {
        db.createObjectStore('settings', { keyPath: 'id' });
        console.log('Created settings store');
      }
    };

    request.onsuccess = () => {
      console.log('Database opened successfully');
      resolve(request.result);
    };

    request.onerror = () => {
      console.error('Error opening database:', request.error);
      reject(request.error);
    };
  });
}

/* ================================================
   Settings Management
================================================ */

export async function saveSettings(settings: RenterdSettings): Promise<void> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction('settings', 'readwrite');
    const store = transaction.objectStore('settings');
    const request = store.put({ ...settings, id: 'renterdSettings' });

    request.onsuccess = () => {
      console.log('Settings saved successfully.');
      resolve();
    };

    request.onerror = () => {
      console.error('Error saving settings:', request.error);
      reject(request.error);
    };
  });
}

export async function getSettings(): Promise<RenterdSettings | null> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const request = db
      .transaction('settings', 'readonly')
      .objectStore('settings')
      .get('renterdSettings');

    request.onsuccess = () => resolve((request.result as RenterdSettings) || null);
    request.onerror = () => {
      console.error('Error retrieving settings:', request.error);
      reject(request.error);
    };
  });
}

/* ================================================
   Stored Credential Management
================================================ */

export async function saveStoredCredential(storedCredential: StoredCredential): Promise<void> {
  if (!storedCredential.creationTime) storedCredential.creationTime = Date.now();

  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const request = db
      .transaction(STORE_NAME, 'readwrite')
      .objectStore(STORE_NAME)
      .put(storedCredential);

    request.onsuccess = () => {
      logInfo('StoredCredential saved successfully:', storedCredential.uniqueId);
      resolve();
    };
    request.onerror = () => {
      logError('Error saving StoredCredential:', request.error);
      reject(request.error);
    };
  });
}

async function getStoredCredentialByCredentialId(
  credentialId: string,
): Promise<StoredCredential | undefined> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const request = db
      .transaction(STORE_NAME, 'readonly')
      .objectStore(STORE_NAME)
      .index('credentialId')
      .get(credentialId);

    request.onsuccess = () => resolve(request.result as StoredCredential | undefined);
    request.onerror = () => {
      logError('Error getting StoredCredential by credentialId:', request.error);
      reject(request.error);
    };
  });
}

export async function getAllStoredCredentialsFromDB(): Promise<StoredCredential[]> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).getAll();

    request.onsuccess = () => resolve(request.result as StoredCredential[]);
    request.onerror = () => {
      logError('Error getting all StoredCredentials:', request.error);
      reject(request.error);
    };
  });
}

async function findStoredCredential(
  options: any,
  selectedCredentialId?: string,
): Promise<StoredCredential | undefined> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).getAll();

    request.onsuccess = () => {
      const storedCredentials = (request.result as StoredCredential[]) || [];
      const rpId = options.rpId || new URL(options.origin).hostname;
      let match: StoredCredential | undefined;

      if (selectedCredentialId) {
        match = storedCredentials.find(
          (cred) => cred.credentialId === selectedCredentialId && cred.rpId === rpId,
        );
      } else if (options.allowCredentials?.length) {
        for (const a of options.allowCredentials) {
          const id =
            typeof a.id === 'string' ? a.id : base64UrlEncode(new Uint8Array(a.id));
          match = storedCredentials.find((c) => c.credentialId === id && c.rpId === rpId);
          if (match) break;
        }
      } else {
        match = storedCredentials.find((c) => c.rpId === rpId);
      }
      resolve(match);
    };

    request.onerror = () => {
      logError('Error finding StoredCredential:', request.error);
      reject(request.error);
    };
  });
}

export async function updateCredentialCounter(credentialId: string): Promise<void> {
  const db = await openDatabase();
  const storedCredential = await getStoredCredentialByCredentialId(credentialId);
  if (!storedCredential) throw new Error('Credential not found for updating counter');

  storedCredential.counter++;

  return new Promise((resolve, reject) => {
    const request = db
      .transaction(STORE_NAME, 'readwrite')
      .objectStore(STORE_NAME)
      .put(storedCredential);

    request.onsuccess = async () => {
      logInfo('Credential counter updated', { credentialId, newCounter: storedCredential.counter });
      const res = await uploadPasskeyDirect(storedCredential);
      if (!res.success) logError('Failed to sync updated passkey:', res.error);
      resolve();
    };
    request.onerror = () => {
      logError('Error updating credential counter:', request.error);
      reject(request.error);
    };
  });
}

/* ================================================
   Messaging in Background Context
================================================ */

export async function handleMessageInBackground(message: any): Promise<any> {
  switch (message.type) {
    case 'saveStoredCredential':
      await saveStoredCredential(message.storedCredential);
      return { status: 'success' };
    case 'getStoredCredential':
      return (await getStoredCredentialByCredentialId(message.credentialId)) || {
        error: 'Credential not found',
      };
    case 'findCredential':
      return (await findStoredCredential(message.options, message.selectedCredentialId)) || {
        error: 'Credential not found',
      };
    case 'updateCredentialCounter':
      await updateCredentialCounter(message.credentialId);
      return { status: 'success' };
    case 'getAllStoredCredentials':
      return await getAllStoredCredentialsFromDB();
    default:
      throw new Error('Unknown message type');
  }
}

/* ================================================
   MemoryStore Class
================================================ */

class MemoryStore {
  private static instance: MemoryStore | null = null;
  private store = new Map<string, any>();

  private constructor() {}

  public static getInstance(): MemoryStore {
    return this.instance ?? (this.instance = new MemoryStore());
  }

  public saveAttestationResponse(resp: { id: string }): void {
    this.store.set(resp.id, resp);
    logInfo('Attestation response cached', { id: resp.id });
  }
}

export const getMemoryStore = (): MemoryStore => MemoryStore.getInstance();

/* ================================================
   Utility Functions
================================================ */

export async function createUniqueId(rpId: string, credentialId: string): Promise<string> {
  const data = new TextEncoder().encode(`${rpId}:${credentialId}`);
  const hash = await subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hash));
}

/* ================================================
   Private Key Management
================================================ */

export async function savePrivateKey(
  credentialId: Uint8Array,
  rpId: string,
  privateKey: CryptoKey,
  userId: Uint8Array,
  cosePublicKey: Uint8Array,
  publicKeyAlgorithm: number,
  userIdHash: string,
  userName?: string,
): Promise<void> {
  logInfo('Saving private key');
  const pkcs8 = await subtle.exportKey('pkcs8', privateKey);
  const stored: StoredCredential = {
    uniqueId: await createUniqueId(rpId, base64UrlEncode(credentialId)),
    credentialId: base64UrlEncode(credentialId),
    rpId,
    userIdHash,
    privateKey: base64UrlEncode(new Uint8Array(pkcs8)),
    userHandle: base64UrlEncode(userId),
    publicKey: base64UrlEncode(cosePublicKey),
    publicKeyAlgorithm,
    counter: 0,
    userName,
    creationTime: Date.now(),
  };

  const resp = await sendMessageToExtension({ type: 'saveStoredCredential', storedCredential: stored });
  if (resp?.error) throw new Error(resp.error);
}

export async function loadPrivateKey(
  credentialId: string,
): Promise<[CryptoKey, SigningAlgorithm, number]> {
  const resp = await sendMessageToExtension({ type: 'getStoredCredential', credentialId });
  if (resp?.error) throw new Error(resp.error);

  const record = resp as StoredCredential;
  const pkBuf = base64UrlDecode(record.privateKey);

  let alg: SigningAlgorithm; let params: any;
  if (record.publicKeyAlgorithm === -7) {
    alg = new ES256(); params = { name: 'ECDSA', namedCurve: 'P-256' };
  } else if (record.publicKeyAlgorithm === -257) {
    alg = new RS256(); params = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  } else if (record.publicKeyAlgorithm === -8) {
    alg = new Ed25519(); params = { name: 'Ed25519' };
  } else {
    throw new Error('Unsupported algorithm');
  }

  const key = await subtle.importKey('pkcs8', pkBuf, params, false, ['sign']);
  return [key, alg, record.counter];
}

/* ================================================
   Foreground Proxies
================================================ */

export async function findCredential(
  options: any,
  selectedCredentialId?: string,
): Promise<StoredCredential> {
  const resp = await sendMessageToExtension({
    type: 'findCredential',
    options,
    selectedCredentialId,
  });
  if (resp?.error) throw new Error(resp.error);
  return resp as StoredCredential;
}

export async function getAllStoredCredentials(): Promise<StoredCredential[]> {
  const resp = await sendMessageToExtension({ type: 'getAllStoredCredentials' });
  if (resp?.error) throw new Error(resp.error);
  return resp as StoredCredential[];
}
