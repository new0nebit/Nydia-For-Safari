import { logDebug, logError } from './logger';
import { getSettings } from './store';
import { EncryptedEnvelope, EncryptedRecord, RenterdSettings } from './types';

const PASSKEY_EXTENSION = '.passkey';
const MIME_OCTET_STREAM = 'application/octet-stream';
const QUERY_BUCKET = 'bucket';
const QUERY_MIMETYPE = 'mimetype';

interface RemotePasskeyFile {
  fileName: string;
  uniqueId: string;
  etag: string | null;
}

function isValidEnvelope(value: unknown): value is EncryptedEnvelope {
  return Boolean(
    value &&
      typeof value === 'object' &&
      'iv' in value &&
      typeof (value as { iv: unknown }).iv === 'string' &&
      'data' in value &&
      typeof (value as { data: unknown }).data === 'string',
  );
}

function isValidEncryptedRecord(value: unknown): value is EncryptedRecord {
  return Boolean(
    value &&
      typeof value === 'object' &&
      'uniqueId' in value &&
      typeof (value as { uniqueId: unknown }).uniqueId === 'string' &&
      'metadata' in value &&
      isValidEnvelope((value as { metadata: unknown }).metadata) &&
      'secret' in value &&
      isValidEnvelope((value as { secret: unknown }).secret) &&
      'isSynced' in value &&
      typeof (value as { isSynced: unknown }).isSynced === 'boolean',
  );
}

// Build base URL using saved protocol (detected during settings save).
function buildBaseURL(settings: RenterdSettings): string {
  const protocol = settings.serverProtocol ?? 'http';
  return `${protocol}://${settings.serverAddress}:${settings.serverPort}`;
}

// Base URL builders.
function buildWorkerBaseURL(settings: RenterdSettings): string {
  return `${buildBaseURL(settings)}/api/worker/object`;
}

function buildBusBaseURL(settings: RenterdSettings): string {
  return `${buildBaseURL(settings)}/api/bus`;
}

// Build a URL to list objects in the renterd bucket.
function buildListURL(settings: RenterdSettings, prefix = ''): string {
  return (
    `${buildBusBaseURL(settings)}/objects/${encodeURIComponent(prefix)}` +
    `?${QUERY_BUCKET}=${settings.bucketName}`
  );
}

// Build a URL for uploading/downloading a passkey.
function buildObjectURL(settings: RenterdSettings, fileName: string): string {
  return (
    `${buildWorkerBaseURL(settings)}/${encodeURIComponent(fileName)}` +
    `?${QUERY_BUCKET}=${settings.bucketName}`
  );
}

// URL for PUT uploads.
function buildUploadURL(settings: RenterdSettings, fileName: string): string {
  return (
    `${buildWorkerBaseURL(settings)}/${encodeURIComponent(fileName)}` +
    `?${QUERY_BUCKET}=${settings.bucketName}` +
    `&${QUERY_MIMETYPE}=${encodeURIComponent(MIME_OCTET_STREAM)}`
  );
}

// Create Basic Auth headers for renterd API.
function buildHeaders(
  settings: RenterdSettings,
  contentType?: string,
): HeadersInit {
  const headerMap: HeadersInit = {
    Authorization: 'Basic ' + btoa(`username:${settings.password}`),
  };
  if (contentType) headerMap['Content-Type'] = contentType;
  return headerMap;
}

// Send the request, check for errors, log the result.
async function httpRequest(
  url: string,
  options: RequestInit,
): Promise<Response> {
  const requestURL = new URL(url);
  logDebug('[Sia] Sending request', {
    method: options.method ?? 'GET',
    path: requestURL.pathname,
  });
  const response = await fetch(url, { ...options, cache: 'no-store' });
  logDebug('[Sia] Response status', { status: response.status });

  if (!response.ok) {
    const errorText = `HTTP error! Status: ${response.status} ${response.statusText}`;
    logError('[Sia] Non-successful server response', errorText);
    throw new Error(errorText);
  }
  return response;
}

function normalizeETag(etag: string | null): string | null {
  if (!etag) return null;
  return etag.replace(/^W\//, '').replace(/^"|"$/g, '');
}

// Get a list of passkeys from the bucket.
export async function listPasskeysFromRenterd(
  settings: RenterdSettings,
): Promise<RemotePasskeyFile[]> {
  logDebug('[Sia] Starting listPasskeysFromRenterd', { settings });

  const response = await httpRequest(buildListURL(settings), {
    method: 'GET',
    headers: buildHeaders(settings),
  });
  const jsonData = (await response.json()) as {
    objects?: Array<{ key?: unknown; etag?: unknown; eTag?: unknown }>;
  };
  const objects = jsonData.objects ?? [];
  const passkeyFiles = objects
    .filter((object): object is { key: string; etag?: unknown; eTag?: unknown } => typeof object.key === 'string')
    .map((object) => ({
      fileName: object.key.replace(/^\//, ''),
      etag: normalizeETag(
        typeof object.etag === 'string'
          ? object.etag
          : typeof object.eTag === 'string'
            ? object.eTag
            : null,
      ),
    }))
    .filter(({ fileName }) => fileName.endsWith(PASSKEY_EXTENSION))
    .map(({ fileName, etag }) => ({
      fileName,
      uniqueId: fileName.replace(/\.passkey$/, ''),
      etag,
    }));

  logDebug('[Sia] Found passkey files', { count: passkeyFiles.length, files: passkeyFiles });
  return passkeyFiles;
}

// Upload a passkey to renterd under the uniqueId name.
async function uploadPasskeyToRenterd(
  passkeyData: Blob,
  uniqueId: string,
  settings: RenterdSettings,
): Promise<string | null> {
  const fileName = `${uniqueId}${PASSKEY_EXTENSION}`;
  logDebug('[Sia] Starting uploadPasskeyToRenterd', { fileName });

  const response = await httpRequest(buildUploadURL(settings, fileName), {
    method: 'PUT',
    headers: buildHeaders(settings, MIME_OCTET_STREAM),
    body: passkeyData,
  });
  logDebug('[Sia] Passkey uploaded to renterd', { fileName });
  return normalizeETag(response.headers.get('ETag'));
}

// Download a passkey from renterd and return it as EncryptedRecord.
export async function downloadPasskeyFromRenterd(
  fileName: string,
  settings: RenterdSettings,
): Promise<EncryptedRecord> {
  logDebug('[Sia] Starting downloadPasskeyFromRenterd', { fileName });

  const response = await httpRequest(buildObjectURL(settings, fileName), {
    method: 'GET',
    headers: buildHeaders(settings),
  });
  const record = (await response.json()) as unknown;
  logDebug('[Sia] Downloaded encrypted passkey data', {
    uniqueId:
      record && typeof record === 'object' && 'uniqueId' in record
        ? (record as { uniqueId: unknown }).uniqueId
        : undefined,
  });

  // Validate encrypted passkey shape.
  if (!isValidEncryptedRecord(record)) {
    throw new Error('Invalid encrypted record format');
  }

  return record;
}

// Upload an encrypted passkey record to renterd.
export async function uploadPasskeyDirect(
  record: EncryptedRecord,
): Promise<{ success: true; etag: string | null } | { success: false; error: string }> {
  try {
    const settings = await getSettings();
    if (!settings) {
      return {
        success: false,
        error: 'Please configure renterd settings first.',
      };
    }

    // Clone record and mark as synced.
    const recordToUpload = { ...record, isSynced: true };
    const passkeyDataJson = JSON.stringify(recordToUpload, null, 2);
    const passkeyData = new Blob([passkeyDataJson], {
      type: MIME_OCTET_STREAM,
    });

    const etag = await uploadPasskeyToRenterd(passkeyData, record.uniqueId, settings);
    logDebug('[Sia] Encrypted record prepared and uploaded via renterd worker API', {
      uniqueId: record.uniqueId,
    });
    return { success: true, etag };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      error: `Failed to backup passkey: ${message}`,
    };
  }
}
