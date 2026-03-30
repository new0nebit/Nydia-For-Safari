import { logDebug, logError } from '../logger';
import { uploadPasskeyDirect } from '../sia';
import { getEncryptedRecord, markSyncedIfStillCurrent, savePasskeyETag } from '../store';
import type { UploadResult } from './types';

interface UploadEntry {
  promise: Promise<UploadResult>;
  rerun: boolean;
}

const inFlight = new Map<string, UploadEntry>();

async function doUpload(uniqueId: string): Promise<UploadResult> {
  const record = await getEncryptedRecord(uniqueId);
  if (!record) return { success: false, error: 'Passkey not found' };

  const result = await uploadPasskeyDirect(record);

  if (!result.success) {
    logError(`[Uploader] Upload failed for ${uniqueId}`, result.error);
    return { success: false, error: result.error };
  }

  if (result.etag) {
    await savePasskeyETag(uniqueId, result.etag);
  }

  const markedSynced = await markSyncedIfStillCurrent(record);
  if (!markedSynced) {
    logDebug('[Uploader] Skipped sync flag: record changed since upload');
  }

  return { success: true, etag: result.etag };
}

export function enqueueUpload(uniqueId: string): Promise<UploadResult> {
  const existing = inFlight.get(uniqueId);
  if (existing) {
    existing.rerun = true;
    return existing.promise;
  }

  const entry: UploadEntry = {
    rerun: false,
    promise: Promise.resolve<UploadResult>({ success: true, etag: null }),
  };

  entry.promise = (async () => {
    try {
      let result: UploadResult;
      do {
        entry.rerun = false;
        result = await doUpload(uniqueId);
      } while (entry.rerun);
      return result;
    } catch (error) {
      logError('[Uploader] Upload error', error);
      return { success: false, error: error instanceof Error ? error.message : String(error) };
    } finally {
      inFlight.delete(uniqueId);
    }
  })();

  inFlight.set(uniqueId, entry);
  return entry.promise;
}
