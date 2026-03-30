import { logDebug, logError, logInfo } from '../logger';
import {
  downloadPasskeyFromRenterd,
  listPasskeysFromRenterd,
} from '../sia';
import {
  getAllPasskeyETags,
  getAllEncryptedRecords,
  getSettings,
  isEncryptedRecordReadable,
  isStoredRecordReadable,
  reconcileRemoteRecord,
  savePasskeyETag,
} from '../store';
import { enqueueUpload } from './uploader';
import type { FullSyncSummary, ReconcileDecision } from './types';

export async function handleFullSync(): Promise<FullSyncSummary> {
  const settings = await getSettings();
  if (!settings) throw new Error('No renterd settings');

  const summary: FullSyncSummary = {
    uploadedCount: 0,
    downloadedCount: 0,
    updatedCount: 0,
    repairedCount: 0,
    unreadableCount: 0,
    failedCount: 0,
  };

  // Phase 1: Download remote passkeys that need reconciliation with local
  const remotePasskeyFiles = await listPasskeysFromRenterd(settings);
  const remoteListedIds = new Set(remotePasskeyFiles.map(({ uniqueId }) => uniqueId));
  const cachedETags = await getAllPasskeyETags();

  const initialLocalRecords = await getAllEncryptedRecords();
  const localById = new Map(initialLocalRecords.map((record) => [record.uniqueId, record]));
  const repairSet = new Set<string>();

  const downloadResults = await Promise.allSettled(
    remotePasskeyFiles.map(async ({ fileName, uniqueId, etag }) => {
      const shouldDownload =
        !etag ||
        cachedETags.get(uniqueId) !== etag ||
        !localById.has(uniqueId);

      if (!shouldDownload) {
        return { uniqueId, etag, skippedDownload: true as const };
      }

      const remoteRecord = await downloadPasskeyFromRenterd(fileName, settings);
      return { remoteRecord, etag, skippedDownload: false as const };
    }),
  );

  for (let i = 0; i < downloadResults.length; i++) {
    const result = downloadResults[i];
    if (result.status === 'rejected') {
      logError(`[Syncer] Download failed for ${remotePasskeyFiles[i].fileName}`, result.reason);
      summary.failedCount++;
      continue;
    }

    const { etag } = result.value;

    if (result.value.skippedDownload) {
      const localRecord = localById.get(result.value.uniqueId);
      logDebug('[Syncer] Skipped', { reason: 'etag-unchanged', uniqueId: result.value.uniqueId });

      if (localRecord?.isSynced === false) {
        repairSet.add(result.value.uniqueId);
      }

      if (localRecord && !(await isEncryptedRecordReadable(localRecord))) {
        logDebug('[Syncer] Record unreadable with current root key', { uniqueId: result.value.uniqueId });
        summary.unreadableCount++;
      }
      continue;
    }

    const { remoteRecord } = result.value;

    try {
      const decision: ReconcileDecision = await reconcileRemoteRecord(remoteRecord);
      logDebug('[Syncer] Reconcile', { decision, uniqueId: remoteRecord.uniqueId });

      switch (decision) {
        case 'new':
          summary.downloadedCount++;
          break;
        case 'updated':
          summary.updatedCount++;
          break;
        case 'repair':
          repairSet.add(remoteRecord.uniqueId);
          break;
        case 'identical':
          break;
        default: {
          const exhaustive: never = decision;
          void exhaustive;
          throw new Error('Unhandled reconcile decision');
        }
      }

      if (etag) {
        await savePasskeyETag(remoteRecord.uniqueId, etag);
      }

      const recordToCheck =
        decision === 'repair'
          ? null
          : remoteRecord;

      const isReadable = recordToCheck
        ? await isEncryptedRecordReadable(recordToCheck)
        : await isStoredRecordReadable(remoteRecord.uniqueId);

      if (!isReadable) {
        logDebug('[Syncer] Record unreadable with current root key', { uniqueId: remoteRecord.uniqueId });
        summary.unreadableCount++;
      }
    } catch (error) {
      logError(`[Syncer] Reconcile failed for ${remoteRecord.uniqueId}`, error);
      summary.failedCount++;
    }
  }

  // Phase 2: Collect all passkeys that need upload
  const currentLocalRecords = await getAllEncryptedRecords();
  const uploadSet = new Set<string>();
  for (const local of currentLocalRecords) {
    if (!local.isSynced || !remoteListedIds.has(local.uniqueId)) {
      uploadSet.add(local.uniqueId);
    }
  }
  // Add repair set to upload set, removing duplicates
  for (const id of repairSet) {
    uploadSet.add(id);
  }

  // Phase 3: Upload passkeys
  const uploadIds = [...uploadSet];
  if (uploadIds.length > 0) {
    const uploadResults = await Promise.all(
      uploadIds.map((uniqueId) => enqueueUpload(uniqueId)),
    );

    for (let i = 0; i < uploadResults.length; i++) {
      const result = uploadResults[i];
      if (!result.success) {
        summary.failedCount++;
      } else if (repairSet.has(uploadIds[i])) {
        summary.repairedCount++;
      } else {
        summary.uploadedCount++;
      }
    }
  }

  const summaryParts: string[] = [];
  if (summary.uploadedCount) summaryParts.push(`${summary.uploadedCount} uploaded`);
  if (summary.downloadedCount) summaryParts.push(`${summary.downloadedCount} downloaded`);
  if (summary.updatedCount) summaryParts.push(`${summary.updatedCount} updated`);
  if (summary.repairedCount) summaryParts.push(`${summary.repairedCount} repaired`);
  if (summary.unreadableCount) summaryParts.push(`${summary.unreadableCount} unreadable`);
  if (summary.failedCount) summaryParts.push(`${summary.failedCount} failed`);

  logInfo(`[Syncer] Full sync complete: ${summaryParts.join(', ') || 'everything is up to date'}.`);
  return summary;
}
