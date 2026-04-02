export type ReconcileDecision = 'new' | 'updated' | 'identical' | 'repair';

export interface FullSyncSummary {
  uploadedCount: number;
  downloadedCount: number;
  updatedCount: number;
  repairedCount: number;
  unreadableCount: number;
  failedCount: number;
}

export type UploadResult = { success: true; etag: string | null } | { success: false; error: string };
