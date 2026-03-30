export type ReconcileDecision = 'new' | 'updated' | 'identical' | 'repair';

export interface FullSyncSummary {
  uploadedCount: number;
  downloadedCount: number;
  updatedCount: number;
  repairedCount: number;
  unreadableCount: number;
  failedCount: number;
}

export type UploadResult = { success: true } | { success: false; error: string };
