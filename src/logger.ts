export function logError(message: string, error?: any) {
  console.error(`[Error] ${message}`, error);
}

export function logInfo(message: string, data?: any) {
  if (data !== undefined) {
    console.log(`[Info] ${message}:`, data);
  } else {
    console.log(`[Info] ${message}`);
  }
}
