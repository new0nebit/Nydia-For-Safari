// Structured transport of DOMException identity across extension layers.
// Only name and message cross contexts; names are validated again before a
// DOMException is reconstructed for the relying party.

const ALLOWED_DOM_ERROR_NAMES: ReadonlySet<string> = new Set([
  'AbortError',
  'ConstraintError',
  'EncodingError',
  'InvalidStateError',
  'NotAllowedError',
  'NotSupportedError',
  'SecurityError',
  'TimeoutError',
  'UnknownError',
]);

export type SerializedError = {
  message: string;
  name?: string;
};

export function serializeError(error: unknown): SerializedError {
  if (error instanceof DOMException) {
    return { message: error.message, name: error.name };
  }
  return { message: error instanceof Error ? error.message : String(error) };
}

export function sanitizeDomErrorName(name: string | undefined): string {
  return name !== undefined && ALLOWED_DOM_ERROR_NAMES.has(name)
    ? name
    : 'NotAllowedError';
}

// Popup actions keep recoverable errors local, while WebAuthn DOMExceptions
// are terminal API outcomes that must also be returned to the relying party.
export function isWebAuthnDomException(error: unknown): error is DOMException {
  return error instanceof DOMException && ALLOWED_DOM_ERROR_NAMES.has(error.name);
}

export function toDomException(
  message: string | undefined,
  name: string | undefined,
): DOMException {
  return new DOMException(message ?? 'Operation failed', sanitizeDomErrorName(name));
}
