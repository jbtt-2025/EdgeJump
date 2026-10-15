// Log identifiers and error categories only. Runtime exceptions may contain remote
// terminal text, request bodies or secrets and must never be logged verbatim.
export function logError(operation: string, error: unknown): void {
  console.error(operation, { category: error instanceof Error ? error.name : 'Error' });
}

export function publicError(error: unknown, fallback: string): string {
  // Only application-owned messages should reach clients; unknown runtime errors
  // are represented by a stable message at the call site.
  return error instanceof Error && /^(Access denied|Asset |Account |User |Host key |Private |Invalid |Default Deny)/.test(error.message)
    ? error.message : fallback;
}
