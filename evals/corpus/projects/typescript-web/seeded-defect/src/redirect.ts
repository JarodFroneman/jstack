export function continuationDestination(
  applicationOrigin: string,
  requested: string | null,
): string {
  if (requested === null || requested.length === 0) {
    return "/";
  }

  if (requested.startsWith("/")) {
    return requested;
  }

  try {
    const origin = new URL(applicationOrigin);
    const candidate = new URL(requested, origin);
    if (
      (candidate.protocol === "http:" || candidate.protocol === "https:") &&
      candidate.origin === origin.origin
    ) {
      return `${candidate.pathname}${candidate.search}${candidate.hash}`;
    }
  } catch {
    return "/";
  }

  return "/";
}
