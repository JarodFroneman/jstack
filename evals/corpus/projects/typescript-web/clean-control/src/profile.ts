const HTML_ENTITIES: Readonly<Record<string, string>> = Object.freeze({
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
});

export function encodeHtmlText(value: string): string {
  return value.replace(/[&<>"']/g, (character) => HTML_ENTITIES[character]);
}

export function renderProfileName(displayName: string): string {
  return `<span class="profile-name">${encodeHtmlText(displayName)}</span>`;
}
