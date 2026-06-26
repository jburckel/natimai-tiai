/** Format an ISO timestamp for display, or a dash when absent. */
export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—';
  return new Date(value).toLocaleString('fr-FR');
}

/** Human label for a nullable boolean (e.g. Defender flags). */
export function boolLabel(value: boolean | null | undefined): string {
  if (value === null || value === undefined) return 'Inconnu';
  return value ? 'Oui' : 'Non';
}
