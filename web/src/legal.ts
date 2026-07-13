export type LegalVersions = {
  terms: string;
  privacy: string;
  assetBoundary: string;
};

export function legalVersionsMatch(expected: LegalVersions, actual?: Partial<LegalVersions>): boolean {
  return actual !== undefined
    && actual.terms === expected.terms
    && actual.privacy === expected.privacy
    && actual.assetBoundary === expected.assetBoundary;
}
