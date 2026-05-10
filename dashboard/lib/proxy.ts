export function buildProxyTarget(base: string, path: string[], search = ""): string {
  const normalizedBase = base.replace(/\/$/, "");
  const normalizedPath = path.map((segment) => encodeURIComponent(segment)).join("/");
  return `${normalizedBase}/${normalizedPath}${search}`;
}
