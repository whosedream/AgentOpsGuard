import { describe, expect, it } from "vitest";
import { buildProxyTarget } from "../lib/proxy";

describe("BFF proxy target builder", () => {
  it("preserves query strings for filtered and paginated API requests", () => {
    expect(buildProxyTarget("http://api:8000/", ["v1", "risks"], "?project_id=default&page_mode=envelope&severity=critical")).toBe(
      "http://api:8000/v1/risks?project_id=default&page_mode=envelope&severity=critical",
    );
  });

  it("encodes dynamic path segments", () => {
    expect(buildProxyTarget("http://api:8000", ["v1", "projects", "team/demo"], "")).toBe("http://api:8000/v1/projects/team%2Fdemo");
  });
});
