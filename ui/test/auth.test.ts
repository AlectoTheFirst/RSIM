// The sign-in and the API tokens as data.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ApiProblem, getMe, listTwins, onUnauthorized, retryAfterSeconds, revokeToken, signIn } from "../src/api/client";
import type { TokenInfo } from "../src/api/types";
import { viewOf, viewSearch } from "../src/page/url";
import { chosenScopes, daysValue, initials, problemText, secondsLeft, timeText, tokenState, waitDetail, waitUntil } from "../src/auth/model";

const token = (t: Partial<TokenInfo>): TokenInfo => ({
  id: 1,
  name: "ci",
  scopes: ["rsim.read"],
  created_at: "2026-11-01T10:00:00Z",
  revoked: false,
  ...t,
});

describe("problems", () => {
  it("shows the detail of a problem", () => {
    expect(problemText(new ApiProblem(401, "sign_in_failed", "the user name or the password is wrong"))).toBe(
      "the user name or the password is wrong",
    );
    expect(problemText(new Error("network"))).toBe("network");
  });

  it("reads the seconds of Retry-After", () => {
    expect(retryAfterSeconds("30")).toBe(30);
    expect(retryAfterSeconds(null)).toBeNull();
    expect(retryAfterSeconds("Wed, 21 Oct 2026 07:28:00 GMT")).toBeNull();
  });

  it("counts down the wait of a 429", () => {
    const p = new ApiProblem(429, "too_many_sign_ins", "too many failed sign-ins; wait 30 s", "", 30);
    const until = waitUntil(p, 1000)!;
    expect(until).toBe(31000);
    expect(secondsLeft(until, 12500)).toBe(19);
    expect(secondsLeft(until, 40000)).toBe(0);
    expect(waitDetail(p.detail, 19)).toBe("too many failed sign-ins; wait 19 s");
    expect(waitDetail("too many requests", 4)).toBe("too many requests; wait 4 s");
    expect(waitUntil(new ApiProblem(401, "", "x"), 0)).toBeNull();
  });
});

describe("tokens", () => {
  const now = "2026-11-19T12:00:00Z";
  it("gives the state of a token", () => {
    expect(tokenState(token({}), now)).toBe("active");
    expect(tokenState(token({ revoked: true }), now)).toBe("revoked");
    expect(tokenState(token({ expires_at: "2026-11-18T12:00:00Z" }), now)).toBe("expired");
    expect(tokenState(token({ expires_at: "2026-12-18T12:00:00Z" }), now)).toBe("active");
  });

  it("reads the days of a new token", () => {
    expect(daysValue("")).toBeNull();
    expect(daysValue(" 30 ")).toBe(30);
    expect(daysValue("0")).toBe("invalid");
    expect(daysValue("1.5")).toBe("invalid");
  });

  it("keeps the scopes in the order of the user", () => {
    expect(chosenScopes(["rsim.read", "rsim.inventory.write", "rsim.admin"], new Set(["rsim.admin", "rsim.read"]))).toEqual([
      "rsim.read",
      "rsim.admin",
    ]);
  });

  it("writes a time and the initials", () => {
    expect(timeText("2026-11-01T10:00:00Z", "never")).toBe("2026-11-01 10:00");
    expect(timeText(null, "never")).toBe("never");
    expect(initials("ada.lovelace")).toBe("AL");
    expect(initials("admin")).toBe("AD");
  });
});

describe("the view Tokens in the URL", () => {
  it("reads and writes the view", () => {
    expect(viewOf("?view=tokens")).toBe("Tokens");
    expect(viewSearch("Tokens", "t1")).toBe("?view=tokens&twin=t1");
  });
});

describe("the requests", () => {
  const real = globalThis.fetch;
  let calls = 0;
  const answer = (status: number, body: unknown, headers: Record<string, string> = {}) => {
    globalThis.fetch = (async () =>
      new Response(body === null ? null : JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json", ...headers },
      })) as typeof fetch;
  };
  beforeEach(() => {
    calls = 0;
    onUnauthorized(() => {
      calls += 1;
    });
  });
  afterEach(() => {
    globalThis.fetch = real;
    onUnauthorized(null);
  });

  it("calls the handler on a 401 of a view request", async () => {
    answer(401, { code: "unauthorized", detail: "sign in, or give an API token" });
    await expect(listTwins()).rejects.toBeInstanceOf(ApiProblem);
    expect(calls).toBe(1);
  });

  it("takes a 401 of the sign-in and of the user as an answer", async () => {
    answer(401, { code: "sign_in_failed", detail: "the user name or the password is wrong" });
    await expect(signIn("ada", "x")).rejects.toMatchObject({ status: 401, code: "sign_in_failed" });
    await expect(getMe()).rejects.toMatchObject({ status: 401 });
    expect(calls).toBe(0);
  });

  it("reads the wait of a 429", async () => {
    answer(429, { code: "too_many_sign_ins", detail: "too many failed sign-ins; wait 30 s" }, { "retry-after": "30" });
    await expect(signIn("ada", "x")).rejects.toMatchObject({ status: 429, retryAfter: 30 });
  });

  it("takes a 204 of a revoke", async () => {
    answer(204, null);
    await expect(revokeToken(3)).resolves.toBeUndefined();
  });
});
