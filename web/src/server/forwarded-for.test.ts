/**
 * @file The dashboard's `X-Forwarded-For`: the last hop is always the real connection.
 *
 * A fake server class stands in for `http.Server`, so nothing listens on a port and the real class
 * stays unpatched.
 */

import { EventEmitter } from "node:events";
import type http from "node:http";

import { describe, expect, it } from "vitest";

import { appendPeer, forwardPeerAddress } from "./forwarded-for.mjs";

type FakeRequest = {
  headers: Record<string, string | undefined>;
  socket: { remoteAddress?: string };
};

/**
 * Send one request through a patched fake server.
 *
 * @param request - The request to emit.
 * @param event - The event that carries it: an ordinary request or a protocol upgrade.
 * @returns The headers the server's listener saw.
 */
function received(
  request: FakeRequest,
  event: "request" | "upgrade" = "request",
): Record<string, string | undefined> {
  class FakeServer extends EventEmitter {}
  forwardPeerAddress(FakeServer as unknown as typeof http.Server);
  const server = new FakeServer();
  let seen: Record<string, string | undefined> = {};
  server.on(event, (incoming: FakeRequest) => {
    seen = { ...incoming.headers };
  });
  server.emit(event, request);
  return seen;
}

describe("appendPeer", () => {
  it("makes the connection the only hop when the client sent none", () => {
    expect(appendPeer(undefined, "192.0.2.1")).toBe("192.0.2.1");
  });

  it("keeps what the client sent to the left of the connection", () => {
    expect(appendPeer("198.51.100.7", "192.0.2.1")).toBe("198.51.100.7, 192.0.2.1");
  });

  it("joins a repeated header in order", () => {
    expect(appendPeer(["198.51.100.7", "198.51.100.8"], "192.0.2.1")).toBe(
      "198.51.100.7, 198.51.100.8, 192.0.2.1",
    );
  });

  it("forwards nothing without a peer, since the last hop would be the client's", () => {
    expect(appendPeer("198.51.100.7", undefined)).toBeUndefined();
  });
});

describe("forwardPeerAddress", () => {
  it("rewrites the header before the listener runs", () => {
    const seen = received({
      headers: { "x-forwarded-for": "198.51.100.7" },
      socket: { remoteAddress: "192.0.2.1" },
    });
    expect(seen["x-forwarded-for"]).toBe("198.51.100.7, 192.0.2.1");
  });

  it("rewrites the header of an upgrade request too", () => {
    const seen = received(
      { headers: { "x-forwarded-for": "198.51.100.7" }, socket: { remoteAddress: "192.0.2.1" } },
      "upgrade",
    );
    expect(seen["x-forwarded-for"]).toBe("198.51.100.7, 192.0.2.1");
  });

  it("drops a client's header from an upgrade when the connection has no address", () => {
    const seen = received(
      { headers: { "x-forwarded-for": "198.51.100.7" }, socket: {} },
      "upgrade",
    );
    expect(seen).not.toHaveProperty("x-forwarded-for");
  });

  it("drops a client's header when the connection has no address", () => {
    const seen = received({ headers: { "x-forwarded-for": "198.51.100.7" }, socket: {} });
    expect(seen).not.toHaveProperty("x-forwarded-for");
  });

  it.each(["checkContinue", "connection"])("leaves the %s event alone", (event) => {
    class FakeServer extends EventEmitter {}
    forwardPeerAddress(FakeServer as unknown as typeof http.Server);
    const server = new FakeServer();
    const headers = { "x-forwarded-for": "198.51.100.7" };
    let calls = 0;
    server.on(event, () => {
      calls += 1;
    });
    server.emit(event, { headers, socket: { remoteAddress: "192.0.2.1" } });
    expect(calls).toBe(1);
    expect(headers["x-forwarded-for"]).toBe("198.51.100.7");
  });
});
