/**
 * @file Makes the dashboard's proxy report who is really connecting.
 *
 * Next forwards `/api/*` with whatever `X-Forwarded-For` the client sent and adds nothing to it, so
 * the API could not tell a real address from an invented one. This appends the address of the
 * connection, as a reverse proxy does: the rightmost hop is then the one nobody but this server
 * wrote, and that is the hop the API reads when `web.trusted_proxies` lists the dashboard.
 */

/**
 * The header value to forward.
 *
 * @param {string | string[] | undefined} existing - What the client sent, if anything.
 * @param {string | undefined} peer - The address of the connection.
 * @returns {string | undefined} The value with `peer` as its last hop; `undefined` without a peer,
 *   because a value whose last hop came from the client must not be forwarded.
 */
export const appendPeer = (existing, peer) => {
  if (!peer) return undefined;
  return [...[existing ?? []].flat(), peer].join(", ");
};

/**
 * Rewrite the header of every request a server class receives, before Next sees it.
 *
 * Patched on the class because the standalone `server.js` creates its server privately.
 *
 * @param {typeof import("node:http").Server} serverClass - The class to patch.
 * @returns {void}
 */
export const forwardPeerAddress = (serverClass) => {
  const { emit } = serverClass.prototype;
  // A `function`, not an arrow: `emit` runs with `this` set to the server that received the event.
  /** @type {(this: import("node:http").Server, event: string, ...args: any[]) => boolean} */
  const patched = function (event, ...args) {
    if (event === "request") {
      const { headers, socket } = args[0];
      const value = appendPeer(headers["x-forwarded-for"], socket.remoteAddress);
      if (value === undefined) delete headers["x-forwarded-for"];
      else headers["x-forwarded-for"] = value;
    }
    return emit.call(this, event, ...args);
  };
  serverClass.prototype.emit = /** @type {typeof emit} */ (patched);
};
