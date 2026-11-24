/**
 * @file Loaded with `node --import` before the standalone server in the Docker image.
 *
 * A separate file so that importing `forwarded-for.mjs` in a test patches nothing.
 */

import http from "node:http";

import { forwardPeerAddress } from "./forwarded-for.mjs";

forwardPeerAddress(http.Server);
