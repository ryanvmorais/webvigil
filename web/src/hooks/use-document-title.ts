/**
 * Set the tab title from data that only the client has (the scan detail names the target).
 * Static titles belong in a route `layout.tsx` `metadata`, rendered on the server.
 */
"use client";

import { useEffect } from "react";

/**
 * Set `document.title` once `title` is known.
 *
 * @param title - The full title, or `undefined` while the data is loading (the route layout's
 *   title stays until then).
 */
export function useDocumentTitle(title: string | undefined): void {
  useEffect(() => {
    if (title) document.title = title;
  }, [title]);
}
