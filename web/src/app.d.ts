import type { Me } from "$lib/types";

// See https://svelte.dev/docs/kit/types#app
declare global {
  namespace App {
    interface Locals {
      // The signed-in user's claims (tier + capabilities), resolved per request
      // from the access-token cookie by hooks.server.ts. Null when signed out.
      me: Me | null;
    }
  }
}

export {};
