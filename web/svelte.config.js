import adapter from "@sveltejs/adapter-node";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    // adapter-node: the app needs a server at runtime to hold tokens in
    // httpOnly cookies and proxy authd (the BFF — see README).
    adapter: adapter(),
  },
};

export default config;
