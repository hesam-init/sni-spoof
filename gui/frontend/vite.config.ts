import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, type PluginOption } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

const here = dirname(fileURLToPath(import.meta.url));

// Single source of truth for the app icon. Wails generates the desktop icons
// from build/appicon.png (exported from this SVG), and the browser favicon is
// derived from the same SVG here — served in dev via middleware, emitted into
// dist/ at build — so the two can never silently drift. There is intentionally
// no committed favicon.svg; edit build/appicon.svg only.
const appIconSvg = resolve(here, "..", "build", "appicon.svg");

const faviconFromAppIcon = (): PluginOption => ({
  name: "favicon-from-appicon",
  configureServer(server) {
    server.middlewares.use((req, res, next) => {
      if (req.url?.split("?")[0] === "/favicon.svg") {
        res.setHeader("Content-Type", "image/svg+xml");
        res.end(readFileSync(appIconSvg));
        return;
      }
      next();
    });
  },
  generateBundle() {
    this.emitFile({
      type: "asset",
      fileName: "favicon.svg",
      source: readFileSync(appIconSvg),
    });
  },
});

// Vite empties `dist/` at the start of every build, which removes the
// .gitkeep committed to git. Without that placeholder, `go build` (and CI's
// `go vet`) fails on a fresh checkout because `//go:embed all:frontend/dist`
// needs at least one file. This plugin re-creates the placeholder after the
// bundle is written so the working tree stays consistent with the index.
const ensureDistGitkeep = (): PluginOption => ({
  name: "ensure-dist-gitkeep",
  apply: "build",
  writeBundle() {
    writeFileSync(resolve(here, "dist", ".gitkeep"), "");
  },
});

export default defineConfig({
  plugins: [svelte(), faviconFromAppIcon(), ensureDistGitkeep()],
});
