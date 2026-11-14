# Third-party assets

The API reference uses vendored Swagger UI distribution **5.17.14**, distributed under Apache License 2.0. Its license is included at `sentinel/static/swagger-LICENSE`. Assets are served locally and require no external browser connection.

Source: `https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.17.14/`.

| Asset | SHA-256 |
| --- | --- |
| `swagger-ui-bundle.js` | `c2e4a9ef08144839ff47c14202063ecfe4e59e70a4e7154a26bd50d880c88ba1` |
| `swagger-ui.css` | `40170f0ee859d17f92131ba707329a88a070e4f66874d11365e9a77d232f6117` |

Application dependencies and their resolved versions are listed in `uv.lock` and `frontend/package-lock.json`. The frontend bundles DM Sans and IBM Plex Mono from `@fontsource`, under SIL Open Font License 1.1. Their licenses are included in `licenses/`. React/React DOM and Lucide license notices are also included there.
