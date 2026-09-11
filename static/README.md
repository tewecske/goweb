# Static Assets

Store browser assets here, including stylesheets, scripts, and images.

## CSS build

Install pinned npm dependencies and build the stylesheet before running the Go
application:

```sh
npm install
npm run build:css
npm run check:assets
```

`src/app.css` is the CSS-first Tailwind 4 entry point. `app.css` is generated,
embedded by Go, and served at `/static/app.css`; do not use a CDN in templates.

Static assets are presentation dependencies. Authentication, authorization,
validation, and state-changing request protection remain server-side.
