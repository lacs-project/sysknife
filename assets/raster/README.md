# Raster assets

SVG sources live in `../logo/`; these PNGs are rendered for places GitHub
won't accept SVG — namely the **repo social preview** (1280×640) and any
favicon / OG-image consumers.

## Regenerate

```sh
npx --yes svgexport assets/logo/sysknife.svg assets/raster/sysknife-256.png 256:256
npx --yes svgexport assets/logo/sysknife.svg assets/raster/sysknife-1024.png 1024:1024
npx --yes svgexport assets/social-preview.svg assets/social-preview.png 1280:640
```

## Manual upload

GitHub's social-preview API is web-UI-only. To set the repo card image:

1. Go to **Settings** on `lacs-project/sysknife`
2. Scroll to **Social preview**
3. Upload `assets/social-preview.png`

Same flow for org avatar (`assets/raster/sysknife-1024.png`) — open
`https://github.com/organizations/lacs-project/settings/profile`,
upload there.
