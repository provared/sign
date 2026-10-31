# sign.prova.red

This repository publishes one page: the page on which a person signs a
Provared permission (a slip) with a passkey, at https://sign.prova.red.

Nothing else is ever served at this address, on purpose. A browser lets a
passkey sign only for the website name it was made for and the addresses
under it. A passkey made here can therefore be used by no other page: not
by https://prova.red, not by the application at https://app.prova.red, and
not by a script that gets onto either of them. If the same passkey could be
used by another page, that page could present a record's fingerprint as an
ordinary sign-in question and have the passkey sign a record the person
never saw. The list of threats of Provared describes this in section 3.

## What is here

- `site/`: the signing page (`index.html`, `sign-page.js`, `render.js`,
  `style.css`) and the library's modules in `site/src/`. Each file is a
  byte-for-byte copy of the same file at commit `18c0fe6e576cbe7a80b8b1fd54272c8abfc805b6` of
  https://github.com/provared/provared (`page/sign.html` is served here as
  `index.html`). `site/files.sha256` holds the SHA-256 fingerprint of each.
- `.github/workflows/pages.yml`: checks every file against its
  fingerprint and publishes the folder with GitHub Pages.

The page loads nothing from any other site and keeps nothing on a server.
Its content security policy allows only its own scripts and style sheet.

## What it does not protect against

GitHub serves this site, so GitHub, or anyone who controls this
repository or the address's DNS record, could serve a different page here.
The page shows the permission in words before the passkey is asked, so a
person can read what they sign.

## Licence

Apache License 2.0, as for the code of Provared. Copyright 2026 Pavel
Izmaylov.
