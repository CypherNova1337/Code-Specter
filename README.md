# Code Specter

A bookmarklet that reads a page's own JavaScript and tells you what's interesting.

![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![type](https://img.shields.io/badge/type-bookmarklet-f7df1e?style=flat-square)

## What it does

Every page you visit ships its source code to you. Developers leave things in
it: a `TODO` about the auth check that was never finished, a commented-out admin
endpoint, a `DEBUG` flag, an API path nothing links to.

There's also the code itself. When a page takes something from the URL and
writes it straight into the document — `document.write(location.hash)`,
`element.innerHTML = params.get('q')` — that's the shape of a DOM XSS. Finding
it means tracing where untrusted input enters and where it ends up.

Code Specter does both passes in the browser you already have open. Click the
bookmarklet, and it reports developer notes it found, and any place where
something the user controls flows into a function that can execute or inject.

No proxy, no setup, no sending the page anywhere. It runs on the page in front
of you.

## Why you'd use it

- **One click, zero install.** It's a bookmark. It works on any page, including
  ones behind a login, because it runs in your session.
- **Flags data flow, not just keywords** — it looks for user-controlled input
  reaching `innerHTML`, `eval` or `document.write`, which is the pattern that
  actually matters.
- **Sorts by what's worth your time**, keeping potential injection flows
  separate from informational notes.
- **Nothing leaves the browser.** Useful when you shouldn't be pasting a
  client's source into an online analyser.

## Install

1. Open `Code Specter.js` and copy the whole file.
2. Make a new bookmark in your browser.
3. Name it anything; paste the code as the **URL**.

That's it. It lives in your bookmarks bar.

## Usage

Go to a page and click the bookmark. A panel appears with what it found.

Most useful on:

- **Single-page apps**, where most of the logic is client-side and there's a lot
  to read
- **Pages behind a login**, where the authenticated JavaScript is different from
  what an anonymous crawler sees
- **Anything you're about to test properly** — thirty seconds here often points
  at where to look next

## Good to know

- **It reads what's loaded now.** Code pulled in later by a lazily-loaded bundle
  won't be there until you trigger it. Click around, then re-run.
- **A flow is a lead, not a bug.** Plenty of them pass through sanitisation the
  tool can't see. Confirm by hand.
- **Minified code hides things.** Bundled production JavaScript mangles names
  and strips comments, so a minified page yields much less than a source-mapped
  one.
- **It won't find server-side anything.** This is the client half of the
  application, which is the half you're allowed to read.

## Authorised use

Reading a page's source is what a browser does anyway. Acting on what you find
is different — only do that against targets you own or are in scope for.

## License

MIT — see [LICENSE](LICENSE).
