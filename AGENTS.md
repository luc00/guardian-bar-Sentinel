<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

- Threat intel comes from keyless public feeds (OpenPhish, URLhaus) fetched server-side with a 30-min in-memory cache in src/lib/threat-feed.server.ts; matches are injected into the chat instructions — no database needed, always fresh.
- Windows desktop build lives in desktop/ (plain Electron: main.cjs does system scans/actions via PowerShell, ui.html is a standalone panel); packaged by unzipping the Electron win32 zip and copying desktop/ into resources/app, since packager/rcedit needs wine and hangs here.
