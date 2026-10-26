---
name: Metadata & Asset Recon
description: Inspect embedded file metadata (EXIF, author/software tags, GPS, comments) with the `metadata` tool, and treat unusual-looking catalog items, attachments, and exports as recon targets rather than skipping them. Use whenever a challenge/task description names a file type or property ("blueprint", "hidden message", "original photo", "the export") instead of a literal filename, or when a target serves user- or product-uploaded assets.
---

# Metadata & Asset Recon

## The anti-pattern this skill exists to kill
A task or challenge description is a description of what to find, not a filename to guess. "Retrieve the blueprint" does not mean a file literally named `blueprint.pdf` or `blueprint.md` exists - it means some file, under whatever name it actually has, *is* the blueprint. Treat every task name as a *property* to verify (file type, content, purpose), not a string to pattern-match against directory listings. If a handful of guessed literal filenames 404, that is not evidence the asset doesn't exist - it's evidence you're guessing names instead of browsing.

Concretely: before giving up on "I can't find file X", enumerate what's actually there (product listings, attachment/upload endpoints, `surface`'s discovered asset paths, directory/catalog browsing) and inspect candidates by *what they are*, not by whether their name matches the words in the task.

## Metadata is itself an attack surface
Images, PDFs, Office documents, and many other formats carry metadata the uploader didn't intend to expose or didn't know was there: camera/software identifiers, GPS coordinates, author/owner names, revision history, comments, and free-text fields a developer sometimes (ab)uses to stash a hint, a credential, or an internal note. An asset that looks like an ordinary product photo or export can be the actual vector - metadata inspection is a cheap, high-signal step and should be routine for any downloadable file encountered during recon, not just ones that already look suspicious.

Run the `metadata` tool (wraps `exiftool`) against:
- Product/catalog images and attachments, especially ones that stand out as unusual relative to the rest of a catalog (an odd format among JPEGs, an oddly large or small file, an item with no obvious purpose)
- User-uploaded avatars, documents, and exports
- Any file a task description characterizes by *type or property* ("the original", "the design file", "a backup") rather than by name
- Files downloaded during `surface`/`ffuf` asset discovery before deciding they're uninteresting

`metadata` takes either a `url` (it downloads the file itself) or a local `path`, and returns every embedded tag plus a `Notable tags` callout for fields matching GPS/software/comment/author/creator/owner/hint/description/user/copyright - read those first.

## Signals that a catalog/listing is worth a closer look
- An item whose name, description, or image is subtly out of place next to its neighbors (different format, odd phrasing, a product that doesn't quite fit the catalog's theme)
- An asset referenced by the app's own code (bundle strings, API responses) but not obviously surfaced in the UI
- Any file whose extension doesn't match what it's being served as (an `.stl`, `.cad`, or similarly unusual format in an image gallery is itself a hint - 3D/engineering file formats routinely carry software/library metadata as a deliberate signal)

Don't filter "weird-looking" entries out as noise; they are disproportionately likely to be the one the task actually cares about. Pull the full catalog/listing (don't stop at the first page) before concluding an asset doesn't exist.

## Workflow
1. Enumerate real candidates: browse the catalog/listing UI and its backing API, and cross-reference `surface`'s discovered paths - don't rely on guessed literal names.
2. For each plausible candidate (especially anything unusual per the signals above), download and run `metadata` on it.
3. Read the `Notable tags` first; then scan the full tag list for anything that reads as a hint, path, name, or credential rather than routine camera/software boilerplate.
4. If metadata points at a format, tool, or keyword (e.g. a CAD/3D tool name), use that as a pivot - it often names the exact file type or generator the task is actually about.

## Tools
- `metadata` - EXIF/embedded-metadata extraction from a URL or local file
- `surface` - build the path/asset inventory first so "candidates" isn't just what the UI shows
- `ffuf` - confirm or rule out guessed literal filenames quickly, but only as a supplement to real enumeration, never as the primary method
- `http` - fetch a candidate asset/catalog page directly when the UI paginates or lazy-loads

## Reporting
State which specific file carried the relevant metadata, the exact tag(s) and value(s) that mattered, and how you located that file (catalog browsing, bundle reference, `surface` discovery) - not just "found via metadata," since the discovery path is often the more fragile/missable part of the chain. Recommend stripping metadata on upload/export (e.g. `exiftool -all=`) and auditing other assets of the same type for the same leak.
