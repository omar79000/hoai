# HOAI — MikroTik Management Applications

This repository contains two packaged Windows applications intended for MikroTik management, card generation/printing, sales recording, and reporting.

## Reverse-engineering workspace

The active analysis branch is `reverse-engineering/initial-audit`. It is based on the uploaded archive branch `omar79000-upload-1`; the original uploaded archives are retained unchanged.

### Automated static audit

GitHub Actions workflow: [Reverse Engineering - Static Audit](.github/workflows/reverse-engineering.yml)

The workflow is designed to:
1. Inventory both RAR archives and record SHA-256 hashes.
2. List archive contents and attempt extraction into isolated audit folders.
3. Identify file types, extensions, and likely application technologies.
4. Search readable source/resources/strings for MikroTik RouterOS/API, database, printing, card generation, sales, reporting, and networking indicators.
5. Publish a downloadable artifact named `hoai-static-reverse-engineering-audit`.

Run it from **Actions → Reverse Engineering - Static Audit → Run workflow**, selecting `reverse-engineering/initial-audit`, if the automatic push event did not start it.

### Safety and evidence rules

- Static inspection only: extracted executables, installers, scripts, and macros are never launched.
- Do not test against a production MikroTik router during reverse engineering.
- A string match is only an indicator, not proof that the application executes that command.
- Password-protected, damaged, unsupported, or nested archives may need additional handling.
- Compiled .NET, Java, Delphi, Visual Basic, native, or packed binaries may require dedicated decompilers and manual analysis. Original source code cannot be guaranteed to be recoverable.
- No application behavior, RouterOS compatibility, or runtime safety is considered verified until call sites and behavior are traced and tested in a controlled lab.

## Intended final engineering deliverables

After the archive inventory identifies each application's actual technology and structure, the analysis should document:
- Screen and feature map for each application.
- RouterOS connection method, authentication flow, commands, parameters, and response/error handling.
- User Manager and Hotspot account lifecycle.
- Profiles, packages, speed/limit handling, and other router-side changes.
- Card layout, generation, print pipeline, printer dependencies, and PDF/export behavior.
- Sales data model, calculations, reports, and export formats.
- Local databases, configuration, logs, and credential storage.
- Shared components and differences between the two applications.
- A safe modification plan with regression tests for existing behavior.

No production application code has been changed in this initial audit commit.
