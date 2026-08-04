# GitHub Upload Guide

This folder is the clean source package for takeWxapkg.

## Upload

Upload the contents of this folder to a new GitHub repository.

Recommended commands:

```powershell
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/<your-name>/takeWxapkg.git
git push -u origin main
```

## Do Not Upload

Do not upload local build or runtime data:

- `.venv/`
- `build/`
- `dist/`
- `output/`
- `outputs/`
- `work/`
- `__pycache__/`
- `*.wxapkg`
- `*.zip`
- `build_exe.bat`
- `vendor/wx_decompiler_runtime/`

## Optional Runtime

`vendor/wx_decompiler_runtime/` is ignored by default. Keep it local when building
your own exe. If you publish a binary that includes a third-party runtime, include
`THIRD_PARTY_NOTICES.md` and the relevant license text.
