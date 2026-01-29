# IdentityAuth v2-Modernized - Build Artifacts

This folder contains build scripts and temporary build artifacts.

## Build Scripts

- **Build-PS51Module.ps1** - Builds PowerShell 5.1 module
- **Build-PS7Module.ps1** - Builds PowerShell 7+ module

## VS Code Tasks

Use VS Code tasks to build:
- `Ctrl+Shift+B` → Build: PS5.1 Module (default)
- `Ctrl+Shift+P` → Tasks: Run Task → Build: All Modules

## Manual Build

```powershell
# Build PS5.1 version
.\Build\Build-PS51Module.ps1

# Build PS7 version (requires PowerShell 7+)
pwsh .\Build\Build-PS7Module.ps1

# Or use VS Code task (recommended)
```

## Output

Built modules are placed in:
- `Distribution/IdentityAuth/` (PS5.1)
- `Distribution/IdentityAuth-PS7/` (PS7+)
