# SimPro Patcher

Patches SimPro Manager to allow window resizing.

## What it does

Currently only patches CreateWindow to allow resizing of the main window.

## Usage

**Run as administrator** and point to `SimPro.exe` (make sure SimPro isn't running first), then choose your patch option.

Alternatively, copy `simpro.exe` elsewhere and point the patcher to that copy.

The patcher creates a `simpro.exe.bak` backup file and supports reverting by repatching with the default option.

## Recommendations

I recommend using the last option: **Show native window frame**.

## Compatibility

Supports SimPro Manager V2.1.4, but should work with older versions too since it looks for the signature. Haven't tested older versions though - let me know if you run into issues.