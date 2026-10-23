# Windows Network Troubleshooter

Read-only Windows 11 checks for hostname resolution, SMB/RDP connectivity and delayed share access.

## Requirements

Windows 11 with built-in Windows PowerShell 5.1. Keep the BAT and PS1 together.
No installation is needed. Start without administrator rights; organization policy may block scripts.

## Usage

Open Command Prompt in the downloaded folder. In PowerShell, prefix BAT commands with `.\`.

```bat
network-troubleshooter.bat help
network-troubleshooter.bat diagnose -Target files.example.test -Share "\\files.example.test\team" -Redact
network-troubleshooter.bat monitor -Target files.example.test -Share "\\files.example.test\team" -DurationSeconds 600 -Redact
```

Replace the example target with a share you are authorized to test. Quote paths containing spaces.

## Behavior

`diagnose` takes one sample. `monitor` checks every five seconds for ten minutes by default.
Slow or unavailable checks are reported; a timeout does not prove a connection failure.
Optional Notepad++ session inspection uses `-InspectSession` or `-SessionPath`.
It reads metadata without opening or changing referenced documents and cannot prove why tabs were lost.

## Outputs

Each run prints its location under a new local `runs/` folder and saves
`timeline.jsonl`, `report.txt` and `report.json`. To regenerate reports offline:

```bat
network-troubleshooter.bat report -InputPath "C:\Captures\run\timeline.jsonl" -OutputDirectory "C:\Captures\new report" -Redact
```

`-OutputDirectory` requires a new absolute local folder. `report -Redact` also writes
a sanitized timeline. Exit 0 means processing completed, even if probes failed;
exit 1 means invalid input or an operational failure.

## Safety and privacy

No repairs, settings changes, tasks or reboots. Checks send normal network and
Windows authentication traffic under your account; `-TargetIP` changes transport only.
There is no telemetry or upload. Use `-Redact` when capturing and review files before
sharing: raw captures can identify people and paths, and arbitrary imported JSON may retain private data.

## Troubleshooting

Run `network-troubleshooter.bat help` in a terminal to check startup; expect exit 0.
An invalid command exits 1 without probing a target. Review timed-out or unavailable
checks before drawing conclusions about the network.

Report issues with the command, Windows version, exit code and expected/actual result.
Omit real captures, private paths and account details.
