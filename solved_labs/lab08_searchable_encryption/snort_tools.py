"""Snort 3 command helpers and alert-log analysis for Lab 8.

Snort is a system-level network intrusion detection tool.  This file does not
capture traffic itself and never adds ``sudo`` automatically.  It builds
commands for an administrator's authorized lab interface or PCAP and analyzes
an existing alert log with Python.

Usage examples:
    python3 solved_labs/lab08_searchable_encryption/snort_tools.py
    analyze_alert_log("alert_fast.log", "icmp")
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import shutil
import subprocess


def snort_executable() -> str | None:
    """Return the installed Snort path, or ``None`` when unavailable."""

    return shutil.which("snort")


def test_config_command(config: str | Path, rules: str | Path) -> list[str]:
    """Build a Snort 3 configuration/rule validation command."""

    return ["snort", "-c", str(config), "-R", str(rules), "-T"]


def pcap_command(
    config: str | Path, rules: str | Path, pcap: str | Path
) -> list[str]:
    """Build an authorized offline-PCAP inspection command."""

    return [
        "snort",
        "-c",
        str(config),
        "-R",
        str(rules),
        "-r",
        str(pcap),
        "-A",
        "alert_fast",
    ]


def live_command(
    config: str | Path, rules: str | Path, interface: str
) -> list[str]:
    """Build a live-monitoring command; caller must have authorization."""

    return [
        "snort",
        "-c",
        str(config),
        "-R",
        str(rules),
        "-i",
        interface,
        "-A",
        "alert_fast",
    ]


def run_snort(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Run a validated Snort command without invoking a shell."""

    if snort_executable() is None:
        raise FileNotFoundError("Snort executable was not found")
    return subprocess.run(command, check=True, capture_output=True, text=True)


def analyze_alert_log(
    path: str | Path, keyword: str = "", top_n: int = 5
) -> dict[str, object]:
    """Count and filter existing alert lines without sniffing network traffic."""

    if top_n < 1:
        raise ValueError("top_n must be positive")
    log_path = Path(path)
    if not log_path.is_file():
        raise FileNotFoundError(log_path)
    lines = [
        line.strip()
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]
    needle = keyword.casefold().strip()
    matched = [line for line in lines if not needle or needle in line.casefold()]
    return {
        "total_lines": len(lines),
        "matching_lines": matched,
        "top_frequencies": Counter(matched).most_common(top_n),
    }


def demo() -> None:
    """Print safe command examples and a deterministic synthetic-log result."""

    print("Snort available:", snort_executable() is not None)
    print("PCAP command:", pcap_command("snort.lua", "local.rules", "traffic.pcap"))
    print("Live command:", live_command("snort.lua", "local.rules", "lo"))
    temporary_log = Path("/tmp/islab_snort_demo_alerts.log")
    temporary_log.write_text(
        "[1:1000001] ICMP observed\n[1:1000001] ICMP observed\n[1:1000002] TCP observed\n",
        encoding="utf-8",
    )
    print("Synthetic alert analysis:", analyze_alert_log(temporary_log, "icmp"))


def run_menu() -> None:
    """Show Snort helpers and analyze an existing alert log interactively."""

    while True:
        print("\n=== Snort menu ===")
        print("1. Show safe command templates")
        print("2. Analyze an existing alert log")
        print("3. Run a Snort command")
        print("0. Exit")
        choice = input("Choose an example: ").strip()
        if choice == "0" or not choice:
            return
        if choice == "1":
            print("PCAP command:", pcap_command("snort.lua", "local.rules", "traffic.pcap"))
            print("Live command:", live_command("snort.lua", "local.rules", "lo"))
        elif choice == "2":
            try:
                result = analyze_alert_log(
                    input("Alert log path: ").strip(), input("Keyword (optional): ").strip()
                )
                print(result)
            except (FileNotFoundError, OSError, ValueError) as exc:
                print(f"Log analysis failed: {exc}")
        elif choice == "3":
            print("1. Test config  2. Inspect PCAP  3. Monitor interface")
            operation = input("Choose operation: ").strip()
            try:
                if operation == "1":
                    command = test_config_command(
                        input("Config path: ").strip(), input("Rules path: ").strip()
                    )
                elif operation == "2":
                    command = pcap_command(
                        input("Config path: ").strip(),
                        input("Rules path: ").strip(),
                        input("PCAP path: ").strip(),
                    )
                elif operation == "3":
                    command = live_command(
                        input("Config path: ").strip(),
                        input("Rules path: ").strip(),
                        input("Authorized interface: ").strip(),
                    )
                else:
                    print("Invalid operation.")
                    continue
                result = run_snort(command)
                print(result.stdout or result.stderr or "Snort command completed.")
            except (FileNotFoundError, OSError, subprocess.CalledProcessError) as exc:
                print(f"Snort operation failed: {exc}")
        else:
            print("Invalid choice.")


if __name__ == "__main__":  # pragma: no cover - system-dependent command runner.
    run_menu()

