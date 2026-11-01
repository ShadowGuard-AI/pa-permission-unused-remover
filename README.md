# pa-permission-unused-remover
Static scan that removes nothing and changes nothing. It scans Python files in a directory for chmod calls, both the ordinary `os.chmod(...)` form and the `chmod(...)` form after a from import, and suggests review of those calls. When `--check-file-permissions` is given, it also flags world writable files and directories, whatever their exact mode. It does not define or track permissions, does not read usage history, and does not monitor anything at runtime, so it cannot say a permission is unused; the report flag lists overly permissive entries only. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-permission-unused-remover`

## Usage
`python3 main.py [params]`

A run that analyzes and checks no files prints a nothing checked line and exits 1, instead of reporting a clean result. `--report-unused-permissions` without `--check-file-permissions` is an argument error at exit 2.

## Parameters
- `-h`: Show help message and exit
- `directory`: The directory to analyze. Defaults to the current directory.
- `-e`, `--exclude`: File patterns to exclude from analysis (e.g., *.txt, /path/to/exclude).
- `-v`, `--verbose`: Enable verbose output (debug logging).
- `--check-file-permissions`: Check file and directory permissions for world writable entries.
- `--report-unused-permissions`: Report overly permissive permissions (requires --check-file-permissions).

## License
Copyright (c) ShadowStrikeHQ
