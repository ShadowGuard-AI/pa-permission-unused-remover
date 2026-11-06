# pa-permission-unused-remover
Static scan that removes nothing and changes nothing. It scans Python files in a directory for chmod calls, both the ordinary `os.chmod(...)` form and the `chmod(...)` form after a from import, and suggests review of those calls. When `--check-file-permissions` is given, it also flags world writable files and directories, whatever their exact mode. It does not define or track permissions, does not read usage history, and does not monitor anything at runtime, so it cannot say a permission is unused; the report flag lists overly permissive entries only. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowGuard-AI/pa-permission-unused-remover`
`pip install -r requirements.txt`

## Usage
`python3 main.py [directory] [-e PATTERN ...] [-v] [--check-file-permissions] [--report-unused-permissions]`

`directory` is optional and defaults to the current directory. All other options are optional flags.

A run that analyzes and checks no files prints the summary table first, then a nothing checked line, and exits 1, instead of reporting a clean result. `--report-unused-permissions` without `--check-file-permissions` is an argument error at exit 2.

## Parameters
- `-h`: Show help message and exit
- `directory` (optional): The directory to analyze. Defaults to the current directory.
- `-e`, `--exclude` (optional): One or more file patterns to exclude from analysis (e.g., *.txt, /path/to/exclude).
- `-v`, `--verbose` (optional): Enable verbose output (debug logging).
- `--check-file-permissions` (optional): Check file and directory permissions for world writable entries.
- `--report-unused-permissions` (optional): Report overly permissive permissions (requires --check-file-permissions).

## License
MIT License. See LICENSE.
