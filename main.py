import argparse
import logging
import os
import sys
import ast
import stat
from collections import defaultdict

try:
    import pathspec
    from rich.console import Console
    from rich.table import Table
except ImportError as e:
    print(f"Error: Missing dependencies. Please install them using: pip install pathspec rich")
    sys.exit(1)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Static scan that removes nothing: it flags chmod calls in Python files and, when asked, world writable files and directories, and suggests review."
    )
    parser.add_argument(
        "directory",
        nargs="?",  # Optional directory argument
        default=".",
        help="The directory to analyze for unused permissions. Defaults to the current directory.",
    )
    parser.add_argument(
        "-e",
        "--exclude",
        nargs="+",
        help="File patterns to exclude from analysis (e.g., *.txt, /path/to/exclude).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output (debug logging).",
    )
    parser.add_argument(
        "--check-file-permissions",
        action="store_true",
        help="Check file and directory permissions for world writable entries.",
    )
    parser.add_argument(
        "--report-unused-permissions",
        action="store_true",
        help="Report overly permissive permissions (requires --check-file-permissions).",
    )
    return parser


def is_valid_directory(path):
    """
    Checks if the provided path is a valid directory.

    Args:
        path (str): The path to check.

    Returns:
        bool: True if the path is a valid directory, False otherwise.
    """
    if not os.path.isdir(path):
        logging.error(f"Error: '{path}' is not a valid directory.")
        return False
    return True


def load_exclude_patterns(exclude_patterns):
    """
    Loads exclude patterns into a pathspec object.

    Args:
        exclude_patterns (list): A list of exclude patterns.

    Returns:
        pathspec.PathSpec or None: A PathSpec object if exclude patterns are provided, None otherwise.
    """
    if exclude_patterns:
        try:
            spec = pathspec.PathSpec.from_lines(pathspec.patterns.GitWildMatchPattern, exclude_patterns)
            return spec
        except Exception as e:
            logging.error(f"Error loading exclude patterns: {e}")
            return None
    return None


def analyze_code(directory, exclude_spec=None):
    """
    Analyzes the Python code in the given directory to identify chmod calls.
    Both the ordinary os.chmod(...) form and the from-import chmod(...) form are matched.
    Only files that parse successfully count as analyzed.

    Args:
        directory (str): The directory to analyze.
        exclude_spec (pathspec.PathSpec): A PathSpec object for excluding files.

    Returns:
        dict: A dictionary containing analysis results.
    """
    analysis_results = {"files_analyzed": 0, "potential_issues": []}

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                filepath = os.path.join(root, file)
                if exclude_spec and exclude_spec.match_file(filepath):
                    continue

                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        source_code = f.read()
                    tree = ast.parse(source_code)
                    analysis_results["files_analyzed"] += 1

                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            func = node.func
                            # I match on the call name alone, whatever object it hangs off and whatever arguments it carries. A chmod to a safe mode, a method on an unrelated class that shares the name, and a local helper called chmod all land in the same bucket, because a static name scan cannot tell them apart and I would rather over report here.
                            if (isinstance(func, ast.Attribute) and func.attr == 'chmod') or (isinstance(func, ast.Name) and func.id == 'chmod'):
                                # One line is appended per call, with no line number and no deduplication. A file with five chmod calls appears five times identically in the detail list, so the count in the summary table is a count of calls, not of files with a problem.
                                analysis_results["potential_issues"].append(f"Potential chmod usage in: {filepath}")

                except Exception as e:
                    logging.error(f"Error analyzing {filepath}: {e}")

    return analysis_results

def check_file_permissions(directory, exclude_spec=None):
    """
    Checks file permissions within the specified directory.

    Args:
        directory (str): The directory to check.
        exclude_spec (pathspec.PathSpec): A PathSpec object for excluding files.

    Returns:
        dict: A dictionary containing permission analysis results.
    """
    permission_results = {"files_checked": 0, "insecure_permissions": []}

    for root, dirs, files in os.walk(directory):
        dirs.sort()
        entries = [(os.path.join(root, d), True) for d in dirs] + [(os.path.join(root, f), False) for f in sorted(files)]
        for filepath, is_dir_entry in entries:
            if exclude_spec and exclude_spec.match_file(filepath):
                continue

            # Despite the name, this counter includes directories: the entries list above deliberately mixes both, so files checked in the summary means entries examined. Comparing it against the files analyzed count from the code pass is comparing two different units.
            permission_results["files_checked"] += 1
            try:
                mode = os.stat(filepath).st_mode

                # Flag any world writable file or directory, not only exact 777.
                # os.stat follows symlinks, so a link is judged by its target's type and mode while the path I print is the link's. The printed mode is also masked down to the low nine bits, so a setuid world writable file is displayed without the bit that makes it the most dangerous entry in the list.
                if (stat.S_ISREG(mode) or stat.S_ISDIR(mode)) and (mode & 0o002):
                    kind = "Directory" if stat.S_ISDIR(mode) else "File"
                    permission_results["insecure_permissions"].append(f"{filepath}: {kind} permissions are world writable ({format(mode & 0o777, '03o')})")

            except Exception as e:
                logging.error(f"Error checking permissions for {filepath}: {e}")

    return permission_results

def report_unused_permissions(permission_results):
    """
    Reports overly permissive file permissions found by the check.
    """
    if permission_results and permission_results["insecure_permissions"]:
        print("Potentially overly permissive permissions:")
        for issue in permission_results["insecure_permissions"]:
            print(f"- {issue}")
    else:
        print("No insecure permissions found.")

# The table prints before the nothing checked test below runs. A run over an empty tree shows a tidy all zero table first and only then exits 1, so anyone capturing output sees what looks like a completed report for a scan that examined nothing.
def display_results(analysis_results, permission_results):
    """
    Displays the analysis and permission check results using the rich library.

    Args:
        analysis_results (dict): The results from the code analysis.
        permission_results (dict): The results from the permission check.
    """
    console = Console()

    table = Table(title="Permission Analysis Results")
    table.add_column("Metric", justify="right", style="cyan", no_wrap=True)
    table.add_column("Value", justify="left", style="magenta")

    table.add_row("Files Analyzed", str(analysis_results["files_analyzed"]))
    if permission_results is None:
        table.add_row("Files Checked for Permissions", "Not checked")
    else:
        table.add_row("Files Checked for Permissions", str(permission_results["files_checked"]))

    if analysis_results["potential_issues"]:
        table.add_row("Potential Code Issues", str(len(analysis_results["potential_issues"])))
    else:
        table.add_row("Potential Code Issues", "None")

    if permission_results is None:
        table.add_row("Insecure Permissions", "Not checked")
    elif permission_results["insecure_permissions"]:
        table.add_row("Insecure Permissions", str(len(permission_results["insecure_permissions"])))
    else:
         table.add_row("Insecure Permissions", "None")



    console.print(table)

    if analysis_results["potential_issues"]:
        console.print("\n[bold red]Potential Code Issues:[/bold red]")
        for issue in analysis_results["potential_issues"]:
            console.print(f"- {issue}")

    if permission_results and permission_results["insecure_permissions"]:
        console.print("\n[bold red]Insecure Permissions:[/bold red]")
        for issue in permission_results["insecure_permissions"]:
            console.print(f"- {issue}")


def main():
    """
    Main function to orchestrate the permission analysis and reporting.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.report_unused_permissions and not args.check_file_permissions:
        parser.error("--report-unused-permissions requires --check-file-permissions")

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    directory = args.directory

    if not is_valid_directory(directory):
        sys.exit(1)

    exclude_spec = load_exclude_patterns(args.exclude)

    # Perform code analysis
    analysis_results = analyze_code(directory, exclude_spec)

    # Perform permission checks only when the flag asks for them
    permission_results = check_file_permissions(directory, exclude_spec) if args.check_file_permissions else None

    # Display results
    display_results(analysis_results, permission_results)

    checked = permission_results["files_checked"] if permission_results else 0
    if analysis_results["files_analyzed"] == 0 and checked == 0:
        logging.error("Nothing checked: no files were analyzed or checked.")
        sys.exit(1)

    # Optionally report overly permissive permissions
    if args.report_unused_permissions and args.check_file_permissions:
        report_unused_permissions(permission_results)


if __name__ == "__main__":
    main()