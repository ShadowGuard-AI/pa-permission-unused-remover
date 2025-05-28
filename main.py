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
        description="Identifies and suggests removal of unused permissions based on application code analysis and historical usage."
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
        help="Check file permissions against a recommended permission set.",
    )
    parser.add_argument(
        "--report-unused-permissions",
        action="store_true",
        help="Report unused file permissions (requires --check-file-permissions).",
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
    Analyzes the Python code in the given directory to identify potential permission-related issues.
    Currently, this is a placeholder and should be expanded with more sophisticated analysis.

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

                analysis_results["files_analyzed"] += 1
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        source_code = f.read()
                    tree = ast.parse(source_code)

                    # TODO: Implement deeper static analysis of the AST to identify
                    #       potential permission-related vulnerabilities.
                    #       For example, look for uses of `os.chmod`, `open` with specific modes,
                    #       or calls to system functions related to permissions.

                    # Placeholder: Simple check for 'os.chmod'
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Name) and node.id == 'chmod':
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

    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            if exclude_spec and exclude_spec.match_file(filepath):
                continue

            permission_results["files_checked"] += 1
            try:
                # Get file mode (permissions)
                mode = os.stat(filepath).st_mode

                # Check if it's a regular file and permissions are too open (e.g., 777)
                if stat.S_ISREG(mode) and (mode & 0o777) == 0o777:
                    permission_results["insecure_permissions"].append(f"{filepath}: Permissions are too open (777)")
                elif stat.S_ISDIR(mode) and (mode & 0o777) == 0o777:
                     permission_results["insecure_permissions"].append(f"{filepath}: Directory permissions are too open (777)")


            except Exception as e:
                logging.error(f"Error checking permissions for {filepath}: {e}")

    return permission_results

def report_unused_permissions(permission_results):
    """
    Reports potentially unused file permissions.  Currently, this is a placeholder.
    """
    if permission_results and permission_results["insecure_permissions"]:
        print("Potentially unused or overly permissive permissions:")
        for issue in permission_results["insecure_permissions"]:
            print(f"- {issue}")
    else:
        print("No insecure permissions found.")

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
    table.add_row("Files Checked for Permissions", str(permission_results["files_checked"]))

    if analysis_results["potential_issues"]:
        table.add_row("Potential Code Issues", str(len(analysis_results["potential_issues"])))
    else:
        table.add_row("Potential Code Issues", "None")

    if permission_results["insecure_permissions"]:
        table.add_row("Insecure Permissions", str(len(permission_results["insecure_permissions"])))
    else:
         table.add_row("Insecure Permissions", "None")



    console.print(table)

    if analysis_results["potential_issues"]:
        console.print("\n[bold red]Potential Code Issues:[/bold red]")
        for issue in analysis_results["potential_issues"]:
            console.print(f"- {issue}")

    if permission_results["insecure_permissions"]:
        console.print("\n[bold red]Insecure Permissions:[/bold red]")
        for issue in permission_results["insecure_permissions"]:
            console.print(f"- {issue}")


def main():
    """
    Main function to orchestrate the permission analysis and reporting.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    directory = args.directory

    if not is_valid_directory(directory):
        sys.exit(1)

    exclude_spec = load_exclude_patterns(args.exclude)

    # Perform code analysis
    analysis_results = analyze_code(directory, exclude_spec)

    # Perform permission checks
    permission_results = check_file_permissions(directory, exclude_spec)

    # Display results
    display_results(analysis_results, permission_results)

    # Optionally report unused permissions
    if args.report_unused_permissions and args.check_file_permissions:
        report_unused_permissions(permission_results)


if __name__ == "__main__":
    main()