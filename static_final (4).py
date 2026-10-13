#!/usr/bin/env python3
import os
import ast

# Starter Script for Automated Static Code Analysis Tool
# Scenario: You are a junior penetration tester at a manufacturing facility.
# Your mission is to identify vulnerabilities in the facility's software.

# Step 4: Define Vulnerability Patterns
# List of unsafe functions commonly associated with security vulnerabilities
unsafe_functions = ["eval", "exec", "pickle.loads"]


# Step 2: Collect the Source Code
def collect_source_files(directory):
    """
    Recursively searches a directory for Python files.
    Returns a list of file paths ending in .py.
    """
    source_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                source_files.append(os.path.join(root, file))
    return source_files


# Step 3: Parse the Code
def parse_source_code(file_path):
    """
    Reads a source code file and converts it into an
    Abstract Syntax Tree (AST) for structural analysis.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        source_code = f.read()
    tree = ast.parse(source_code, filename=file_path)
    return tree


# Step 4: Define Vulnerability Patterns (helper function)
def is_vulnerable_function(node):
    """
    Checks an AST node to determine whether it represents a call
    to one of the known unsafe functions.
    Returns a tuple: (bool, func_name)
    """
    if isinstance(node, ast.Call):
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"
            else:
                func_name = node.func.attr

        if func_name in unsafe_functions:
            return True, func_name

    return False, None


# Step 5: Implement the Analysis
def analyze_ast(tree, file_path):
    """
    Analyzes the AST of a source file for potential vulnerabilities.
    Returns a list of found issues.
    """
    issues = []
    for node in ast.walk(tree):
        vulnerable, func_name = is_vulnerable_function(node)
        if vulnerable:
            issue = {
                "file": file_path,
                "line": getattr(node, 'lineno', 'unknown'),
                "issue": f"Use of unsafe function '{func_name}'"
            }
            issues.append(issue)
    return issues


# Step 6: Generate and Report Findings
def main():
    """
    Entry point of the script. Collects source files, parses them,
    analyzes them for vulnerabilities, and reports the findings.
    """
    directory = input("Enter the directory to scan: ").strip()

    source_files = collect_source_files(directory)

    if not source_files:
        print("No Python source files found in the specified directory.")
        return

    all_issues = []
    for file_path in source_files:
        try:
            tree = parse_source_code(file_path)
            issues = analyze_ast(tree, file_path)
            all_issues.extend(issues)
        except (SyntaxError, UnicodeDecodeError) as e:
            print(f"Could not parse {file_path}: {e}")

    if all_issues:
        print("\nVulnerabilities Found:")
        for issue in all_issues:
            print(f"[{issue['file']}:{issue['line']}] {issue['issue']}")
    else:
        print("\nNo vulnerabilities found.")


if __name__ == "__main__":
    main()
