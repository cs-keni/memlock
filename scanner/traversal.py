"""
File system traversal: walk directories and collect C source files.

This module provides utilities for recursively traversing directories to find
C source files (.c) and header files (.h) for static analysis. It includes
configurable filtering to exclude common build directories and test folders.

Typical usage:
    from pathlib import Path
    from scanner.traversal import find_c_files, find_source_files
    
    # Find only .c files
    c_files = find_c_files(Path("./my_project"))
    
    # Find both .c and .h files
    all_sources = find_source_files(Path("./my_project"), include_headers=True)
    
    # Custom ignore patterns
    sources = find_source_files(
        Path("./my_project"),
        ignore_dirs={"build", "dist", "vendor"}
    )
"""

import logging
from pathlib import Path
from typing import Callable, Optional, Set

logger = logging.getLogger(__name__)

# Default directories to ignore during traversal
DEFAULT_IGNORE_DIRS: Set[str] = {
    # Build and distribution directories
    "build",
    "Build",
    "builds",
    "dist",
    "out",
    "bin",
    "obj",
    
    # Test directories (we want to scan production code, not test fixtures)
    "tests",
    "test",
    "testing",
    "__tests__",
    
    # Dependency and package directories
    "node_modules",
    "vendor",
    "third_party",
    "external",
    "deps",
    
    # Version control
    ".git",
    ".svn",
    ".hg",
    
    # IDE and editor directories
    ".vscode",
    ".idea",
    ".vs",
    
    # Python virtual environments (in case C extensions are mixed in)
    "venv",
    ".venv",
    "env",
    "ENV",
    
    # Cache directories
    "__pycache__",
    ".cache",
    ".pytest_cache",
}


def is_c_file(path: Path) -> bool:
    """
    Check if a file is a C source file (.c extension).
    
    Args:
        path: Path to the file to check.
    
    Returns:
        True if the file has a .c extension, False otherwise.
    
    Examples:
        >>> is_c_file(Path("main.c"))
        True
        >>> is_c_file(Path("header.h"))
        False
        >>> is_c_file(Path("main.cpp"))
        False
    """
    return path.suffix.lower() == ".c"


def is_header_file(path: Path) -> bool:
    """
    Check if a file is a C header file (.h extension).
    
    Args:
        path: Path to the file to check.
    
    Returns:
        True if the file has a .h extension, False otherwise.
    
    Examples:
        >>> is_header_file(Path("header.h"))
        True
        >>> is_header_file(Path("main.c"))
        False
    """
    return path.suffix.lower() == ".h"


def is_source_file(path: Path, include_headers: bool = False) -> bool:
    """
    Check if a file is a C source or header file.
    
    Args:
        path: Path to the file to check.
        include_headers: If True, also accept .h files; if False, only .c files.
    
    Returns:
        True if the file matches the criteria, False otherwise.
    
    Examples:
        >>> is_source_file(Path("main.c"))
        True
        >>> is_source_file(Path("header.h"), include_headers=False)
        False
        >>> is_source_file(Path("header.h"), include_headers=True)
        True
    """
    if is_c_file(path):
        return True
    if include_headers and is_header_file(path):
        return True
    return False


def should_ignore_directory(dir_path: Path, ignore_dirs: Set[str]) -> bool:
    """
    Check if a directory should be ignored during traversal.
    
    Args:
        dir_path: Path to the directory to check.
        ignore_dirs: Set of directory names to ignore (case-sensitive).
    
    Returns:
        True if the directory should be skipped, False otherwise.
    
    Notes:
        - Only checks the directory name, not the full path.
        - Hidden directories (starting with '.') are automatically ignored
          unless explicitly in the ignore set.
    
    Examples:
        >>> should_ignore_directory(Path("build"), {"build", "tests"})
        True
        >>> should_ignore_directory(Path("src"), {"build", "tests"})
        False
    """
    return dir_path.name in ignore_dirs


def find_source_files(
    root: Path,
    include_headers: bool = False,
    ignore_dirs: Optional[Set[str]] = None,
    follow_symlinks: bool = False,
    filter_fn: Optional[Callable[[Path], bool]] = None,
) -> list[Path]:
    """
    Recursively find all C source files in a directory tree.
    
    This is the main entry point for file traversal. It walks the directory
    tree starting from `root`, collecting all .c files (and optionally .h files)
    while skipping ignored directories.
    
    Args:
        root: Root directory to start traversal from.
        include_headers: If True, also collect .h files; if False, only .c files.
        ignore_dirs: Set of directory names to skip. If None, uses DEFAULT_IGNORE_DIRS.
        follow_symlinks: If True, follow symbolic links during traversal.
                         If False (default), symlinks are skipped for safety.
        filter_fn: Optional additional filter function. If provided, only files
                   for which filter_fn(path) returns True are included.
    
    Returns:
        List of Path objects for all matching source files found.
        The list is sorted for deterministic ordering.
    
    Raises:
        FileNotFoundError: If the root directory does not exist.
        PermissionError: If the root directory cannot be accessed (logged, not raised).
    
    Examples:
        >>> # Find all .c files in current directory
        >>> files = find_source_files(Path("."))
        
        >>> # Find .c and .h files, excluding specific directories
        >>> files = find_source_files(
        ...     Path("./src"),
        ...     include_headers=True,
        ...     ignore_dirs={"tests", "build", "vendor"}
        ... )
        
        >>> # Find .c files with custom filter (only files with "main" in name)
        >>> files = find_source_files(
        ...     Path("./src"),
        ...     filter_fn=lambda p: "main" in p.name
        ... )
    
    Notes:
        - Files are collected in a deterministic order (sorted by path).
        - Permission errors on subdirectories are logged but do not stop traversal.
        - The root path is resolved to an absolute path before traversal.
    """
    if ignore_dirs is None:
        ignore_dirs = DEFAULT_IGNORE_DIRS
    
    # Resolve to absolute path
    root = root.resolve()
    
    if not root.exists():
        logger.error("Root directory does not exist: %s", root)
        raise FileNotFoundError(f"Root directory does not exist: {root}")
    
    if not root.is_dir():
        logger.error("Root path is not a directory: %s", root)
        raise NotADirectoryError(f"Root path is not a directory: {root}")
    
    logger.info("Starting traversal from: %s", root)
    logger.debug(
        "Traversal config: include_headers=%s, follow_symlinks=%s, ignore_dirs=%s",
        include_headers,
        follow_symlinks,
        ignore_dirs,
    )
    
    collected_files: list[Path] = []
    
    def _walk_directory(current_dir: Path) -> None:
        """Recursive helper to walk directory tree."""
        try:
            # Iterate over directory contents
            for entry in current_dir.iterdir():
                # Skip symlinks unless explicitly following them
                if entry.is_symlink() and not follow_symlinks:
                    logger.debug("Skipping symlink: %s", entry)
                    continue
                
                # Handle directories
                if entry.is_dir():
                    if should_ignore_directory(entry, ignore_dirs):
                        logger.debug("Ignoring directory: %s", entry)
                        continue
                    # Recursively traverse subdirectory
                    _walk_directory(entry)
                
                # Handle files
                elif entry.is_file():
                    # Check if it's a source file we want
                    if is_source_file(entry, include_headers=include_headers):
                        # Apply custom filter if provided
                        if filter_fn is not None and not filter_fn(entry):
                            logger.debug("Filtered out by custom filter: %s", entry)
                            continue
                        
                        logger.debug("Found source file: %s", entry)
                        collected_files.append(entry)
        
        except PermissionError as e:
            logger.warning("Permission denied accessing directory %s: %s", current_dir, e)
        except OSError as e:
            logger.warning("Error accessing directory %s: %s", current_dir, e)
    
    # Start recursive traversal
    _walk_directory(root)
    
    # Sort for deterministic ordering
    collected_files.sort()
    
    logger.info(
        "Traversal complete: found %d source file(s) in %s",
        len(collected_files),
        root,
    )
    
    return collected_files


def find_c_files(
    root: Path,
    ignore_dirs: Optional[Set[str]] = None,
    follow_symlinks: bool = False,
) -> list[Path]:
    """
    Recursively find all .c files in a directory tree.
    
    Convenience wrapper around find_source_files() that only collects .c files.
    This is the most common use case for C static analysis.
    
    Args:
        root: Root directory to start traversal from.
        ignore_dirs: Set of directory names to skip. If None, uses DEFAULT_IGNORE_DIRS.
        follow_symlinks: If True, follow symbolic links during traversal.
    
    Returns:
        List of Path objects for all .c files found, sorted by path.
    
    Examples:
        >>> # Find all .c files in a project
        >>> c_files = find_c_files(Path("./my_project"))
        >>> for file in c_files:
        ...     print(file)
        ./my_project/src/main.c
        ./my_project/src/utils.c
    """
    return find_source_files(
        root=root,
        include_headers=False,
        ignore_dirs=ignore_dirs,
        follow_symlinks=follow_symlinks,
    )


def find_header_files(
    root: Path,
    ignore_dirs: Optional[Set[str]] = None,
    follow_symlinks: bool = False,
) -> list[Path]:
    """
    Recursively find all .h files in a directory tree.
    
    Convenience wrapper around find_source_files() that only collects .h files.
    
    Args:
        root: Root directory to start traversal from.
        ignore_dirs: Set of directory names to skip. If None, uses DEFAULT_IGNORE_DIRS.
        follow_symlinks: If True, follow symbolic links during traversal.
    
    Returns:
        List of Path objects for all .h files found, sorted by path.
    """
    # Use filter_fn to only accept .h files (not .c files)
    return find_source_files(
        root=root,
        include_headers=True,
        ignore_dirs=ignore_dirs,
        follow_symlinks=follow_symlinks,
        filter_fn=lambda p: is_header_file(p),
    )
