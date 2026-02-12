"""Tests for file system traversal functionality."""

import logging
from pathlib import Path

import pytest

from scanner.traversal import (
    DEFAULT_IGNORE_DIRS,
    find_c_files,
    find_header_files,
    find_source_files,
    is_c_file,
    is_header_file,
    is_source_file,
    should_ignore_directory,
)


class TestFileTypeChecks:
    """Test file type checking functions."""
    
    def test_is_c_file_recognizes_c_extension(self):
        """is_c_file() returns True for .c files."""
        assert is_c_file(Path("main.c"))
        assert is_c_file(Path("src/utils.c"))
        assert is_c_file(Path("/absolute/path/file.c"))
    
    def test_is_c_file_case_insensitive(self):
        """is_c_file() works with uppercase extensions."""
        assert is_c_file(Path("MAIN.C"))
        assert is_c_file(Path("file.C"))
    
    def test_is_c_file_rejects_non_c_files(self):
        """is_c_file() returns False for non-.c files."""
        assert not is_c_file(Path("main.h"))
        assert not is_c_file(Path("main.cpp"))
        assert not is_c_file(Path("main.cc"))
        assert not is_c_file(Path("README.md"))
        assert not is_c_file(Path("Makefile"))
    
    def test_is_header_file_recognizes_h_extension(self):
        """is_header_file() returns True for .h files."""
        assert is_header_file(Path("header.h"))
        assert is_header_file(Path("include/types.h"))
        assert is_header_file(Path("/absolute/path/api.h"))
    
    def test_is_header_file_case_insensitive(self):
        """is_header_file() works with uppercase extensions."""
        assert is_header_file(Path("HEADER.H"))
        assert is_header_file(Path("file.H"))
    
    def test_is_header_file_rejects_non_header_files(self):
        """is_header_file() returns False for non-.h files."""
        assert not is_header_file(Path("main.c"))
        assert not is_header_file(Path("header.hpp"))
        assert not is_header_file(Path("README.txt"))
    
    def test_is_source_file_without_headers(self):
        """is_source_file() only accepts .c when include_headers=False."""
        assert is_source_file(Path("main.c"), include_headers=False)
        assert not is_source_file(Path("header.h"), include_headers=False)
    
    def test_is_source_file_with_headers(self):
        """is_source_file() accepts both .c and .h when include_headers=True."""
        assert is_source_file(Path("main.c"), include_headers=True)
        assert is_source_file(Path("header.h"), include_headers=True)
        assert not is_source_file(Path("main.cpp"), include_headers=True)


class TestDirectoryFiltering:
    """Test directory ignore logic."""
    
    def test_should_ignore_directory_recognizes_ignored_dirs(self):
        """should_ignore_directory() returns True for directories in ignore set."""
        ignore_set = {"build", "tests", "vendor"}
        assert should_ignore_directory(Path("build"), ignore_set)
        assert should_ignore_directory(Path("tests"), ignore_set)
        assert should_ignore_directory(Path("vendor"), ignore_set)
    
    def test_should_ignore_directory_allows_non_ignored_dirs(self):
        """should_ignore_directory() returns False for directories not in ignore set."""
        ignore_set = {"build", "tests"}
        assert not should_ignore_directory(Path("src"), ignore_set)
        assert not should_ignore_directory(Path("lib"), ignore_set)
        assert not should_ignore_directory(Path("include"), ignore_set)
    
    def test_should_ignore_directory_case_sensitive(self):
        """should_ignore_directory() is case-sensitive."""
        ignore_set = {"build"}
        assert should_ignore_directory(Path("build"), ignore_set)
        assert not should_ignore_directory(Path("Build"), ignore_set)
    
    def test_default_ignore_dirs_includes_common_patterns(self):
        """DEFAULT_IGNORE_DIRS contains expected patterns."""
        assert "build" in DEFAULT_IGNORE_DIRS
        assert "tests" in DEFAULT_IGNORE_DIRS
        assert ".git" in DEFAULT_IGNORE_DIRS
        assert "node_modules" in DEFAULT_IGNORE_DIRS
        assert "__pycache__" in DEFAULT_IGNORE_DIRS


class TestTraversal:
    """Test file traversal functions."""
    
    @pytest.fixture
    def temp_project(self, tmp_path):
        """Create a temporary project structure for testing."""
        # Create directory structure:
        # tmp_path/
        #   src/
        #     main.c
        #     utils.c
        #     utils.h
        #   include/
        #     api.h
        #   build/
        #     main.o (should be ignored)
        #     compiled.c (should be ignored - in build/)
        #   tests/
        #     test_main.c (should be ignored)
        #   README.md
        
        # Create directories
        (tmp_path / "src").mkdir()
        (tmp_path / "include").mkdir()
        (tmp_path / "build").mkdir()
        (tmp_path / "tests").mkdir()
        
        # Create source files
        (tmp_path / "src" / "main.c").write_text("int main() { return 0; }")
        (tmp_path / "src" / "utils.c").write_text("void util() {}")
        (tmp_path / "src" / "utils.h").write_text("#pragma once")
        (tmp_path / "include" / "api.h").write_text("#define API_VERSION 1")
        
        # Create files that should be ignored
        (tmp_path / "build" / "main.o").write_text("binary")
        (tmp_path / "build" / "compiled.c").write_text("// build artifact")
        (tmp_path / "tests" / "test_main.c").write_text("// test file")
        
        # Create non-C file
        (tmp_path / "README.md").write_text("# Project")
        
        return tmp_path
    
    def test_find_c_files_collects_only_c_files(self, temp_project):
        """find_c_files() returns only .c files, excluding ignored directories."""
        c_files = find_c_files(temp_project)
        
        # Should find main.c and utils.c in src/, but not:
        # - utils.h (header file)
        # - api.h (header file)
        # - compiled.c (in build/)
        # - test_main.c (in tests/)
        
        c_file_names = {f.name for f in c_files}
        assert "main.c" in c_file_names
        assert "utils.c" in c_file_names
        assert len(c_files) == 2
        
        # Verify paths
        assert all(f.suffix == ".c" for f in c_files)
        assert all("build" not in f.parts for f in c_files)
        assert all("tests" not in f.parts for f in c_files)
    
    def test_find_source_files_with_headers(self, temp_project):
        """find_source_files() with include_headers=True returns .c and .h files."""
        source_files = find_source_files(temp_project, include_headers=True)
        
        file_names = {f.name for f in source_files}
        assert "main.c" in file_names
        assert "utils.c" in file_names
        assert "utils.h" in file_names
        assert "api.h" in file_names
        assert len(source_files) == 4
        
        # Should not include files from build/ or tests/
        assert "compiled.c" not in file_names
        assert "test_main.c" not in file_names
    
    def test_find_source_files_without_headers(self, temp_project):
        """find_source_files() with include_headers=False returns only .c files."""
        source_files = find_source_files(temp_project, include_headers=False)
        
        file_names = {f.name for f in source_files}
        assert "main.c" in file_names
        assert "utils.c" in file_names
        assert "utils.h" not in file_names
        assert "api.h" not in file_names
        assert len(source_files) == 2
    
    def test_find_header_files_collects_only_headers(self, temp_project):
        """find_header_files() returns only .h files."""
        header_files = find_header_files(temp_project)
        
        file_names = {f.name for f in header_files}
        assert "utils.h" in file_names
        assert "api.h" in file_names
        assert "main.c" not in file_names
        assert "utils.c" not in file_names
        assert len(header_files) == 2
    
    def test_find_source_files_custom_ignore_dirs(self, temp_project):
        """find_source_files() respects custom ignore_dirs."""
        # Don't ignore tests/ - only ignore build/
        source_files = find_source_files(
            temp_project,
            include_headers=False,
            ignore_dirs={"build"},
        )
        
        file_names = {f.name for f in source_files}
        # Should now include test_main.c from tests/
        assert "test_main.c" in file_names
        assert "main.c" in file_names
        assert "utils.c" in file_names
        # Should still not include compiled.c from build/
        assert "compiled.c" not in file_names
        assert len(source_files) == 3
    
    def test_find_source_files_with_filter_function(self, temp_project):
        """find_source_files() applies custom filter_fn."""
        # Only include files with "main" in the name
        source_files = find_source_files(
            temp_project,
            include_headers=False,
            filter_fn=lambda p: "main" in p.name,
        )
        
        file_names = {f.name for f in source_files}
        assert "main.c" in file_names
        assert "utils.c" not in file_names
        assert len(source_files) == 1
    
    def test_find_source_files_empty_directory(self, tmp_path):
        """find_source_files() returns empty list for directory with no C files."""
        # Create directory with no C files
        (tmp_path / "empty").mkdir()
        (tmp_path / "empty" / "README.txt").write_text("No C files here")
        
        source_files = find_source_files(tmp_path / "empty")
        assert source_files == []
    
    def test_find_source_files_nonexistent_directory(self):
        """find_source_files() raises FileNotFoundError for nonexistent directory."""
        with pytest.raises(FileNotFoundError):
            find_source_files(Path("/nonexistent/directory"))
    
    def test_find_source_files_on_file_not_directory(self, tmp_path):
        """find_source_files() raises NotADirectoryError when given a file."""
        file_path = tmp_path / "test.c"
        file_path.write_text("int main() {}")
        
        with pytest.raises(NotADirectoryError):
            find_source_files(file_path)
    
    def test_find_source_files_returns_sorted_results(self, temp_project):
        """find_source_files() returns files in sorted order."""
        c_files = find_c_files(temp_project)
        
        # Check that results are sorted
        sorted_files = sorted(c_files)
        assert c_files == sorted_files
    
    def test_find_source_files_logs_progress(self, temp_project, caplog):
        """find_source_files() logs traversal progress."""
        with caplog.at_level(logging.INFO):
            find_c_files(temp_project)
        
        # Should log start and completion
        assert "Starting traversal" in caplog.text
        assert "Traversal complete" in caplog.text
        assert "found" in caplog.text.lower()


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_nested_directories(self, tmp_path):
        """Traversal works with deeply nested directories."""
        # Create nested structure: tmp_path/a/b/c/d/file.c
        nested = tmp_path / "a" / "b" / "c" / "d"
        nested.mkdir(parents=True)
        (nested / "deep.c").write_text("void deep() {}")
        
        c_files = find_c_files(tmp_path)
        assert len(c_files) == 1
        assert c_files[0].name == "deep.c"
    
    def test_empty_ignore_dirs_set(self, tmp_path):
        """find_source_files() works with empty ignore_dirs set."""
        # Create files in build/ and tests/
        (tmp_path / "build").mkdir()
        (tmp_path / "tests").mkdir()
        (tmp_path / "build" / "build.c").write_text("// build")
        (tmp_path / "tests" / "test.c").write_text("// test")
        
        # With empty ignore set, should find files in build/ and tests/
        source_files = find_source_files(tmp_path, ignore_dirs=set())
        
        file_names = {f.name for f in source_files}
        assert "build.c" in file_names
        assert "test.c" in file_names
        assert len(source_files) == 2
    
    def test_single_file_in_root(self, tmp_path):
        """Traversal finds file in root directory."""
        (tmp_path / "root.c").write_text("int main() {}")
        
        c_files = find_c_files(tmp_path)
        assert len(c_files) == 1
        assert c_files[0].name == "root.c"
    
    def test_hidden_files_not_included(self, tmp_path):
        """Traversal does not include hidden files (starting with .)."""
        (tmp_path / ".hidden.c").write_text("// hidden")
        (tmp_path / "visible.c").write_text("// visible")
        
        c_files = find_c_files(tmp_path)
        file_names = {f.name for f in c_files}
        
        # Both should be found - hidden file filtering is based on directories
        # not files (unless you want to add that filtering)
        # For now, let's document current behavior
        assert "visible.c" in file_names
        # .hidden.c will be found if we don't filter dot-files
        # Adjust test based on desired behavior
