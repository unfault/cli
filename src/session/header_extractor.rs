//! # Header Extractor
//!
//! Extracts import headers from source files for complete dependency graph building.
//! 
//! The header section is the portion of a file that contains import/use statements,
//! typically at the top of the file. Extracting only headers allows us to build a
//! complete import graph without sending entire file contents.
//!
//! ## Supported Languages
//!
//! - **Python**: `import`, `from ... import`
//! - **Rust**: `use`, `mod`, `extern crate`
//! - **Go**: `import`
//! - **JavaScript/TypeScript**: `import`, `require`, `export ... from`
//! - **Java**: `import`, `package`

use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

use super::workspace::Language;

/// Extracted header from a source file.
#[derive(Debug, Clone)]
pub struct FileHeader {
    /// File path relative to workspace root
    pub path: String,
    /// Programming language
    pub language: String,
    /// Extracted header content (import section only)
    pub header: String,
}

/// Configuration for header extraction.
#[derive(Debug, Clone)]
pub struct HeaderExtractorConfig {
    /// Maximum number of lines to consider as header
    pub max_header_lines: usize,
    /// Maximum bytes per header (to prevent oversized headers)
    pub max_header_bytes: usize,
}

impl Default for HeaderExtractorConfig {
    fn default() -> Self {
        Self {
            max_header_lines: 100,      // Most imports should be within first 100 lines
            max_header_bytes: 8 * 1024, // 8KB max per header
        }
    }
}

/// Extractor for file headers (import sections).
pub struct HeaderExtractor {
    root: PathBuf,
    config: HeaderExtractorConfig,
}

impl HeaderExtractor {
    /// Create a new header extractor.
    ///
    /// # Arguments
    ///
    /// * `root` - Root directory of the workspace
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            config: HeaderExtractorConfig::default(),
        }
    }

    /// Create a new header extractor with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `root` - Root directory of the workspace
    /// * `config` - Extraction configuration
    pub fn with_config(root: impl AsRef<Path>, config: HeaderExtractorConfig) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            config,
        }
    }

    /// Extract headers from all source files in parallel.
    ///
    /// # Arguments
    ///
    /// * `source_files` - List of (path, language) tuples from workspace scanning
    ///
    /// # Returns
    ///
    /// Vector of extracted file headers
    pub fn extract_all(&self, source_files: &[(PathBuf, Language)]) -> Vec<FileHeader> {
        source_files
            .par_iter()
            .filter_map(|(path, language)| {
                let relative_path = path
                    .strip_prefix(&self.root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string();

                match fs::read_to_string(path) {
                    Ok(contents) => {
                        let header = self.extract_header(&contents, *language);
                        
                        // Skip files with no imports
                        if header.is_empty() {
                            return None;
                        }

                        Some(FileHeader {
                            path: relative_path,
                            language: language.as_str().to_string(),
                            header,
                        })
                    }
                    Err(_) => None,
                }
            })
            .collect()
    }

    /// Extract the header (import section) from file contents.
    ///
    /// # Arguments
    ///
    /// * `contents` - Full file contents
    /// * `language` - Programming language
    ///
    /// # Returns
    ///
    /// Extracted header string containing only import statements
    pub fn extract_header(&self, contents: &str, language: Language) -> String {
        match language {
            Language::Python => self.extract_python_header(contents),
            Language::Rust => self.extract_rust_header(contents),
            Language::Go => self.extract_go_header(contents),
            Language::TypeScript | Language::JavaScript => self.extract_js_header(contents),
            Language::Java => self.extract_java_header(contents),
        }
    }

    /// Extract Python import header.
    ///
    /// Includes:
    /// - `import x`
    /// - `from x import y`
    /// - Leading comments and docstrings (for context)
    fn extract_python_header(&self, contents: &str) -> String {
        let mut header_lines = Vec::new();
        let mut in_multiline_string = false;
        let mut multiline_delim = "";
        let mut header_started = false;

        for (i, line) in contents.lines().enumerate() {
            if i >= self.config.max_header_lines {
                break;
            }

            let trimmed = line.trim();

            // Handle multi-line strings (docstrings)
            if in_multiline_string {
                header_lines.push(line.to_string());
                if trimmed.contains(multiline_delim) && !trimmed.starts_with(multiline_delim) {
                    in_multiline_string = false;
                } else if trimmed.ends_with(multiline_delim) {
                    in_multiline_string = false;
                }
                continue;
            }

            // Check for multiline string start
            if trimmed.starts_with("\"\"\"") || trimmed.starts_with("'''") {
                multiline_delim = if trimmed.starts_with("\"\"\"") {
                    "\"\"\""
                } else {
                    "'''"
                };
                header_lines.push(line.to_string());
                // Check if it ends on the same line
                let rest = &trimmed[3..];
                if !rest.contains(multiline_delim) {
                    in_multiline_string = true;
                }
                continue;
            }

            // Skip empty lines at the beginning
            if trimmed.is_empty() {
                if header_started {
                    header_lines.push(line.to_string());
                }
                continue;
            }

            // Include comments (only before imports)
            if trimmed.starts_with('#') {
                if !header_started {
                    header_lines.push(line.to_string());
                }
                continue;
            }

            // Include future imports and regular imports
            if trimmed.starts_with("from __future__")
                || trimmed.starts_with("from ")
                || trimmed.starts_with("import ")
            {
                header_started = true;
                header_lines.push(line.to_string());
                
                // Handle multi-line imports with parentheses
                if trimmed.contains('(') && !trimmed.contains(')') {
                    // Continue until we find closing paren
                    for next_line in contents.lines().skip(i + 1) {
                        header_lines.push(next_line.to_string());
                        if next_line.contains(')') {
                            break;
                        }
                    }
                }
                // Handle line continuation with backslash
                else if trimmed.ends_with('\\') {
                    for next_line in contents.lines().skip(i + 1) {
                        header_lines.push(next_line.to_string());
                        if !next_line.trim().ends_with('\\') {
                            break;
                        }
                    }
                }
                continue;
            }

            // Stop at first non-import code
            break;
        }

        self.truncate_to_max_bytes(header_lines.join("\n"))
    }

    /// Extract Rust use/mod header.
    ///
    /// Includes:
    /// - `use x;`
    /// - `mod x;`
    /// - `extern crate x;`
    /// - Module-level attributes
    fn extract_rust_header(&self, contents: &str) -> String {
        let mut header_lines = Vec::new();
        let mut in_block_comment = false;
        let mut brace_depth = 0;

        for (i, line) in contents.lines().enumerate() {
            if i >= self.config.max_header_lines {
                break;
            }

            let trimmed = line.trim();

            // Handle block comments
            if in_block_comment {
                header_lines.push(line.to_string());
                if trimmed.contains("*/") {
                    in_block_comment = false;
                }
                continue;
            }

            if trimmed.starts_with("/*") {
                header_lines.push(line.to_string());
                if !trimmed.contains("*/") {
                    in_block_comment = true;
                }
                continue;
            }

            // Skip empty lines at the beginning
            if trimmed.is_empty() {
                if !header_lines.is_empty() {
                    header_lines.push(line.to_string());
                }
                continue;
            }

            // Include line comments
            if trimmed.starts_with("//") {
                header_lines.push(line.to_string());
                continue;
            }

            // Include attributes
            if trimmed.starts_with("#[") || trimmed.starts_with("#![") {
                header_lines.push(line.to_string());
                continue;
            }

            // Include use statements (handle multi-line with braces)
            if trimmed.starts_with("use ") {
                header_lines.push(line.to_string());
                
                // Count braces for multi-line use
                for c in trimmed.chars() {
                    if c == '{' {
                        brace_depth += 1;
                    } else if c == '}' {
                        brace_depth -= 1;
                    }
                }
                
                // Continue if braces not balanced
                if brace_depth > 0 {
                    for next_line in contents.lines().skip(i + 1) {
                        header_lines.push(next_line.to_string());
                        for c in next_line.chars() {
                            if c == '{' {
                                brace_depth += 1;
                            } else if c == '}' {
                                brace_depth -= 1;
                            }
                        }
                        if brace_depth == 0 {
                            break;
                        }
                    }
                }
                continue;
            }

            // Include mod declarations (external modules)
            if (trimmed.starts_with("mod ") || trimmed.starts_with("pub mod "))
                && trimmed.ends_with(';')
            {
                header_lines.push(line.to_string());
                continue;
            }

            // Include extern crate
            if trimmed.starts_with("extern crate ") {
                header_lines.push(line.to_string());
                continue;
            }

            // Stop at first non-header content (fn, struct, impl, etc.)
            if trimmed.starts_with("fn ")
                || trimmed.starts_with("pub fn ")
                || trimmed.starts_with("struct ")
                || trimmed.starts_with("pub struct ")
                || trimmed.starts_with("enum ")
                || trimmed.starts_with("pub enum ")
                || trimmed.starts_with("impl ")
                || trimmed.starts_with("trait ")
                || trimmed.starts_with("pub trait ")
                || trimmed.starts_with("const ")
                || trimmed.starts_with("pub const ")
                || trimmed.starts_with("static ")
                || trimmed.starts_with("pub static ")
                || trimmed.starts_with("type ")
                || trimmed.starts_with("pub type ")
                || (trimmed.starts_with("mod ") && trimmed.contains('{'))
            {
                break;
            }
        }

        self.truncate_to_max_bytes(header_lines.join("\n"))
    }

    /// Extract Go import header.
    ///
    /// Includes:
    /// - `package x`
    /// - `import "x"`
    /// - `import (...)` block
    fn extract_go_header(&self, contents: &str) -> String {
        let mut header_lines = Vec::new();
        let mut in_import_block = false;
        let mut in_block_comment = false;

        for (i, line) in contents.lines().enumerate() {
            if i >= self.config.max_header_lines {
                break;
            }

            let trimmed = line.trim();

            // Handle block comments
            if in_block_comment {
                header_lines.push(line.to_string());
                if trimmed.contains("*/") {
                    in_block_comment = false;
                }
                continue;
            }

            if trimmed.starts_with("/*") {
                header_lines.push(line.to_string());
                if !trimmed.contains("*/") {
                    in_block_comment = true;
                }
                continue;
            }

            // Handle import block
            if in_import_block {
                header_lines.push(line.to_string());
                if trimmed == ")" {
                    in_import_block = false;
                }
                continue;
            }

            // Skip empty lines at the beginning
            if trimmed.is_empty() {
                if !header_lines.is_empty() {
                    header_lines.push(line.to_string());
                }
                continue;
            }

            // Include line comments
            if trimmed.starts_with("//") {
                header_lines.push(line.to_string());
                continue;
            }

            // Include package declaration
            if trimmed.starts_with("package ") {
                header_lines.push(line.to_string());
                continue;
            }

            // Include single-line imports
            if trimmed.starts_with("import \"") || trimmed.starts_with("import `") {
                header_lines.push(line.to_string());
                continue;
            }

            // Start of import block
            if trimmed.starts_with("import (") {
                header_lines.push(line.to_string());
                if !trimmed.ends_with(')') {
                    in_import_block = true;
                }
                continue;
            }

            // Stop at first non-header content
            if trimmed.starts_with("func ")
                || trimmed.starts_with("type ")
                || trimmed.starts_with("var ")
                || trimmed.starts_with("const ")
            {
                break;
            }
        }

        self.truncate_to_max_bytes(header_lines.join("\n"))
    }

    /// Extract JavaScript/TypeScript import header.
    ///
    /// Includes:
    /// - `import x from "y"`
    /// - `import { x } from "y"`
    /// - `import * as x from "y"`
    /// - `const x = require("y")`
    /// - `export { x } from "y"`
    fn extract_js_header(&self, contents: &str) -> String {
        let mut header_lines = Vec::new();
        let mut in_block_comment = false;

        for (i, line) in contents.lines().enumerate() {
            if i >= self.config.max_header_lines {
                break;
            }

            let trimmed = line.trim();

            // Handle block comments
            if in_block_comment {
                header_lines.push(line.to_string());
                if trimmed.contains("*/") {
                    in_block_comment = false;
                }
                continue;
            }

            if trimmed.starts_with("/*") {
                header_lines.push(line.to_string());
                if !trimmed.contains("*/") {
                    in_block_comment = true;
                }
                continue;
            }

            // Skip empty lines at the beginning
            if trimmed.is_empty() {
                if !header_lines.is_empty() {
                    header_lines.push(line.to_string());
                }
                continue;
            }

            // Include line comments
            if trimmed.starts_with("//") {
                header_lines.push(line.to_string());
                continue;
            }

            // Include 'use strict' and 'use client' directives
            if trimmed.starts_with("'use ") || trimmed.starts_with("\"use ") {
                header_lines.push(line.to_string());
                continue;
            }

            // Include import statements
            if trimmed.starts_with("import ") {
                header_lines.push(line.to_string());
                
                // Handle multi-line imports
                if (trimmed.contains('{') && !trimmed.contains('}'))
                    || (!trimmed.contains("from") && !trimmed.ends_with(';'))
                {
                    for next_line in contents.lines().skip(i + 1) {
                        header_lines.push(next_line.to_string());
                        let next_trimmed = next_line.trim();
                        if next_trimmed.contains("from") || next_trimmed.ends_with(';') {
                            break;
                        }
                    }
                }
                continue;
            }

            // Include require statements
            if trimmed.contains("require(") 
                && (trimmed.starts_with("const ") 
                    || trimmed.starts_with("let ") 
                    || trimmed.starts_with("var "))
            {
                header_lines.push(line.to_string());
                continue;
            }

            // Include re-exports
            if trimmed.starts_with("export ") && trimmed.contains(" from ") {
                header_lines.push(line.to_string());
                continue;
            }

            // Include export * from
            if trimmed.starts_with("export *") {
                header_lines.push(line.to_string());
                continue;
            }

            // Stop at first non-import content
            if trimmed.starts_with("function ")
                || trimmed.starts_with("async function ")
                || trimmed.starts_with("class ")
                || trimmed.starts_with("export default ")
                || trimmed.starts_with("export class ")
                || trimmed.starts_with("export function ")
                || trimmed.starts_with("export async ")
                || trimmed.starts_with("export const ")
                || trimmed.starts_with("export let ")
                || trimmed.starts_with("export interface ")
                || trimmed.starts_with("export type ")
                || trimmed.starts_with("interface ")
                || trimmed.starts_with("type ")
                || (trimmed.starts_with("const ") && !trimmed.contains("require("))
                || (trimmed.starts_with("let ") && !trimmed.contains("require("))
            {
                break;
            }
        }

        self.truncate_to_max_bytes(header_lines.join("\n"))
    }

    /// Extract Java import header.
    ///
    /// Includes:
    /// - `package x.y.z;`
    /// - `import x.y.z;`
    /// - `import static x.y.z;`
    fn extract_java_header(&self, contents: &str) -> String {
        let mut header_lines = Vec::new();
        let mut in_block_comment = false;

        for (i, line) in contents.lines().enumerate() {
            if i >= self.config.max_header_lines {
                break;
            }

            let trimmed = line.trim();

            // Handle block comments / javadoc
            if in_block_comment {
                header_lines.push(line.to_string());
                if trimmed.contains("*/") {
                    in_block_comment = false;
                }
                continue;
            }

            if trimmed.starts_with("/*") {
                header_lines.push(line.to_string());
                if !trimmed.contains("*/") {
                    in_block_comment = true;
                }
                continue;
            }

            // Skip empty lines at the beginning
            if trimmed.is_empty() {
                if !header_lines.is_empty() {
                    header_lines.push(line.to_string());
                }
                continue;
            }

            // Include line comments
            if trimmed.starts_with("//") {
                header_lines.push(line.to_string());
                continue;
            }

            // Include package declaration
            if trimmed.starts_with("package ") {
                header_lines.push(line.to_string());
                continue;
            }

            // Include import statements
            if trimmed.starts_with("import ") {
                header_lines.push(line.to_string());
                continue;
            }

            // Stop at first non-header content (class, interface, annotation)
            if trimmed.starts_with("public ")
                || trimmed.starts_with("private ")
                || trimmed.starts_with("protected ")
                || trimmed.starts_with("class ")
                || trimmed.starts_with("interface ")
                || trimmed.starts_with("enum ")
                || trimmed.starts_with("@")
                || trimmed.starts_with("abstract ")
                || trimmed.starts_with("final ")
            {
                break;
            }
        }

        self.truncate_to_max_bytes(header_lines.join("\n"))
    }

    /// Truncate header to maximum bytes.
    fn truncate_to_max_bytes(&self, header: String) -> String {
        if header.len() <= self.config.max_header_bytes {
            header
        } else {
            // Find a safe truncation point (end of line)
            let truncated = &header[..self.config.max_header_bytes];
            if let Some(last_newline) = truncated.rfind('\n') {
                truncated[..last_newline].to_string()
            } else {
                truncated.to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn test_python_simple_imports() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = r#"import os
import sys
from typing import List, Dict
from myapp.utils import helper

def main():
    pass
"#;
        let header = extractor.extract_header(contents, Language::Python);
        assert!(header.contains("import os"));
        assert!(header.contains("import sys"));
        assert!(header.contains("from typing import"));
        assert!(header.contains("from myapp.utils"));
        assert!(!header.contains("def main"));
    }

    #[test]
    fn test_python_multiline_imports() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = r#"from mymodule import (
    ClassA,
    ClassB,
    ClassC,
)

class MyClass:
    pass
"#;
        let header = extractor.extract_header(contents, Language::Python);
        assert!(header.contains("from mymodule import"));
        assert!(header.contains("ClassA"));
        assert!(header.contains("ClassC"));
        assert!(!header.contains("class MyClass"));
    }

    #[test]
    fn test_python_with_docstring() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = r#"#!/usr/bin/env python
"""
Module docstring here.
"""
import os

def func():
    pass
"#;
        let header = extractor.extract_header(contents, Language::Python);
        assert!(header.contains("#!/usr/bin/env python"));
        assert!(header.contains("import os"));
        assert!(!header.contains("def func"));
    }

    #[test]
    fn test_rust_use_statements() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = r#"use std::collections::HashMap;
use crate::utils::helper;
use super::parent_mod;

fn main() {
    println!("Hello");
}
"#;
        let header = extractor.extract_header(contents, Language::Rust);
        assert!(header.contains("use std::collections::HashMap"));
        assert!(header.contains("use crate::utils::helper"));
        assert!(header.contains("use super::parent_mod"));
        assert!(!header.contains("fn main"));
    }

    #[test]
    fn test_rust_multiline_use() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = r#"use std::{
    collections::HashMap,
    sync::Arc,
};

fn main() {}
"#;
        let header = extractor.extract_header(contents, Language::Rust);
        assert!(header.contains("use std::"));
        assert!(header.contains("collections::HashMap"));
        assert!(header.contains("sync::Arc"));
        assert!(!header.contains("fn main"));
    }

    #[test]
    fn test_rust_mod_declarations() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = r#"mod utils;
pub mod config;

use crate::utils::helper;

fn main() {}
"#;
        let header = extractor.extract_header(contents, Language::Rust);
        assert!(header.contains("mod utils;"));
        assert!(header.contains("pub mod config;"));
        assert!(header.contains("use crate::utils::helper"));
        assert!(!header.contains("fn main"));
    }

    #[test]
    fn test_go_imports() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = r#"package main

import (
	"fmt"
	"net/http"
	
	"github.com/gin-gonic/gin"
)

func main() {
	fmt.Println("Hello")
}
"#;
        let header = extractor.extract_header(contents, Language::Go);
        assert!(header.contains("package main"));
        assert!(header.contains("\"fmt\""));
        assert!(header.contains("\"net/http\""));
        assert!(header.contains("github.com/gin-gonic/gin"));
        assert!(!header.contains("func main"));
    }

    #[test]
    fn test_go_single_import() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = r#"package utils

import "fmt"

func Helper() {}
"#;
        let header = extractor.extract_header(contents, Language::Go);
        assert!(header.contains("package utils"));
        assert!(header.contains("import \"fmt\""));
        assert!(!header.contains("func Helper"));
    }

    #[test]
    fn test_js_imports() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = r#"import React from 'react';
import { useState, useEffect } from 'react';
import * as utils from './utils';

const Component = () => {
    return null;
};
"#;
        let header = extractor.extract_header(contents, Language::JavaScript);
        assert!(header.contains("import React from 'react'"));
        assert!(header.contains("import { useState, useEffect }"));
        assert!(header.contains("import * as utils"));
        assert!(!header.contains("const Component"));
    }

    #[test]
    fn test_js_require() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = r#"const express = require('express');
const { Router } = require('express');
let config = require('./config');

function main() {}
"#;
        let header = extractor.extract_header(contents, Language::JavaScript);
        assert!(header.contains("const express = require('express')"));
        assert!(header.contains("const { Router } = require('express')"));
        assert!(header.contains("let config = require('./config')"));
        assert!(!header.contains("function main"));
    }

    #[test]
    fn test_js_multiline_import() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = r#"import {
    ComponentA,
    ComponentB,
    ComponentC
} from './components';

export default function App() {}
"#;
        let header = extractor.extract_header(contents, Language::JavaScript);
        assert!(header.contains("import {"));
        assert!(header.contains("ComponentA"));
        assert!(header.contains("from './components'"));
        assert!(!header.contains("export default function"));
    }

    #[test]
    fn test_ts_imports() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = r#"import type { FC } from 'react';
import { useState } from 'react';

interface Props {}

const Component: FC<Props> = () => null;
"#;
        let header = extractor.extract_header(contents, Language::TypeScript);
        assert!(header.contains("import type { FC }"));
        assert!(header.contains("import { useState }"));
        assert!(!header.contains("interface Props"));
        assert!(!header.contains("const Component"));
    }

    #[test]
    fn test_java_imports() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = r#"package com.example.app;

import java.util.List;
import java.util.Map;
import static java.util.Collections.emptyList;

public class Main {
    public static void main(String[] args) {}
}
"#;
        let header = extractor.extract_header(contents, Language::Java);
        assert!(header.contains("package com.example.app"));
        assert!(header.contains("import java.util.List"));
        assert!(header.contains("import java.util.Map"));
        assert!(header.contains("import static java.util.Collections.emptyList"));
        assert!(!header.contains("public class Main"));
    }

    #[test]
    fn test_extract_all_parallel() {
        let temp_dir = TempDir::new().unwrap();
        
        let py_path = create_test_file(
            temp_dir.path(),
            "main.py",
            "import os\n\ndef main(): pass",
        );
        let rs_path = create_test_file(
            temp_dir.path(),
            "main.rs",
            "use std::io;\n\nfn main() {}",
        );
        let no_import_path = create_test_file(
            temp_dir.path(),
            "empty.py",
            "def func(): pass",
        );

        let source_files = vec![
            (py_path, Language::Python),
            (rs_path, Language::Rust),
            (no_import_path, Language::Python),
        ];

        let extractor = HeaderExtractor::new(temp_dir.path());
        let headers = extractor.extract_all(&source_files);

        // Should have 2 headers (empty.py has no imports)
        assert_eq!(headers.len(), 2);
        
        let py_header = headers.iter().find(|h| h.path == "main.py");
        assert!(py_header.is_some());
        assert!(py_header.unwrap().header.contains("import os"));

        let rs_header = headers.iter().find(|h| h.path == "main.rs");
        assert!(rs_header.is_some());
        assert!(rs_header.unwrap().header.contains("use std::io"));
    }

    #[test]
    fn test_max_header_lines() {
        let config = HeaderExtractorConfig {
            max_header_lines: 3,
            max_header_bytes: 8 * 1024,
        };
        let extractor = HeaderExtractor::with_config("/tmp", config);
        
        let contents = "import a\nimport b\nimport c\nimport d\nimport e\n";
        let header = extractor.extract_header(contents, Language::Python);
        
        // Should only get first 3 lines
        assert!(header.contains("import a"));
        assert!(header.contains("import b"));
        assert!(header.contains("import c"));
        assert!(!header.contains("import d"));
    }

    #[test]
    fn test_max_header_bytes() {
        let config = HeaderExtractorConfig {
            max_header_lines: 100,
            max_header_bytes: 20, // Very small limit
        };
        let extractor = HeaderExtractor::with_config("/tmp", config);
        
        let contents = "import verylongmodulename\nimport another\n";
        let header = extractor.extract_header(contents, Language::Python);
        
        // Should be truncated
        assert!(header.len() <= 20);
    }

    #[test]
    fn test_empty_file() {
        let extractor = HeaderExtractor::new("/tmp");
        let header = extractor.extract_header("", Language::Python);
        assert!(header.is_empty());
    }

    #[test]
    fn test_no_imports() {
        let extractor = HeaderExtractor::new("/tmp");
        let contents = "def main():\n    print('hello')\n";
        let header = extractor.extract_header(contents, Language::Python);
        assert!(header.is_empty());
    }
}
