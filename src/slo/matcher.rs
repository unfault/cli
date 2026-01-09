//! Path pattern matching for SLOs to HTTP routes.
//!
//! This module provides utilities to match SLO path patterns against
//! HTTP route paths discovered in the code graph.

use petgraph::graph::NodeIndex;
use unfault_core::graph::CodeGraph;

use super::types::SloDefinition;

/// Match an SLO path pattern to route handler nodes in the graph.
///
/// Returns NodeIndexes of Function nodes where `is_handler=true` and
/// the `http_path` matches the SLO's `path_pattern`.
///
/// # Pattern Matching Rules
///
/// | SLO Pattern | Matches Route |
/// |-------------|---------------|
/// | `/api/users` | `/api/users` (exact) |
/// | `/api/users/*` | `/api/users/:id`, `/api/users/{id}` |
/// | `/api/**` | Any route starting with `/api/` |
/// | `*` | All routes |
pub fn find_matching_routes(slo: &SloDefinition, graph: &CodeGraph) -> Vec<NodeIndex> {
    let Some(ref pattern) = slo.path_pattern else {
        return vec![];
    };

    // Get all HTTP route handlers from the graph
    let routes = graph.get_http_route_handlers();

    routes
        .into_iter()
        .filter(|(_, route_path, route_method)| {
            // Check HTTP method match if SLO specifies one
            if let Some(ref slo_method) = slo.http_method {
                if let Some(rm) = route_method {
                    if !slo_method.eq_ignore_ascii_case(rm) {
                        return false;
                    }
                }
            }

            // Check path pattern match
            path_matches(pattern, route_path)
        })
        .map(|(idx, _, _)| idx)
        .collect()
}

/// Check if a route path matches an SLO path pattern.
///
/// Supports:
/// - Exact match: `/api/users` matches `/api/users`
/// - Single wildcard: `/api/users/*` matches `/api/users/:id`
/// - Double wildcard: `/api/**` matches any path starting with `/api/`
/// - Universal: `*` matches everything
fn path_matches(pattern: &str, route_path: &str) -> bool {
    // Universal wildcard
    if pattern == "*" {
        return true;
    }

    // Normalize paths for comparison
    let pattern = normalize_path(pattern);
    let route = normalize_route_path(route_path);

    // Double wildcard (glob): /api/** matches /api/anything/else
    if pattern.ends_with("/**") {
        let prefix = &pattern[..pattern.len() - 3];
        return route.starts_with(prefix) || route == prefix.trim_end_matches('/');
    }

    // Single wildcard at end: /api/users/* matches /api/users/:id
    if pattern.ends_with("/*") {
        let prefix = &pattern[..pattern.len() - 2];
        // Must match prefix and have exactly one more segment
        if !route.starts_with(prefix) {
            return false;
        }
        let remainder = &route[prefix.len()..];
        // remainder should be empty or start with / and have no more /
        if remainder.is_empty() {
            return true;
        }
        if remainder.starts_with('/') {
            let after_slash = &remainder[1..];
            return !after_slash.contains('/');
        }
        return false;
    }

    // Exact match (after normalization)
    pattern == route
}

/// Normalize an SLO path pattern for comparison.
fn normalize_path(path: &str) -> String {
    let mut p = path.to_lowercase();
    // Remove trailing slash unless it's the root
    if p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    p
}

/// Normalize a route path, converting framework-specific parameter syntax to a canonical form.
///
/// Converts:
/// - `:id` (Express, Gin) → `*`
/// - `{id}` (FastAPI, Axum) → `*`
/// - `<id>` (Flask, Rocket) → `*`
fn normalize_route_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    let mut chars = path.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            ':' => {
                // Express/Gin style :param
                result.push('*');
                // Skip until next / or end
                while chars.peek().is_some_and(|&c| c != '/') {
                    chars.next();
                }
            }
            '{' => {
                // FastAPI/Axum style {param}
                result.push('*');
                // Skip until }
                while chars.peek().is_some_and(|&c| c != '}') {
                    chars.next();
                }
                chars.next(); // consume }
            }
            '<' => {
                // Flask/Rocket style <param>
                result.push('*');
                // Skip until >
                while chars.peek().is_some_and(|&c| c != '>') {
                    chars.next();
                }
                chars.next(); // consume >
            }
            _ => result.push(c.to_ascii_lowercase()),
        }
    }

    // Remove trailing slash unless root
    if result.len() > 1 && result.ends_with('/') {
        result.pop();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_route_path_express() {
        assert_eq!(normalize_route_path("/users/:id"), "/users/*");
        assert_eq!(
            normalize_route_path("/users/:id/posts/:postId"),
            "/users/*/posts/*"
        );
    }

    #[test]
    fn test_normalize_route_path_fastapi() {
        assert_eq!(normalize_route_path("/users/{user_id}"), "/users/*");
        assert_eq!(
            normalize_route_path("/users/{id}/posts/{post_id}"),
            "/users/*/posts/*"
        );
    }

    #[test]
    fn test_normalize_route_path_flask() {
        assert_eq!(normalize_route_path("/users/<id>"), "/users/*");
        assert_eq!(
            normalize_route_path("/users/<int:id>/posts/<post_id>"),
            "/users/*/posts/*"
        );
    }

    #[test]
    fn test_path_matches_exact() {
        assert!(path_matches("/api/users", "/api/users"));
        assert!(path_matches("/api/users", "/API/Users")); // case insensitive
        assert!(path_matches("/api/users/", "/api/users")); // trailing slash normalized
        assert!(!path_matches("/api/users", "/api/posts"));
    }

    #[test]
    fn test_path_matches_single_wildcard() {
        assert!(path_matches("/api/users/*", "/api/users/:id"));
        assert!(path_matches("/api/users/*", "/api/users/{id}"));
        assert!(path_matches("/api/users/*", "/api/users/<id>"));
        assert!(path_matches("/api/users/*", "/api/users/123"));
        assert!(!path_matches("/api/users/*", "/api/users/123/posts"));
    }

    #[test]
    fn test_path_matches_double_wildcard() {
        assert!(path_matches("/api/**", "/api/users"));
        assert!(path_matches("/api/**", "/api/users/123"));
        assert!(path_matches("/api/**", "/api/users/123/posts"));
        assert!(!path_matches("/api/**", "/other/path"));
    }

    #[test]
    fn test_path_matches_universal() {
        assert!(path_matches("*", "/any/path"));
        assert!(path_matches("*", "/"));
    }
}
