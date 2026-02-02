//! # Exit Codes
//!
//! Standard exit codes for the Unfault CLI.
//!
//! These codes follow common Unix conventions and provide meaningful
//! feedback to scripts and CI/CD pipelines.

/// Successful execution
pub const EXIT_SUCCESS: i32 = 0;

/// General error (unspecified)
pub const EXIT_ERROR: i32 = 1;

/// Configuration error (missing or invalid config)
pub const EXIT_CONFIG_ERROR: i32 = 2;

/// Authentication error (invalid or expired credentials)
pub const EXIT_AUTH_ERROR: i32 = 3;

/// Network error (connection failed, timeout, etc.)
pub const EXIT_NETWORK_ERROR: i32 = 4;

/// Analysis found issues (findings detected)
pub const EXIT_FINDINGS_FOUND: i32 = 5;

/// Invalid input (bad arguments, invalid files, etc.)
pub const EXIT_INVALID_INPUT: i32 = 6;

/// Service unavailable (API down, maintenance, etc.)
pub const EXIT_SERVICE_UNAVAILABLE: i32 = 7;

/// Session error (session not found, expired, etc.)
pub const EXIT_SESSION_ERROR: i32 = 8;

/// Subscription required for this operation (402 Payment Required)
///
/// Used when free Insights queries are exhausted and subscription is needed.
pub const EXIT_SUBSCRIPTION_REQUIRED: i32 = 10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_codes_are_distinct() {
        let codes = [
            EXIT_SUCCESS,
            EXIT_ERROR,
            EXIT_CONFIG_ERROR,
            EXIT_AUTH_ERROR,
            EXIT_NETWORK_ERROR,
            EXIT_FINDINGS_FOUND,
            EXIT_INVALID_INPUT,
            EXIT_SERVICE_UNAVAILABLE,
            EXIT_SESSION_ERROR,
            EXIT_SUBSCRIPTION_REQUIRED,
        ];

        // Check all codes are unique
        for (i, &code1) in codes.iter().enumerate() {
            for (j, &code2) in codes.iter().enumerate() {
                if i != j {
                    assert_ne!(code1, code2, "Exit codes {} and {} are not unique", i, j);
                }
            }
        }
    }

    #[test]
    fn test_success_is_zero() {
        assert_eq!(EXIT_SUCCESS, 0);
    }

    #[test]
    fn test_error_codes_are_positive() {
        const _: () = {
            assert!(EXIT_ERROR > 0);
            assert!(EXIT_CONFIG_ERROR > 0);
            assert!(EXIT_AUTH_ERROR > 0);
            assert!(EXIT_NETWORK_ERROR > 0);
            assert!(EXIT_FINDINGS_FOUND > 0);
            assert!(EXIT_INVALID_INPUT > 0);
            assert!(EXIT_SERVICE_UNAVAILABLE > 0);
            assert!(EXIT_SESSION_ERROR > 0);
            assert!(EXIT_SUBSCRIPTION_REQUIRED > 0);
        };
    }
}
