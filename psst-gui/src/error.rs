use std::{error, fmt, sync::Arc};

use druid::Data;

/// Detailed HTTP error information for better error reporting.
#[derive(Clone, Debug, Data)]
pub struct HttpErrorDetails {
    /// HTTP status code (e.g., 400, 401, 404, 500)
    pub status_code: u16,
    /// HTTP status text (e.g., "Bad Request", "Unauthorized")
    pub status_text: Arc<str>,
    /// The request URL that failed
    pub url: Arc<str>,
    /// The HTTP method used (GET, POST, etc.)
    pub method: Arc<str>,
    /// The response body content (if available)
    pub body: Option<Arc<str>>,
    /// A user-friendly error message derived from the response
    pub message: Arc<str>,
}

impl HttpErrorDetails {
    pub fn new(
        status_code: u16,
        status_text: impl Into<Arc<str>>,
        url: impl Into<Arc<str>>,
        method: impl Into<Arc<str>>,
        body: Option<impl Into<Arc<str>>>,
    ) -> Self {
        let status_text: Arc<str> = status_text.into();
        let body: Option<Arc<str>> = body.map(Into::into);
        
        // Try to extract a meaningful message from the response body
        let message = Self::extract_message(&body, &status_text, status_code);
        
        Self {
            status_code,
            status_text,
            url: url.into(),
            method: method.into(),
            body,
            message,
        }
    }
    
    /// Try to extract a user-friendly error message from the response body.
    /// Spotify API typically returns JSON with "error" or "error.message" fields.
    fn extract_message(body: &Option<Arc<str>>, status_text: &str, status_code: u16) -> Arc<str> {
        if let Some(body_str) = body {
            // Try to parse as JSON and extract common error message fields
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str.as_ref()) {
                // Spotify API error format: {"error": {"status": 401, "message": "..."}}
                if let Some(error_obj) = json.get("error") {
                    if let Some(msg) = error_obj.get("message").and_then(|m| m.as_str()) {
                        return msg.into();
                    }
                    if let Some(msg) = error_obj.as_str() {
                        return msg.into();
                    }
                }
                // Alternative formats: {"message": "..."} or {"detail": "..."}
                if let Some(msg) = json.get("message").and_then(|m| m.as_str()) {
                    return msg.into();
                }
                if let Some(msg) = json.get("detail").and_then(|m| m.as_str()) {
                    return msg.into();
                }
            }
            // If body is short enough and not JSON, use it directly
            if body_str.len() < 200 && !body_str.starts_with('{') {
                return body_str.clone();
            }
        }
        // Fall back to status text
        format!("{} ({})", status_text, status_code).into()
    }
    
    /// Get a formatted summary for user display
    pub fn summary(&self) -> String {
        format!("HTTP {} - {}", self.status_code, self.message)
    }
    
    /// Get detailed information for debugging/logging
    #[allow(dead_code)]
    pub fn details(&self) -> String {
        let mut details = format!(
            "HTTP Error:\n  Status: {} {}\n  URL: {}\n  Method: {}",
            self.status_code, self.status_text, self.url, self.method
        );
        if let Some(body) = &self.body {
            // Truncate very long bodies
            let truncated = if body.len() > 500 {
                format!("{}... (truncated)", &body[..500])
            } else {
                body.to_string()
            };
            details.push_str(&format!("\n  Response: {}", truncated));
        }
        details
    }
}

#[derive(Clone, Debug, Data)]
pub enum Error {
    /// A simple error with just a message string
    WebApiError(Arc<str>),
    /// A detailed HTTP error with status code, response body, etc.
    HttpError(HttpErrorDetails),
}

impl Error {
    /// Create a simple WebApiError from any displayable type
    pub fn web_api<T: fmt::Display>(err: T) -> Self {
        Error::WebApiError(err.to_string().into())
    }
    
    /// Create a detailed HTTP error
    pub fn http(
        status_code: u16,
        status_text: impl Into<Arc<str>>,
        url: impl Into<Arc<str>>,
        method: impl Into<Arc<str>>,
        body: Option<impl Into<Arc<str>>>,
    ) -> Self {
        Error::HttpError(HttpErrorDetails::new(status_code, status_text, url, method, body))
    }
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::WebApiError(err) => f.write_str(err),
            Self::HttpError(details) => write!(f, "{}", details.summary()),
        }
    }
}
