// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::clock::{Clock, SystemClock};
use oauth2::basic::BasicClient;
use oauth2::reqwest;
use oauth2::{
    AuthUrl, ClientId, ClientSecret, EndpointNotSet, EndpointSet, Scope, TokenResponse, TokenUrl,
};
use std::sync::Arc;
use thiserror::Error;
use url;

const DEFAULT_REFRESH_SKEW_SECONDS: u64 = 30;

#[derive(Debug, Error)]
pub enum OAuth2TokenProviderError {
    #[error("invalid config: {0}")]
    InvalidConfig(&'static str),

    #[error("invalid token_url: {0}")]
    InvalidTokenUrl(#[from] url::ParseError),

    #[error("failed to build http client: {0}")]
    HttpClientBuild(String),

    #[error("token request failed: {0}")]
    TokenRequest(String),

    #[error("token response missing expires_in")]
    MissingExpiresIn,
}

#[derive(Debug, Clone)]
pub struct ClientCredentialsConfig {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub refresh_skew_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expired_at: u64,
}

type ConfiguredBasicClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

#[derive(Debug)]
pub struct OAuth2TokenProvider {
    config: ClientCredentialsConfig,
    client: ConfiguredBasicClient,
    cache: tokio::sync::RwLock<Option<CachedToken>>,
    clock: Arc<dyn Clock>,
}

pub type Result<T> = std::result::Result<T, OAuth2TokenProviderError>;

impl OAuth2TokenProvider {
    pub fn new(config: ClientCredentialsConfig) -> Result<Self> {
        if config.token_url.trim().is_empty() {
            return Err(OAuth2TokenProviderError::InvalidConfig(
                "token_url must not be empty",
            ));
        }
        if config.client_id.trim().is_empty() {
            return Err(OAuth2TokenProviderError::InvalidConfig(
                "client_id must not be empty",
            ));
        }
        if config.client_secret.trim().is_empty() {
            return Err(OAuth2TokenProviderError::InvalidConfig(
                "client_secret must not be empty",
            ));
        }

        let token_url = TokenUrl::new(config.token_url.clone())?;
        let auth_url = AuthUrl::new("https://invalid.local/authorize".to_string())
            .expect("hardcoded url must be valid");

        let client = BasicClient::new(ClientId::new(config.client_id.clone()))
            .set_client_secret(ClientSecret::new(config.client_secret.clone()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url);

        Ok(Self {
            config,
            client,
            cache: tokio::sync::RwLock::new(None),
            clock: Arc::new(SystemClock::default()),
        })
    }

    pub fn with_clock(config: ClientCredentialsConfig, clock: Arc<dyn Clock>) -> Result<Self> {
        let mut p = Self::new(config)?;
        p.clock = clock;
        Ok(p)
    }

    pub fn refresh_skew(&self) -> u64 {
        match self.config.refresh_skew_seconds {
            Some(0) => 0,
            Some(seconds) => seconds,
            None => DEFAULT_REFRESH_SKEW_SECONDS,
        }
    }

    pub fn get_token(&self) -> Result<String> {
        let guard = self.cache.blocking_read();
        if let Some(token) = guard.as_ref() {
            let now = self.clock.now();
            let skew = self.refresh_skew();
            if skew == 0 || token.expired_at > now.saturating_add(skew) {
                return Ok(token.access_token.clone());
            }
        }
        drop(guard); // read lock dropped

        let http_client = reqwest::blocking::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| OAuth2TokenProviderError::HttpClientBuild(e.to_string()))?;

        let mut req = self.client.exchange_client_credentials();
        for s in &self.config.scopes {
            let scope = s.trim();
            if !scope.is_empty() {
                req = req.add_scope(Scope::new(scope.to_string()));
            }
        }

        let token = req
            .request(&http_client)
            .map_err(|e| OAuth2TokenProviderError::TokenRequest(e.to_string()))?;

        let access_token = token.access_token().secret().to_string();
        let expires_in = token
            .expires_in()
            .ok_or(OAuth2TokenProviderError::MissingExpiresIn)?
            .as_secs();

        let expired_at = self.clock.now().saturating_add(expires_in);

        let mut guard = self.cache.blocking_write();
        *guard = Some(CachedToken {
            access_token: access_token.clone(),
            expired_at,
        });
        drop(guard); // write lock dropped

        Ok(access_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use httpmock::prelude::*;
    use std::sync::Arc;

    fn cfg(token_url: String) -> ClientCredentialsConfig {
        ClientCredentialsConfig {
            token_url,
            client_id: "client-id".to_string(),
            client_secret: "client-secret".to_string(),
            scopes: vec!["scope-a".into(), "scope-b".into()],
            refresh_skew_seconds: Some(30),
        }
    }

    #[test]
    fn new_rejects_empty_fields() {
        let base = ClientCredentialsConfig {
            token_url: "http://localhost/token".into(),
            client_id: "id".into(),
            client_secret: "secret".into(),
            scopes: vec![],
            refresh_skew_seconds: None,
        };

        let mut c = base.clone();
        c.token_url = "   ".into();
        assert!(matches!(
            OAuth2TokenProvider::new(c).unwrap_err(),
            OAuth2TokenProviderError::InvalidConfig(_)
        ));

        let mut c = base.clone();
        c.client_id = "".into();
        assert!(matches!(
            OAuth2TokenProvider::new(c).unwrap_err(),
            OAuth2TokenProviderError::InvalidConfig(_)
        ));

        let mut c = base.clone();
        c.client_secret = " ".into();
        assert!(matches!(
            OAuth2TokenProvider::new(c).unwrap_err(),
            OAuth2TokenProviderError::InvalidConfig(_)
        ));
    }

    #[test]
    fn refresh_skew_none_uses_default() {
        let config = ClientCredentialsConfig {
            token_url: "http://localhost/token".into(),
            client_id: "id".into(),
            client_secret: "secret".into(),
            scopes: vec![],
            refresh_skew_seconds: None,
        };

        let provider = OAuth2TokenProvider::new(config).unwrap();
        assert_eq!(provider.refresh_skew(), DEFAULT_REFRESH_SKEW_SECONDS);
    }

    #[test]
    fn get_token_fetches_and_caches_token() {
        let server = MockServer::start();

        let token_mock = server.mock(|when, then| {
            when.method(POST)
                .path("/token")
                .header("content-type", "application/x-www-form-urlencoded")
                .body_not("grant_type=client_credentials")
                .body_not("scope=scope-a+scope-b");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"access_token":"t1","token_type":"bearer","expires_in":3600}"#);
        });

        let clock = Arc::new(ManualClock::new(1000));
        let provider =
            OAuth2TokenProvider::with_clock(cfg(format!("{}/token", server.base_url())), clock)
                .unwrap();

        let t1 = provider.get_token().unwrap();
        let t2 = provider.get_token().unwrap();

        assert_eq!(t1, "t1");
        assert_eq!(t2, "t1");
        token_mock.assert_calls(1);
    }

    #[test]
    fn get_token_refreshes_when_skew_window_reached() {
        let server = MockServer::start();

        let mock_server = server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"access_token":"t1","token_type":"bearer","expires_in":10}"#);
        });

        let clock = Arc::new(ManualClock::new(1000));

        let config = ClientCredentialsConfig {
            token_url: format!("{}/token", server.base_url()),
            client_id: "client-id".into(),
            client_secret: "client-secret".into(),
            scopes: vec![],
            refresh_skew_seconds: Some(30),
        };

        let provider = OAuth2TokenProvider::with_clock(config, clock.clone()).unwrap();

        let token = provider.get_token().unwrap();
        assert_eq!(token, "t1");

        // Move time forward a bit
        clock.advance(300);

        provider.get_token().unwrap();

        mock_server.assert_calls(2);
    }

    #[test]
    fn get_token_does_not_refresh_when_skew_is_zero() {
        let server = MockServer::start();

        let mock_server = server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"access_token":"t1","token_type":"bearer","expires_in":1}"#);
        });

        let clock = Arc::new(ManualClock::new(1000));

        let config = ClientCredentialsConfig {
            token_url: format!("{}/token", server.base_url()),
            client_id: "client-id".into(),
            client_secret: "client-secret".into(),
            scopes: vec![],
            refresh_skew_seconds: Some(0),
        };

        let provider = OAuth2TokenProvider::with_clock(config, clock.clone()).unwrap();

        let token = provider.get_token().unwrap();
        // Move time forward a bit
        clock.advance(1000);
        provider.get_token().unwrap();

        assert_eq!(token, "t1");
        mock_server.assert_calls(1);
    }

    #[test]
    fn missing_expires_in_returns_error() {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(POST).path("/token");
            then.status(200)
                .header("content-type", "application/json")
                .body(r#"{"access_token":"t1","token_type":"bearer"}"#);
        });

        let clock = Arc::new(ManualClock::new(1000));
        let provider =
            OAuth2TokenProvider::with_clock(cfg(format!("{}/token", server.base_url())), clock)
                .unwrap();

        let err = provider.get_token().unwrap_err();
        assert!(matches!(err, OAuth2TokenProviderError::MissingExpiresIn));
    }

    #[test]
    fn token_request_error_is_mapped() {
        let clock = Arc::new(ManualClock::new(1000));
        let provider = OAuth2TokenProvider::with_clock(
            ClientCredentialsConfig {
                token_url: "http://127.0.0.1:9/token".into(),
                client_id: "client-id".into(),
                client_secret: "client-secret".into(),
                scopes: vec![],
                refresh_skew_seconds: None,
            },
            clock,
        )
        .unwrap();

        let err = provider.get_token().unwrap_err();
        assert!(matches!(err, OAuth2TokenProviderError::TokenRequest(_)));
    }
}
