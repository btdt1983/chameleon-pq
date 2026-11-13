//! Administrator policy: what an unprivileged user may do through the service.
//!
//! Loaded from `policy.toml` next to the service config. The file is strict:
//! unknown keys and wrong types are errors, and an invalid policy stops the
//! service from starting (fail closed) instead of silently falling back to
//! something looser. A **missing** file means [`Policy::default`], which keeps
//! today's behaviour; that is only safe because the directory holding it is
//! admin-only (the Windows host verifies that before reading anything).
//!
//! `auto_connect` is deliberately absent: it needs a real reconnect/backoff
//! story first, and an option that does nothing is worse than none.

use crate::config::{AppConfig, TrafficProfile};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// How the kill switch is decided for a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchPolicy {
    /// Follow `tun.kill_switch` in the service config (today's behaviour).
    #[default]
    UserChoice,
    /// Forced ON at every connect, whatever the config says, and kept engaged
    /// when the user disconnects. The user cannot clear it; an administrator
    /// can (`killswitch off`, or stopping the service).
    ///
    /// This is NOT "traffic blocked whenever the service runs": engaging needs
    /// the TUN adapter to exist, so it takes effect from the first connect.
    Enforced,
    /// Forced OFF at every connect.
    Off,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    /// May the user disconnect? Connecting is always allowed (there is no
    /// auto-connect yet, so forbidding it would make the tunnel unusable).
    pub allow_user_disconnect: bool,
    /// Profiles the user may pick. `None` = all of them. The config's own
    /// profile must be in the list (checked by [`Policy::validate`]).
    pub allowed_profiles: Option<Vec<TrafficProfile>>,
    pub kill_switch: KillSwitchPolicy,
    /// May the GUI contact GitHub for "Check for updates"? Off by default: a
    /// managed machine should not phone out from a user's click.
    pub allow_update_check: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allow_user_disconnect: true,
            allowed_profiles: None,
            kill_switch: KillSwitchPolicy::UserChoice,
            allow_update_check: false,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid policy {path}: {message}")]
    Invalid { path: String, message: String },
}

impl Policy {
    /// Parse a policy document. `origin` is only used in error messages.
    pub fn parse(text: &str, origin: &str) -> Result<Self, PolicyError> {
        toml::from_str::<Policy>(text).map_err(|e| PolicyError::Invalid {
            path: origin.to_string(),
            message: e.to_string(),
        })
    }

    /// Load `path`. A missing file is the default policy; any other problem
    /// (unreadable, malformed) is an error.
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text, &path.display().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(PolicyError::Read {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// Cross-checks against the service config. Run once at startup.
    pub fn validate(&self, cfg: &AppConfig) -> Result<(), PolicyError> {
        let bad = |message: String| PolicyError::Invalid {
            path: "policy".into(),
            message,
        };
        if self.kill_switch == KillSwitchPolicy::Enforced && !cfg.tun.route_all {
            return Err(bad(
                "kill_switch = \"enforced\" needs tun.route_all = true in the service config \
                 (the kill switch only works with a full tunnel)"
                    .into(),
            ));
        }
        if let Some(list) = &self.allowed_profiles {
            if list.is_empty() {
                return Err(bad("allowed_profiles is empty: nobody could connect".into()));
            }
            if !list.contains(&cfg.traffic.profile) {
                return Err(bad(format!(
                    "the service config uses traffic profile '{}' which allowed_profiles does \
                     not list",
                    cfg.traffic.profile
                )));
            }
        }
        Ok(())
    }

    pub fn profile_allowed(&self, p: TrafficProfile) -> bool {
        // map_or, not is_none_or: that needs Rust 1.82 and the MSRV is 1.80.
        self.allowed_profiles
            .as_ref()
            .map_or(true, |list| list.contains(&p))
    }

    /// Whether to engage the kill switch for a connection, given the config's
    /// own setting.
    pub fn kill_switch_wanted(&self, config_value: bool) -> bool {
        match self.kill_switch {
            KillSwitchPolicy::UserChoice => config_value,
            KillSwitchPolicy::Enforced => true,
            KillSwitchPolicy::Off => false,
        }
    }

    /// A user-initiated disconnect leaves the kill switch engaged under
    /// `enforced`; otherwise it takes it down (today's behaviour).
    pub fn disconnect_keeps_kill_switch(&self) -> bool {
        self.kill_switch == KillSwitchPolicy::Enforced
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> AppConfig {
        AppConfig::load(Path::new("config.example.toml")).unwrap()
    }

    #[test]
    fn an_empty_file_is_the_default_policy() {
        assert_eq!(Policy::parse("", "t").unwrap(), Policy::default());
    }

    #[test]
    fn the_default_keeps_todays_behaviour() {
        let p = Policy::default();
        assert!(p.allow_user_disconnect);
        assert!(p.profile_allowed(TrafficProfile::Custom));
        assert!(p.kill_switch_wanted(true) && !p.kill_switch_wanted(false));
        assert!(!p.disconnect_keeps_kill_switch());
        assert!(!p.allow_update_check);
    }

    #[test]
    fn a_missing_file_is_the_default_but_other_errors_are_not() {
        let missing = Path::new("definitely/not/here/policy.toml");
        assert_eq!(Policy::load(missing).unwrap(), Policy::default());
        // A directory exists but cannot be read as a file: an error, not a default.
        assert!(matches!(
            Policy::load(Path::new(".")),
            Err(PolicyError::Read { .. })
        ));
    }

    #[test]
    fn unknown_keys_and_wrong_values_are_errors() {
        for bad in [
            "auto_connect = \"never\"",
            "allow_user_disconect = false",
            "kill_switch = \"always\"",
            "allowed_profiles = [\"turbo\"]",
            "allow_user_disconnect = \"no\"",
            "allowed_profiles = \"balanced\"",
        ] {
            assert!(Policy::parse(bad, "t").is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn the_shipped_managed_example_parses_and_validates() {
        let text = include_str!("../../packaging/windows/policy.managed.example.toml");
        let p = Policy::parse(text, "policy.managed.example.toml").unwrap();
        assert!(!p.allow_user_disconnect);
        assert_eq!(p.kill_switch, KillSwitchPolicy::Enforced);
        // `enforced` needs a full tunnel in the service config.
        let mut c = cfg();
        c.tun.route_all = true;
        assert!(p.validate(&c).is_ok());
        c.tun.route_all = false;
        assert!(p.validate(&c).is_err());
    }

    #[test]
    fn kill_switch_modes() {
        let enforced = Policy::parse("kill_switch = \"enforced\"", "t").unwrap();
        assert!(enforced.kill_switch_wanted(false) && enforced.kill_switch_wanted(true));
        assert!(enforced.disconnect_keeps_kill_switch());

        let off = Policy::parse("kill_switch = \"off\"", "t").unwrap();
        assert!(!off.kill_switch_wanted(true) && !off.kill_switch_wanted(false));
        assert!(!off.disconnect_keeps_kill_switch());

        let user = Policy::parse("kill_switch = \"user_choice\"", "t").unwrap();
        assert!(user.kill_switch_wanted(true) && !user.kill_switch_wanted(false));
    }

    #[test]
    fn profile_allow_list() {
        let p = Policy::parse("allowed_profiles = [\"balanced\", \"stealth\"]", "t").unwrap();
        assert!(p.profile_allowed(TrafficProfile::Balanced));
        assert!(p.profile_allowed(TrafficProfile::Stealth));
        assert!(!p.profile_allowed(TrafficProfile::Throughput));
        assert!(!p.profile_allowed(TrafficProfile::Custom));
    }

    #[test]
    fn validate_checks_the_list_against_the_config() {
        let c = cfg();
        // Empty list: nobody could connect.
        let p = Policy::parse("allowed_profiles = []", "t").unwrap();
        assert!(p.validate(&c).is_err());
        // A list that excludes the config's own profile.
        let other = [
            TrafficProfile::Stealth,
            TrafficProfile::Balanced,
            TrafficProfile::Throughput,
            TrafficProfile::Off,
        ]
        .into_iter()
        .find(|p| *p != c.traffic.profile)
        .unwrap();
        let text = format!(
            "allowed_profiles = [\"{}\"]",
            format!("{other:?}").to_lowercase()
        );
        assert!(Policy::parse(&text, "t").unwrap().validate(&c).is_err());
        // Including it is fine, and so is no list at all.
        let ok = format!(
            "allowed_profiles = [\"{}\"]",
            format!("{:?}", c.traffic.profile).to_lowercase()
        );
        assert!(Policy::parse(&ok, "t").unwrap().validate(&c).is_ok());
        assert!(Policy::default().validate(&c).is_ok());
    }
}
