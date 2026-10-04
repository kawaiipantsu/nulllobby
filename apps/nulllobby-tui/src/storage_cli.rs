//! CLI intent only; storage keys and organization signatures live below the UI.
use std::{ffi::OsString, path::PathBuf};
#[derive(Default)]
pub struct Args {
    vault: Option<(PathBuf, bool)>,
    create_issuer: Option<PathBuf>,
    issuer: Option<PathBuf>,
    request: Option<PathBuf>,
    output: Option<PathBuf>,
    name: Option<String>,
    role: Option<String>,
    hours: Option<u64>,
}
impl Args {
    pub fn parse<'a>(
        &mut self,
        option: &str,
        args: &mut impl Iterator<Item = &'a OsString>,
    ) -> Result<bool, &'static str> {
        if !matches!(
            option,
            "--vault"
                | "--vault-init"
                | "--org-create-issuer"
                | "--org-issuer"
                | "--org-issue"
                | "--org-output"
                | "--org-name"
                | "--org-role"
                | "--org-hours"
        ) {
            return Ok(false);
        }
        let value = args
            .next()
            .ok_or("Storage/issuer option requires a value")?;
        let duplicate = match option {
            "--vault" | "--vault-init" => self
                .vault
                .replace((value.into(), option == "--vault-init"))
                .is_some(),
            "--org-create-issuer" => self.create_issuer.replace(value.into()).is_some(),
            "--org-issuer" => self.issuer.replace(value.into()).is_some(),
            "--org-issue" => self.request.replace(value.into()).is_some(),
            "--org-output" => self.output.replace(value.into()).is_some(),
            "--org-name" => self
                .name
                .replace(
                    value
                        .to_str()
                        .ok_or("Invalid organization label")?
                        .to_owned(),
                )
                .is_some(),
            "--org-role" => self
                .role
                .replace(value.to_str().ok_or("Invalid role")?.to_owned())
                .is_some(),
            "--org-hours" => self
                .hours
                .replace(
                    value
                        .to_str()
                        .and_then(|s| s.parse().ok())
                        .filter(|h| *h > 0 && *h <= 8)
                        .ok_or("Credential lifetime must be 1..8 hours")?,
                )
                .is_some(),
            _ => return Ok(false),
        };
        if duplicate {
            return Err("Duplicate storage/issuer option");
        }
        Ok(true)
    }
    /// True means an offline administration command completed; do not start networking.
    pub fn apply(self, config: &mut nulllobby_app::Config) -> Result<bool, &'static str> {
        let issuance = self.issuer.is_some()
            || self.request.is_some()
            || self.output.is_some()
            || self.name.is_some()
            || self.role.is_some()
            || self.hours.is_some();
        if self.create_issuer.is_some() && issuance
            || self.vault.is_some() && (issuance || self.create_issuer.is_some())
        {
            return Err("Choose one vault or offline issuer operation");
        }
        if let Some(path) = self.create_issuer {
            println!("{}", nulllobby_app::organization::create_issuer(&path)?);
            return Ok(true);
        }
        if issuance {
            nulllobby_app::organization::issue(
                &self.issuer.ok_or("--org-issuer required")?,
                &self.request.ok_or("--org-issue required")?,
                &self.output.ok_or("--org-output required")?,
                &self.name.ok_or("--org-name required")?,
                self.role.as_deref().unwrap_or("member"),
                self.hours.unwrap_or(8),
            )?;
            println!(
                "Organization credential issued. Verify requester eligibility independently; the enrollment request proves key possession only."
            );
            return Ok(true);
        }
        if let Some((path, create)) = self.vault {
            config.vault = Some(nulllobby_app::organization::open_vault(&path, create)?);
            if create {
                println!(
                    "Encrypted vault created. Reopen with --vault and enable /identity persistent separately in each selected lobby."
                );
                return Ok(true);
            }
        }
        Ok(false)
    }
}
pub const HELP: &str = "\nOptional encrypted storage (Linux Secret Service + libsecret-tools):\n--vault-init ABSOLUTE_PATH  Create an empty vault, then exit\n--vault ABSOLUTE_PATH       Open vault; no lobby is saved automatically\n/identity persistent|ephemeral /stored /resume N\n/delivery live|durable /mailbox on|off /sync\n/rotate /revoke FULL_FINGERPRINT (private lobby administrator)\n\nOptional offline organization credentials:\n--org-create-issuer ABSOLUTE_PATH\n--org-issuer ABSOLUTE_PATH --org-issue REQUEST --org-output CREDENTIAL\n  --org-name TEAM [--org-role member] [--org-hours 8]\n/org trust ISSUER_PUBLIC_KEY /org request FILE /org import FILE /org off\nOrganization membership is lobby scoped and separate from fingerprint trust.\nNo CA lookup; release keys are not used for organization membership.";
