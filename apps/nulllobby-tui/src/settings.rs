//! Explicit opt-in preferences. No identities, trust, history or private cards.
use nulllobby_core::{LobbyCard, LobbyKind, domain::Nickname};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
};
use toml_edit::{ArrayOfTables, DocumentMut, Table, value};

#[derive(Clone)]
pub struct Bookmark {
    pub name: String,
    pub card: String,
    pub autoconnect: bool,
}
pub struct Settings {
    pub timestamps: bool,
    pub icons: bool,
    pub lobbies: bool,
    pub members: bool,
    pub ascii: bool,
    pub theme: String,
    pub nickname: Option<String>,
    pub welcome_seen: bool,
    pub bookmarks: Vec<Bookmark>,
    pub path: Option<PathBuf>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            timestamps: true,
            icons: false,
            lobbies: true,
            members: true,
            ascii: false,
            theme: "null".into(),
            nickname: None,
            welcome_seen: false,
            bookmarks: Vec::new(),
            path: None,
        }
    }
}
fn default_path() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|p| PathBuf::from(p).is_absolute())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")))
        .map(|p| p.join("nulllobby/settings.toml"))
}
impl Settings {
    pub fn load(explicit: Option<PathBuf>) -> Result<Self, &'static str> {
        let requested = explicit.is_some();
        let path = explicit.or_else(default_path);
        let Some(path) = path else {
            return Ok(Self::default());
        };
        if !path.exists() {
            return Ok(Self {
                path: if requested { Some(path) } else { None },
                ..Self::default()
            });
        }
        let meta = fs::symlink_metadata(&path).map_err(|_| "Cannot inspect settings")?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            return Err("Settings must be a regular file");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err("Settings permissions must be 0600");
            }
        }
        let mut text = String::new();
        File::open(&path)
            .map_err(|_| "Cannot open settings")?
            .take(32769)
            .read_to_string(&mut text)
            .map_err(|_| "Cannot read settings")?;
        if text.len() > 32768 {
            return Err("Settings exceed 32 KiB");
        }
        Self::decode(&text, Some(path))
    }
    fn decode(text: &str, path: Option<PathBuf>) -> Result<Self, &'static str> {
        let doc = text
            .parse::<DocumentMut>()
            .map_err(|_| "Invalid settings TOML")?;
        if doc.get("version").and_then(|v| v.as_integer()) != Some(1) {
            return Err("Unsupported settings version");
        }
        let mut s = Self {
            path,
            ..Self::default()
        };
        for (key, item) in doc.iter() {
            match key {
                "version" | "bookmarks" => {}
                "theme" => {
                    let t = item.as_str().ok_or("Invalid theme setting")?;
                    if t.len() > 512 || t.chars().any(char::is_control) {
                        return Err("Invalid theme setting");
                    }
                    s.theme = t.into();
                }
                "nickname" => {
                    let n = item.as_str().ok_or("Invalid nickname setting")?;
                    Nickname::new(n).map_err(|_| "Invalid remembered nickname")?;
                    s.nickname = Some(n.into());
                }
                key => {
                    let v = item.as_bool().ok_or("Invalid preference")?;
                    match key {
                        "timestamps" => s.timestamps = v,
                        "icons" => s.icons = v,
                        "lobbies" => s.lobbies = v,
                        "members" => s.members = v,
                        "ascii" => s.ascii = v,
                        "welcome_seen" => s.welcome_seen = v,
                        _ => return Err("Unknown preference"),
                    }
                }
            }
        }
        if let Some(bookmarks) = doc.get("bookmarks") {
            let bookmarks = bookmarks.as_array_of_tables().ok_or("Invalid bookmarks")?;
            if bookmarks.len() > 16 {
                return Err("At most 16 remembered lobbies");
            }
            for table in bookmarks {
                if table.len() != 3 {
                    return Err("Unknown bookmark field");
                }
                let name = table
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or("Invalid bookmark name")?;
                let card = table
                    .get("card")
                    .and_then(|v| v.as_str())
                    .ok_or("Missing public lobby card")?;
                let autoconnect = table
                    .get("autoconnect")
                    .and_then(|v| v.as_bool())
                    .ok_or("Invalid autoconnect setting")?;
                s.add(name, card, autoconnect)?;
            }
        }
        Ok(s)
    }
    pub fn add(&mut self, name: &str, card: &str, autoconnect: bool) -> Result<(), &'static str> {
        if self.bookmarks.len() >= 16 {
            return Err("At most 16 remembered lobbies");
        }
        nulllobby_core::domain::LobbyName::new(name).map_err(|_| "Invalid bookmark name")?;
        let decoded = LobbyCard::parse(card).map_err(|_| "Invalid public card")?;
        if decoded.kind() == LobbyKind::Private {
            return Err("Private invitations stay in RAM; provide a fresh card on each restart");
        }
        if self.bookmarks.iter().any(|b| b.name == name) {
            return Err("Bookmark name already exists");
        }
        self.bookmarks.push(Bookmark {
            name: name.into(),
            card: card.into(),
            autoconnect,
        });
        Ok(())
    }
    pub fn enable(&mut self) -> Result<(), &'static str> {
        let previous = self.path.clone();
        if self.path.is_none() {
            self.path = Some(default_path().ok_or("Set --settings PATH to remember preferences")?);
        }
        if let Err(error) = self.save() {
            self.path = previous;
            return Err(error);
        }
        Ok(())
    }
    pub fn disable(&mut self) -> Result<(), &'static str> {
        if let Some(path) = &self.path {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("Could not remove the saved settings file"),
            }
        }
        self.path = None;
        Ok(())
    }
    pub fn save(&self) -> Result<(), &'static str> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut doc = DocumentMut::new();
        doc["version"] = value(1);
        for (key, v) in [
            ("timestamps", self.timestamps),
            ("icons", self.icons),
            ("lobbies", self.lobbies),
            ("members", self.members),
            ("ascii", self.ascii),
            ("welcome_seen", self.welcome_seen),
        ] {
            doc[key] = value(v);
        }
        doc["theme"] = value(&self.theme);
        if let Some(n) = &self.nickname {
            doc["nickname"] = value(n);
        }
        let mut bookmarks = ArrayOfTables::new();
        for b in &self.bookmarks {
            let mut table = Table::new();
            table["name"] = value(&b.name);
            table["card"] = value(&b.card);
            table["autoconnect"] = value(b.autoconnect);
            bookmarks.push(table);
        }
        doc["bookmarks"] = toml_edit::Item::ArrayOfTables(bookmarks);
        let text = doc.to_string();
        if text.len() > 32768 {
            return Err("Settings exceed 32 KiB");
        }
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let mut dirs = fs::DirBuilder::new();
        dirs.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            dirs.mode(0o700);
        }
        dirs.create(parent)
            .map_err(|_| "Cannot create settings directory")?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "Clock unavailable")?
            .as_nanos();
        let temporary = parent.join(format!(".nulllobby-{}-{nonce}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| "Cannot create private settings file")?;
        let result = (|| {
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            fs::rename(&temporary, path)
        })()
        .map_err(|_| "Cannot save settings");
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use nulllobby_transport::TransportKind;
    use secrecy::ExposeSecret;
    #[test]
    fn rejects_private_cards_and_unknown_state() {
        let card = LobbyCard::private(TransportKind::Direct, vec![]).unwrap();
        let mut s = Settings::default();
        assert!(
            s.add("private", card.export().expose_secret(), false)
                .is_err()
        );
        assert!(Settings::decode("version=1\nidentity=\"key\"", None).is_err());
        assert!(Settings::decode("version=2", None).is_err());
    }
    #[test]
    fn opt_in_settings_roundtrip_permissions_and_disable() {
        let directory =
            std::env::temp_dir().join(format!("nulllobby-preferences-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("settings.toml");
        let mut settings = Settings::load(Some(path.clone())).unwrap();
        settings.nickname = Some("guest{one}".into());
        let card = LobbyCard::public(TransportKind::Direct, vec![]).unwrap();
        settings
            .add("test", card.export().expose_secret(), true)
            .unwrap();
        settings.welcome_seen = true;
        settings.save().unwrap();
        let loaded = Settings::load(Some(path.clone())).unwrap();
        assert_eq!(loaded.nickname.as_deref(), Some("guest{one}"));
        assert!(loaded.welcome_seen && loaded.bookmarks[0].autoconnect);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        settings.disable().unwrap();
        assert!(!path.exists());
        fs::remove_dir(directory).unwrap();
    }
}
