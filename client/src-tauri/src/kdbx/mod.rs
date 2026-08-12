//! keepass-ng backend. Node access is callback-style (Rc<RefCell<dyn Node>>
//! tree), not plain iteration - see with_node/with_node_mut calls below.
//! Two APIs unconfirmed against real keepass-ng docs (NOTE at each site):
//! node removal (delete_item) and Value's non-Unprotected variants.

use crate::error::{VaultError, VaultResult};
use crate::model::{Folder, ItemKind, LoginData, LoginUri, UriMatchType, VaultItem};
use keepass_ng::{
    db::{rc_refcell_node, with_node, with_node_mut, Database, Entry, Group, NodeIterator, Value},
    DatabaseConfig, DatabaseKey,
};
use std::fs::File;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub fn open(path: &Path, password: &str, key_file: Option<&Path>) -> VaultResult<KdbxVault> {
    let mut file = File::open(path)
        .map_err(|e| VaultError::Kdbx(format!("cannot open {}: {e}", path.display())))?;

    let mut key = DatabaseKey::new().with_password(password);
    if let Some(kf_path) = key_file {
        let mut kf = File::open(kf_path)
            .map_err(|e| VaultError::Kdbx(format!("cannot open key file: {e}")))?;
        // NOTE: assumes builder-style with_keyfile (-> Self); if it's Result<Self,_>
        // instead, change to `.with_keyfile(&mut kf).map_err(...)?`.
        key = key.with_keyfile(&mut kf);
    }

    let db = Database::open(&mut file, key)
        .map_err(|e| VaultError::Kdbx(format!("failed to open database (wrong password?): {e}")))?;

    Ok(KdbxVault { path: path.to_path_buf(), password: password.to_string(), db })
}

pub fn create(path: &Path, password: &str) -> VaultResult<KdbxVault> {
    let mut db = Database::new(DatabaseConfig::default());
    db.meta.database_name = Some(
        path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Umewarden Client")
            .to_string(),
    );

    let vault = KdbxVault { path: path.to_path_buf(), password: password.to_string(), db };
    vault.save()?;
    Ok(vault)
}

pub struct KdbxVault {
    path:     PathBuf,
    password: String, // TODO: wrap in SensitiveString, not zeroized today
    db:       Database,
}

impl KdbxVault {
    pub fn list_items(&self) -> VaultResult<Vec<VaultItem>> {
        let mut items = Vec::new();

        for node in NodeIterator::new(&self.db.root).into_iter() {
            with_node::<Entry, _, _>(&node, |e| {
                items.push(entry_to_vault_item(e));
            });
        }

        Ok(items)
    }

    pub fn list_folders(&self) -> VaultResult<Vec<Folder>> {
        let mut folders = Vec::new();

        for node in NodeIterator::new(&self.db.root).into_iter() {
            with_node::<Group, _, _>(&node, |g| {
                // Group has its own uuid field but its name is unconfirmed - hash the
                // title as a stable stand-in until that's verified.
                folders.push(Folder {
                    id:   uuid_from_name(g.get_title().unwrap_or("")),
                    name: g.get_title().unwrap_or("(unnamed)").to_string(),
                });
            });
        }

        Ok(folders)
    }

    pub fn create_item(&mut self, item: &VaultItem) -> VaultResult<VaultItem> {
        let mut entry = Entry::default();
        apply_vault_item_to_entry(&mut entry, item);
        let new_uuid = entry.uuid;

        with_node_mut::<Group, _, _>(&self.db.root, |root| {
            root.add_child(rc_refcell_node(entry), 0);
        });

        self.save()?;

        let mut saved = item.clone();
        saved.id = new_uuid;
        Ok(saved)
    }

    pub fn update_item(&mut self, item: &VaultItem) -> VaultResult<()> {
        let mut found = false;

        for node in NodeIterator::new(&self.db.root).into_iter() {
            with_node_mut::<Entry, _, _>(&node, |e| {
                if e.uuid == item.id {
                    apply_vault_item_to_entry(e, item);
                    found = true;
                }
            });
            if found { break; }
        }

        if !found {
            return Err(VaultError::NotFound(item.id.to_string()));
        }

        self.save()
    }

    /// NOTE: node-removal method name unconfirmed (docs only show add_child);
    /// fails explicitly rather than silently no-oping until verified.
    pub fn delete_item(&mut self, _id: &Uuid) -> VaultResult<()> {
        Err(VaultError::Internal(
            "KDBX delete not implemented: keepass-ng's node-removal API needs to be confirmed \
             via `cargo doc -p keepass-ng --open` before wiring this up (see NOTE in kdbx/mod.rs)"
                .into(),
        ))
    }

    pub fn save(&self) -> VaultResult<()> {
        let mut file = File::create(&self.path)
            .map_err(|e| VaultError::Kdbx(format!("cannot create {}: {e}", self.path.display())))?;
        let key = DatabaseKey::new().with_password(&self.password);

        #[cfg(feature = "save_kdbx4")]
        {
            self.db
                .save(&mut file, key)
                .map_err(|e| VaultError::Kdbx(format!("failed to save database: {e}")))?;
        }
        #[cfg(not(feature = "save_kdbx4"))]
        {
            return Err(VaultError::Kdbx(
                "KDBX write support requires the 'save_kdbx4' feature (already enabled in Cargo.toml; \
                 this branch should not be reachable)".into(),
            ));
        }

        Ok(())
    }
}

fn entry_to_vault_item(e: &Entry) -> VaultItem {
    let username = e.get_username().map(|s| s.to_string());
    let password = e.get_password().map(|s| s.to_string().into());

    let url   = get_field_string(e, "URL");
    let notes = get_field_string(e, "Notes").map(Into::into);
    let totp  = get_field_string(e, "otp").map(Into::into); // KeeOTP/TrayTOTP convention

    let uris = if let Some(u) = url {
        vec![LoginUri { uri: u, r#match: UriMatchType::Domain }]
    } else {
        vec![]
    };

    let fields = e
        .fields
        .iter()
        .filter(|(k, _)| !matches!(k.as_str(), "Title" | "UserName" | "Password" | "URL" | "Notes" | "otp"))
        .map(|(k, v)| crate::model::CustomField {
            name: k.clone(),
            value: crate::model::FieldValue::Text(value_to_string(v)),
            linked_id: None,
        })
        .collect();

    VaultItem {
        id: e.uuid,
        name: e.get_title().unwrap_or("(untitled)").to_string(),
        kind: ItemKind::Login(LoginData { username, password, totp, uris }),
        favorite: false, // KDBX has no native favorite concept
        folder_id: None, // TODO: track parent group uuid
        created_at: 0,   // TODO: e.times has this, field name unconfirmed
        updated_at: 0,
        fields,
        notes,
    }
}

fn apply_vault_item_to_entry(e: &mut Entry, item: &VaultItem) {
    e.set_title(Some(item.name.as_str()));

    if let ItemKind::Login(login) = &item.kind {
        if let Some(u) = &login.username {
            e.set_username(Some(u.as_str()));
        }
        if let Some(p) = &login.password {
            e.set_password(Some(p.expose()));
        }
        if let Some(uri) = login.uris.first() {
            e.fields.insert("URL".to_string(), Value::Unprotected(uri.uri.clone()));
        }
    }

    if let Some(notes) = &item.notes {
        e.fields.insert("Notes".to_string(), Value::Unprotected(notes.expose().to_string()));
    }

    for f in &item.fields {
        let value_str = match &f.value {
            crate::model::FieldValue::Text(s) => s.clone(),
            crate::model::FieldValue::Hidden(s) => s.expose().to_string(),
            crate::model::FieldValue::Boolean(b) => b.to_string(),
        };
        e.fields.insert(f.name.clone(), Value::Unprotected(value_str));
    }
}

fn get_field_string(e: &Entry, key: &str) -> Option<String> {
    e.fields.get(key).map(value_to_string)
}

/// Only Unprotected(String) confirmed; Protected/Bytes variants unconfirmed.
fn value_to_string(v: &Value) -> String {
    match v {
        Value::Unprotected(s) => s.clone(),
        // Debug-formats everything else - avoids panicking, not correct output.
        #[allow(unreachable_patterns)]
        other => format!("{other:?}"),
    }
}

fn uuid_from_name(name: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes())
}
