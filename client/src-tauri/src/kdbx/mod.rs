/// KDBX 文件后端 adapter
///
/// 使用 `keepass-ng` crate 读写 KDBX 3.x / 4.x 文件。
/// 将 KeePass Entry 结构转换为 canonical VaultItem。
///
/// keepass-ng 的节点访问是回调式的（内部用 Rc<RefCell<dyn Node>> 表示树，
/// 不是简单的 &db.root 借用迭代）：
///
///   for node in NodeIterator::new(&db.root).into_iter() {
///       with_node::<Group, _, _>(&node, |group| { ... });   // 命中 Group 才会调用闭包
///       with_node::<Entry, _, _>(&node, |e| { ... });       // 命中 Entry 才会调用闭包
///   }
///
/// 已确认的 API（来自 keepass-ng 官方文档示例）：
///   - Database::open(&mut file, DatabaseKey::new().with_password(pw))
///   - Database::new(DatabaseConfig::default())
///   - db.save(&mut file, key)  （需要 "save_kdbx4" feature，Cargo.toml 已开启）
///   - Entry::default(), entry.set_title/set_username/set_password(Option<&str>)
///   - Entry.uuid: Uuid（公开字段，与上游 keepass crate 一致的结构布局）
///   - Entry.fields: HashMap<String, Value>（标准字段名 "Title"/"UserName"/
///     "Password"/"URL"/"Notes" 是固定的 KDBX schema 键名，与具体实现无关）
///   - Group::new(name), group.add_child(rc_refcell_node(node), index)
///
/// 未能通过文档/搜索 100% 确认、需要在真正编译前用 `cargo doc --open` 核实的部分
/// （已在对应函数里用 NOTE 标出）：
///   - 从树中"移除"一个节点的确切方法名（delete_item 用到）
///   - Value 枚举除 Unprotected(String) 外的其他 variant 名称

use crate::error::{VaultError, VaultResult};
use crate::model::{Folder, ItemKind, LoginData, LoginUri, UriMatchType, VaultItem};
use keepass_ng::{
    db::{rc_refcell_node, with_node, with_node_mut, Database, Entry, Group, NodeIterator, Value},
    DatabaseConfig, DatabaseKey,
};
use std::fs::File;
use std::path::{Path, PathBuf};
use uuid::Uuid;

// ─── 打开 / 创建 KDBX 文件 ────────────────────────────────────────────────────

/// 打开已有 KDBX 文件
pub fn open(path: &Path, password: &str, key_file: Option<&Path>) -> VaultResult<KdbxVault> {
    let mut file = File::open(path)
        .map_err(|e| VaultError::Kdbx(format!("cannot open {}: {e}", path.display())))?;

    let mut key = DatabaseKey::new().with_password(password);
    if let Some(kf_path) = key_file {
        let mut kf = File::open(kf_path)
            .map_err(|e| VaultError::Kdbx(format!("cannot open key file: {e}")))?;
        // NOTE: with_keyfile 假设是 builder 风格（返回 Self，与 with_password 一致），
        // 未在文档里 100% 确认签名；如果真实签名是 Result<Self,_>，编译时把下面这行
        // 改成 `.with_keyfile(&mut kf).map_err(|e| VaultError::Kdbx(...))?`。
        key = key.with_keyfile(&mut kf);
    }

    let db = Database::open(&mut file, key)
        .map_err(|e| VaultError::Kdbx(format!("failed to open database (wrong password?): {e}")))?;

    Ok(KdbxVault { path: path.to_path_buf(), password: password.to_string(), db })
}

/// 创建新 KDBX 文件（内存中构建，调用 save() 才落盘）
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

// ─── KdbxVault ────────────────────────────────────────────────────────────────

/// 持有打开的 KDBX 数据库句柄，提供 CRUD 操作
pub struct KdbxVault {
    path:     PathBuf,
    password: String,   // 保存时需要重新提供 key；不做 zeroize 处理会有残留风险，
                         // TODO: 换成 crate::model::SensitiveString 包装
    db:       Database,
}

impl KdbxVault {
    /// 将 KDBX 数据库中所有 entry 转换为 canonical VaultItem（跨所有分组，扁平化）
    pub fn list_items(&self) -> VaultResult<Vec<VaultItem>> {
        let mut items = Vec::new();

        for node in NodeIterator::new(&self.db.root).into_iter() {
            with_node::<Entry, _, _>(&node, |e| {
                items.push(entry_to_vault_item(e));
            });
        }

        Ok(items)
    }

    /// 获取所有 group 作为 Folder 列表（KDBX 的 Group 对应我们的 Folder 概念）
    pub fn list_folders(&self) -> VaultResult<Vec<Folder>> {
        let mut folders = Vec::new();

        for node in NodeIterator::new(&self.db.root).into_iter() {
            with_node::<Group, _, _>(&node, |g| {
                // 用标题的确定性哈希充当 Folder UUID —— KDBX 的 Group 本身也有 uuid 字段，
                // 但由于同样未在文档里 100% 确认字段名，这里先用一个稳定的替代方案，
                // 后续核实后应改为直接读取 group 的 uuid 字段。
                folders.push(Folder {
                    id:   uuid_from_name(g.get_title().unwrap_or("")),
                    name: g.get_title().unwrap_or("(unnamed)").to_string(),
                });
            });
        }

        Ok(folders)
    }

    /// 新建一个 entry，加到根分组下，返回生成的 VaultItem（含真实 uuid）
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

    /// 找到对应 entry（按 UUID），更新字段并保存
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

    /// 删除 entry
    ///
    /// NOTE：keepass-ng 文档里没有展示"从 Group 中移除子节点"的方法名
    /// （只展示了 add_child）。真正编译时请用 `cargo doc -p keepass-ng --open`
    /// 确认 Group 是否提供 `remove_child` / `remove` 之类的方法，并替换下面这行。
    /// 暂时的保守实现：报错拒绝，而不是静默什么都不做（宁可显式失败）。
    pub fn delete_item(&mut self, _id: &Uuid) -> VaultResult<()> {
        Err(VaultError::Internal(
            "KDBX delete not implemented: keepass-ng's node-removal API needs to be confirmed \
             via `cargo doc -p keepass-ng --open` before wiring this up (see NOTE in kdbx/mod.rs)"
                .into(),
        ))
    }

    /// 保存修改到磁盘
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

// ─── 转换：keepass_ng::Entry ↔ VaultItem ─────────────────────────────────────

fn entry_to_vault_item(e: &Entry) -> VaultItem {
    let username = e.get_username().map(|s| s.to_string());
    let password = e.get_password().map(|s| s.to_string().into());

    // URL / Notes / TOTP 走标准字段名（KDBX schema 固定键名，不依赖具体实现的便捷方法）
    let url   = get_field_string(e, "URL");
    let notes = get_field_string(e, "Notes").map(Into::into);
    let totp  = get_field_string(e, "otp").map(Into::into); // KeePass 里 TOTP 常存在 "otp" 字段（KeeOTP/TrayTOTP 约定）

    let uris = if let Some(u) = url {
        vec![LoginUri { uri: u, r#match: UriMatchType::Domain }]
    } else {
        vec![]
    };

    // 收集除标准字段外的自定义属性
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
        favorite: false, // KDBX 没有内建的 favorite 概念（部分客户端用 tag 模拟，这里先不处理）
        folder_id: None, // TODO: 记录 entry 所属的 parent group uuid（需要遍历时携带父节点信息）
        created_at: 0,   // TODO: e.times 里有创建/修改时间，字段名待确认后接入
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

/// Value 枚举目前只确认了 Unprotected(String) 这个 variant；
/// Protected(...) / Bytes(...) 的精确匹配需要在真正编译时用 cargo doc 核实后补上。
fn value_to_string(v: &Value) -> String {
    match v {
        Value::Unprotected(s) => s.clone(),
        // NOTE: 下面这个分支覆盖所有其他 variant（Protected/Bytes 等），
        // 用 Debug 格式化只是保证不 panic，不是正确的展示方式 —— 需要在
        // 确认真实 variant 名称后替换为对应的字符串提取逻辑。
        #[allow(unreachable_patterns)]
        other => format!("{other:?}"),
    }
}

/// 从字符串生成确定性 UUID（v5，基于名字空间 + 名称），用于 Group 没有直接暴露
/// uuid 字段时的临时替代方案（见 list_folders 里的 NOTE）
fn uuid_from_name(name: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes())
}
