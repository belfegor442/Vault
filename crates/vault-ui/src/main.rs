//! Vault native UI (Slint). Thin presentation layer over `vault_core::VaultEngine`.

slint::include_modules!();

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use slint::VecModel;

use vault_container::parse_id_hex;
use vault_core::{CoreError, CreateOptions, ItemKind, ItemSummary, LockReason, VaultEngine};
use vault_crypto::{to_hex16, SecretBytes};

type Id = [u8; 16];

#[derive(Clone, Copy, PartialEq)]
enum Detail {
    None,
    Edit(ItemKind, Id),
    New(ItemKind),
    Import,
}

struct Inner {
    engine: Option<VaultEngine>,
    dir: PathBuf,
    filter: i32, // 0 all,1 note,2 password,3 file,4 fav
    folder: Option<Id>,
    query: String,
    rows: Vec<ItemSummary>,
    detail: Detail,
}

impl Inner {
    fn new(dir: PathBuf) -> Self {
        Self {
            engine: None,
            dir,
            filter: 0,
            folder: None,
            query: String::new(),
            rows: Vec::new(),
            detail: Detail::None,
        }
    }
}

fn default_dir() -> PathBuf {
    if let Ok(d) = std::env::var("VAULT_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    if let Some(b) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(b).join("Vault");
    }
    if let Some(h) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(h).join(".vault");
    }
    PathBuf::from(".vault")
}

fn fmt_ms(ms: u64) -> String {
    // Civil-from-days (Howard Hinnant's algorithm), UTC.
    let secs = ms / 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mth <= 2 { y + 1 } else { y };
    format!("{y:04}-{mth:02}-{d:02} {h:02}:{m:02}:{s:02}Z")
}

fn fmt_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GiB", n as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn kind_str(k: ItemKind) -> &'static str {
    match k {
        ItemKind::File => "file",
        ItemKind::Note => "note",
        ItemKind::Password => "password",
    }
}

fn err_str(e: CoreError) -> String {
    e.to_string()
}

// ----------------------------------------------------------------- helpers

fn clear_detail(ui: &MainWindow) {
    ui.set_detail_mode(0);
    ui.set_detail_id("".into());
    ui.set_detail_title("".into());
    ui.set_detail_content("".into());
    ui.set_detail_username("".into());
    ui.set_detail_secret("".into());
    ui.set_detail_url("".into());
    ui.set_detail_category("".into());
    ui.set_detail_notes("".into());
    ui.set_detail_favorite(false);
    ui.set_detail_size("".into());
    ui.set_export_path("".into());
    ui.set_import_path("".into());
    ui.set_selected_index(-1);
}

fn refresh(ui: &MainWindow, st: &Rc<RefCell<Inner>>) {
    let mut s = st.borrow_mut();
    if s.engine.is_none() {
        ui.set_items(Rc::new(VecModel::from(Vec::<ItemRow>::new())).into());
        ui.set_folders(Rc::new(VecModel::from(Vec::<FolderRow>::new())).into());
        return;
    }

    let folder = s.folder;
    let filter = s.filter;
    let query = s.query.trim().to_string();

    let mut rows = match s.engine.as_mut().unwrap().list_all() {
        Ok(r) => r,
        Err(e) => {
            ui.set_notice(format!("list failed: {e}").into());
            return;
        }
    };

    // folder filter
    if let Some(f) = folder {
        rows.retain(|r| r.folder == Some(f));
    }
    // kind / favorites filter
    match filter {
        1 => rows.retain(|r| r.kind == ItemKind::Note),
        2 => rows.retain(|r| r.kind == ItemKind::Password),
        3 => rows.retain(|r| r.kind == ItemKind::File),
        4 => rows.retain(|r| r.favorite),
        _ => {}
    }
    // search (metadata, engine-side)
    if !query.is_empty() {
        match s.engine.as_ref().unwrap().search(&query) {
            Ok(found) => {
                let ids: Vec<Id> = found.iter().map(|f| f.id).collect();
                rows.retain(|r| ids.contains(&r.id));
            }
            Err(e) => {
                ui.set_notice(format!("search failed: {e}").into());
            }
        }
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.updated_ms));

    let items: Vec<ItemRow> = rows
        .iter()
        .map(|it| ItemRow {
            id: to_hex16(&it.id).into(),
            title: if it.name.is_empty() { "(untitled)".into() } else { it.name.clone().into() },
            subtitle: {
                let mut sub = format!("{} · {}", kind_str(it.kind), fmt_ms(it.updated_ms));
                if let Some(u) = &it.username {
                    if !u.is_empty() {
                        sub.push_str(&format!(" · {u}"));
                    }
                }
                if it.kind == ItemKind::File {
                    sub.push_str(&format!(" · {}", fmt_bytes(it.size)));
                }
                sub.into()
            },
            kind: kind_str(it.kind).into(),
            favorite: it.favorite,
        })
        .collect();

    let folders: Vec<FolderRow> = match s.engine.as_ref().unwrap().list_folders() {
        Ok(fs) => fs
            .iter()
            .map(|f| FolderRow {
                id: to_hex16(&f.id).into(),
                name: f.name.clone().into(),
                count: f.item_count.to_string().into(),
            })
            .collect(),
        Err(_) => Vec::new(),
    };

    s.rows = rows;
    drop(s);
    ui.set_items(Rc::new(VecModel::from(items)).into());
    ui.set_folders(Rc::new(VecModel::from(folders)).into());
    ui.set_selected_index(-1);
}

fn load_detail(ui: &MainWindow, st: &Rc<RefCell<Inner>>, id: Id, kind: ItemKind, index: i32) {
    let s = st.borrow();
    let engine = match s.engine.as_ref() {
        Some(e) => e,
        None => return,
    };
    match kind {
        ItemKind::Note => match engine.get_note(&id) {
            Ok(n) => {
                ui.set_detail_mode(1);
                ui.set_detail_id(to_hex16(&id).into());
                ui.set_detail_title(n.title.into());
                ui.set_detail_content(n.content.into());
                ui.set_detail_favorite(n.favorite);
                ui.set_detail_size("".into());
            }
            Err(e) => ui.set_notice(format!("open failed: {e}").into()),
        },
        ItemKind::Password => match engine.get_password(&id) {
            Ok(p) => {
                ui.set_detail_mode(2);
                ui.set_detail_id(to_hex16(&id).into());
                ui.set_detail_title(p.name.into());
                ui.set_detail_username(p.username.into());
                ui.set_detail_secret(p.password.into());
                ui.set_detail_url(p.url.into());
                ui.set_detail_category(p.category.into());
                ui.set_detail_notes(p.notes.into());
                ui.set_detail_favorite(p.favorite);
                ui.set_detail_size("".into());
            }
            Err(e) => ui.set_notice(format!("open failed: {e}").into()),
        },
        ItemKind::File => {
            let size = s.rows.iter().find(|r| r.id == id).map(|r| r.size).unwrap_or(0);
            ui.set_detail_mode(3);
            ui.set_detail_id(to_hex16(&id).into());
            ui.set_detail_title(s.rows.iter().find(|r| r.id == id).map(|r| r.name.clone()).unwrap_or_default().into());
            ui.set_detail_size(fmt_bytes(size).into());
            ui.set_detail_favorite(false);
        }
    }
    ui.set_selected_index(index);
    drop(s);
    // st.detail must be set after drop (we only needed reads)
    let mut s = st.borrow_mut();
    s.detail = Detail::Edit(kind, id);
}

fn build_status(ui: &MainWindow, st: &Rc<RefCell<Inner>>) {
    let mut s = st.borrow_mut();
    let engine = match s.engine.as_mut() {
        Some(e) => e,
        None => return,
    };
    let r = engine.security_report();
    let par = engine.header().kdf.parallelism;
    let mut out = String::new();
    out.push_str(&format!("Lockdown state: {}\n", r.lockdown_state));
    out.push_str(&format!(
        "Generation: {} (witnessed {})\n",
        r.generation, r.witnessed_generation
    ));
    out.push_str(&format!(
        "Platform capability: {}   Binary verified: {}\n",
        r.platform_capability,
        if r.binary_verified { "yes" } else { "NO" }
    ));
    out.push_str(&format!(
        "KDF: Argon2id {} KiB, t={}, p={}\n",
        r.kdf_memory_kib, r.kdf_iterations, par
    ));
    out.push_str(&format!(
        "Recovery key: {}   Objects: {}   Integrity: {}\n",
        if r.has_recovery { "configured" } else { "none" },
        r.object_count,
        if r.integrity_ok { "ok" } else { "SUSPECT" }
    ));
    out.push_str(&format!("Findings acknowledged: {}\n", "see lockdown state"));
    out.push_str("\nRecent audit events (newest first):\n");
    for e in r.recent_events.iter().rev().take(20) {
        out.push_str(&format!(
            "  {}  {}/{}  {}  {}\n",
            fmt_ms(e.timestamp_ms),
            e.event,
            e.component,
            e.result,
            e.detail
        ));
    }
    ui.set_status_text(out.into());
}

// --------------------------------------------------------------------- main

fn main() -> Result<(), slint::PlatformError> {
    let dir = default_dir();
    let ui = MainWindow::new()?;
    ui.set_dir_text(dir.display().to_string().into());
    ui.set_screen(0);
    ui.set_auth_mode(0);
    ui.set_error_text("".into());
    ui.set_notice("".into());
    clear_detail(&ui);

    let st = Rc::new(RefCell::new(Inner::new(dir)));

    // ---------------------------------------------------------- auth
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_unlock_requested(move |pw| {
            let ui = ui_weak.unwrap();
            let mut s = st.borrow_mut();
            let dir = PathBuf::from(ui.get_dir_text().to_string());
            s.dir = dir.clone();
            let result = VaultEngine::open(&dir).and_then(|mut e| {
                e.unlock(&SecretBytes::from_str(pw.as_ref()))?;
                Ok(e)
            });
            match result {
                Ok(engine) => {
                    s.engine = Some(engine);
                    s.filter = 0;
                    s.folder = None;
                    s.query = String::new();
                    drop(s);
                    ui.set_error_text("".into());
                    ui.set_notice("".into());
                    ui.set_filter(0);
                    ui.set_folder_filter("".into());
                    ui.set_search_text("".into());
                    clear_detail(&ui);
                    ui.set_screen(1);
                    refresh(&ui, &st);
                }
                Err(e) => ui.set_error_text(err_str(e).into()),
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_create_requested(move |pw, confirm, with_recovery| {
            let ui = ui_weak.unwrap();
            let pw = pw.to_string();
            let confirm = confirm.to_string();
            if pw.len() < 8 {
                ui.set_error_text("password must be at least 8 characters".into());
                return;
            }
            if pw != confirm {
                ui.set_error_text("passwords do not match".into());
                return;
            }
            let mut s = st.borrow_mut();
            let dir = PathBuf::from(ui.get_dir_text().to_string());
            s.dir = dir.clone();
            let opts = CreateOptions { kdf: None, with_recovery };
            match VaultEngine::create(&dir, &SecretBytes::from_str(&pw), opts) {
                Ok((engine, recovery)) => {
                    s.engine = Some(engine);
                    drop(s);
                    ui.set_error_text("".into());
                    ui.set_notice(match recovery {
                        Some(r) => format!("Vault created. Recovery key (write it down, shown once): {r}"),
                        None => "Vault created.".into(),
                    }.into());
                    clear_detail(&ui);
                    ui.set_screen(1);
                    refresh(&ui, &st);
                }
                Err(e) => ui.set_error_text(err_str(e).into()),
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_recover_requested(move |key, new_pw| {
            let ui = ui_weak.unwrap();
            let key = key.to_string();
            let new_pw = new_pw.to_string();
            if new_pw.len() < 8 {
                ui.set_error_text("new password must be at least 8 characters".into());
                return;
            }
            let mut s = st.borrow_mut();
            let dir = PathBuf::from(ui.get_dir_text().to_string());
            s.dir = dir.clone();
            let result = VaultEngine::open(&dir).and_then(|mut e| {
                e.unlock_with_recovery(key.trim(), &SecretBytes::from_str(&new_pw))?;
                Ok(e)
            });
            match result {
                Ok(engine) => {
                    s.engine = Some(engine);
                    s.filter = 0;
                    s.folder = None;
                    s.query = String::new();
                    drop(s);
                    ui.set_error_text("".into());
                    ui.set_notice("Vault recovered; master password has been reset.".into());
                    ui.set_filter(0);
                    ui.set_folder_filter("".into());
                    ui.set_search_text("".into());
                    clear_detail(&ui);
                    ui.set_screen(1);
                    refresh(&ui, &st);
                }
                Err(e) => ui.set_error_text(err_str(e).into()),
            }
        });
    }

    // ----------------------------------------------------------- main
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_lock_requested(move || {
            let ui = ui_weak.unwrap();
            let mut s = st.borrow_mut();
            if let Some(e) = s.engine.as_mut() {
                e.lock(LockReason::Manual);
            }
            s.engine = None;
            s.filter = 0;
            s.folder = None;
            s.query = String::new();
            s.rows.clear();
            s.detail = Detail::None;
            drop(s);
            ui.set_pass("".into());
            ui.set_pass_confirm("".into());
            ui.set_rec_key("".into());
            ui.set_rec_pass("".into());
            ui.set_error_text("".into());
            ui.set_notice("".into());
            ui.set_filter(0);
            ui.set_folder_filter("".into());
            ui.set_search_text("".into());
            ui.set_items(Rc::new(VecModel::from(Vec::<ItemRow>::new())).into());
            ui.set_folders(Rc::new(VecModel::from(Vec::<FolderRow>::new())).into());
            clear_detail(&ui);
            ui.set_screen(0);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_open_status_requested(move || {
            let ui = ui_weak.unwrap();
            build_status(&ui, &st);
            ui.set_notice("".into());
            ui.set_screen(2);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_back_requested(move || {
            let ui = ui_weak.unwrap();
            ui.set_screen(1);
            refresh(&ui, &st);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_refresh_requested(move || {
            let ui = ui_weak.unwrap();
            refresh(&ui, &st);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_filter_changed(move |f| {
            let ui = ui_weak.unwrap();
            {
                let mut s = st.borrow_mut();
                s.filter = f;
                s.folder = None;
            }
            ui.set_filter(f);
            ui.set_folder_filter("".into());
            refresh(&ui, &st);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_folder_changed(move |id_hex| {
            let ui = ui_weak.unwrap();
            let id_hex = id_hex.to_string();
            {
                let mut s = st.borrow_mut();
                s.folder = parse_id_hex(&id_hex);
                s.filter = 0;
            }
            ui.set_filter(0);
            ui.set_folder_filter(id_hex.as_str().into());
            refresh(&ui, &st);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_search_requested(move |q| {
            let ui = ui_weak.unwrap();
            st.borrow_mut().query = q.to_string();
            refresh(&ui, &st);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_select_item(move |i| {
            let ui = ui_weak.unwrap();
            let (id, kind) = {
                let s = st.borrow();
                match s.rows.get(i as usize) {
                    Some(r) => (r.id, r.kind),
                    None => return,
                }
            };
            load_detail(&ui, &st, id, kind, i);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_new_item(move |n| {
            let ui = ui_weak.unwrap();
            clear_detail(&ui);
            match n {
                1 => {
                    st.borrow_mut().detail = Detail::New(ItemKind::Note);
                    ui.set_detail_mode(4);
                }
                2 => {
                    st.borrow_mut().detail = Detail::New(ItemKind::Password);
                    ui.set_detail_mode(5);
                }
                _ => {
                    st.borrow_mut().detail = Detail::Import;
                    ui.set_detail_mode(6);
                }
            }
        });
    }

    // ------------------------------------------------------ CRUD actions
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_save_requested(move || {
            let ui = ui_weak.unwrap();
            let title = ui.get_detail_title().to_string();
            let content = ui.get_detail_content().to_string();
            let username = ui.get_detail_username().to_string();
            let secret = ui.get_detail_secret().to_string();
            let url = ui.get_detail_url().to_string();
            let category = ui.get_detail_category().to_string();
            let notes = ui.get_detail_notes().to_string();
            let favorite = ui.get_detail_favorite();
            let detail_hex = ui.get_detail_id().to_string();

            let mut s = st.borrow_mut();
            let detail = s.detail;
            let folder = s.folder;
            let engine = match s.engine.as_mut() {
                Some(e) => e,
                None => return,
            };
            let outcome: Result<Option<Id>, CoreError> = match detail {
                Detail::New(ItemKind::Note) => engine.add_note(&title, &content, folder).map(Some),
                Detail::New(ItemKind::Password) => engine
                    .add_password(&title, &username, &secret, &url, &notes, &category, favorite)
                    .map(Some),
                Detail::Edit(ItemKind::Note, id) => engine
                    .update_note(&id, &title, &content)
                    .map(|_| None),
                Detail::Edit(ItemKind::Password, id) => engine
                    .update_password(&id, &title, &username, &secret, &url, &notes, &category, favorite)
                    .map(|_| None),
                _ => Ok(None),
            };
            match outcome {
                Ok(Some(new_id)) => {
                    s.detail = Detail::None;
                    drop(s);
                    ui.set_notice(format!("Saved: {}", to_hex16(&new_id)).into());
                    clear_detail(&ui);
                    refresh(&ui, &st);
                }
                Ok(None) => {
                    let kind = match detail {
                        Detail::Edit(k, _) => k,
                        _ => ItemKind::Note,
                    };
                    drop(s);
                    ui.set_notice("Saved.".into());
                    refresh(&ui, &st);
                    // re-open the detail view for the edited id
                    if let Some(id) = parse_id_hex(&detail_hex) {
                        let idx = st
                            .borrow()
                            .rows
                            .iter()
                            .position(|r| r.id == id)
                            .map(|p| p as i32)
                            .unwrap_or(-1);
                        if idx >= 0 {
                            load_detail(&ui, &st, id, kind, idx);
                        } else {
                            clear_detail(&ui);
                        }
                    }
                }
                Err(e) => {
                    drop(s);
                    ui.set_notice(format!("Save failed: {e}").into());
                }
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_delete_requested(move || {
            let ui = ui_weak.unwrap();
            let mut s = st.borrow_mut();
            let id = match s.detail {
                Detail::Edit(_, id) => id,
                _ => return,
            };
            let engine = match s.engine.as_mut() {
                Some(e) => e,
                None => return,
            };
            match engine.delete_object(&id) {
                Ok(()) => {
                    s.detail = Detail::None;
                    drop(s);
                    ui.set_notice("Deleted.".into());
                    clear_detail(&ui);
                    refresh(&ui, &st);
                }
                Err(e) => {
                    drop(s);
                    ui.set_notice(format!("Delete failed: {e}").into());
                }
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_favorite_requested(move || {
            let ui = ui_weak.unwrap();
            let mut s = st.borrow_mut();
            let detail = s.detail;
            let id = match detail {
                Detail::Edit(_, id) => id,
                _ => return,
            };
            let engine = match s.engine.as_mut() {
                Some(e) => e,
                None => return,
            };
            match engine.toggle_favorite(&id) {
                Ok(()) => {
                    let kind = match detail {
                        Detail::Edit(k, _) => k,
                        _ => unreachable!(),
                    };
                    drop(s);
                    refresh(&ui, &st);
                    let idx = st
                        .borrow()
                        .rows
                        .iter()
                        .position(|r| r.id == id)
                        .map(|p| p as i32)
                        .unwrap_or(-1);
                    if idx >= 0 {
                        load_detail(&ui, &st, id, kind, idx);
                    }
                }
                Err(e) => {
                    drop(s);
                    ui.set_notice(format!("Favorite failed: {e}").into());
                }
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_export_requested(move |path| {
            let ui = ui_weak.unwrap();
            let path = path.to_string();
            let mut s = st.borrow_mut();
            let id = match s.detail {
                Detail::Edit(ItemKind::File, id) => id,
                _ => {
                    ui.set_notice("Select a file to export.".into());
                    return;
                }
            };
            let engine = match s.engine.as_mut() {
                Some(e) => e,
                None => return,
            };
            match engine.export_file(&id, PathBuf::from(&path).as_path()) {
                Ok(()) => ui.set_notice(format!("Exported to {path}").into()),
                Err(e) => ui.set_notice(format!("Export failed: {e}").into()),
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_import_requested(move |path| {
            let ui = ui_weak.unwrap();
            let path = path.to_string();
            let mut s = st.borrow_mut();
            let folder = s.folder;
            let engine = match s.engine.as_mut() {
                Some(e) => e,
                None => return,
            };
            match engine.import_file(PathBuf::from(&path).as_path(), folder, None) {
                Ok(id) => {
                    s.detail = Detail::None;
                    drop(s);
                    ui.set_notice(format!("Imported: {}", to_hex16(&id)).into());
                    clear_detail(&ui);
                    refresh(&ui, &st);
                }
                Err(e) => {
                    drop(s);
                    ui.set_notice(format!("Import failed: {e}").into());
                }
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_new_folder_requested(move |name| {
            let ui = ui_weak.unwrap();
            let name = name.trim().to_string();
            if name.is_empty() {
                return;
            }
            let mut s = st.borrow_mut();
            let engine = match s.engine.as_mut() {
                Some(e) => e,
                None => return,
            };
            match engine.create_folder(&name, None) {
                Ok(_) => {
                    drop(s);
                    ui.set_new_folder_name("".into());
                    ui.set_notice(format!("Folder created: {name}").into());
                    refresh(&ui, &st);
                }
                Err(e) => {
                    drop(s);
                    ui.set_notice(format!("Folder failed: {e}").into());
                }
            }
        });
    }

    // ------------------------------------------------------ status actions
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_verify_requested(move || {
            let ui = ui_weak.unwrap();
            let mut s = st.borrow_mut();
            let engine = match s.engine.as_mut() {
                Some(e) => e,
                None => return,
            };
            match engine.verify_integrity(true) {
                Ok(rep) => {
                    let msg = if rep.ok {
                        format!("Integrity OK — {} objects verified.", rep.checked_objects)
                    } else {
                        format!(
                            "Integrity FAILED — {}/{} failed: {}",
                            rep.failed.len(),
                            rep.checked_objects,
                            rep.failed.join(", ")
                        )
                    };
                    ui.set_notice(msg.into());
                }
                Err(e) => ui.set_notice(format!("Verify failed: {e}").into()),
            }
            drop(s);
            build_status(&ui, &st);
        });
    }
    {
        let ui_weak = ui.as_weak();
        let st = st.clone();
        ui.on_ack_requested(move || {
            let ui = ui_weak.unwrap();
            let mut s = st.borrow_mut();
            if let Some(engine) = s.engine.as_mut() {
                match engine.acknowledge_findings() {
                    Ok(()) => ui.set_notice("Findings acknowledged.".into()),
                    Err(e) => ui.set_notice(format!("Acknowledge failed: {e}").into()),
                }
            }
            drop(s);
            build_status(&ui, &st);
        });
    }

    ui.run()
}
