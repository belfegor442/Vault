//! `vault-cli` — headless access to the Vault engine.
//!
//! The CLI is stateless: every command opens the container, authenticates,
//! performs a single operation and drops the session (keys are zeroized).
//!
//! Passwords are never accepted as command-line arguments (they would be
//! visible in the process table). They are read from the terminal via
//! `rpassword`, or — for automation/tests — from the `VAULT_PASSWORD`,
//! `VAULT_NEW_PASSWORD` and `VAULT_RECOVERY_KEY` environment variables
//! (documented as test-only; using them prints a warning).

use std::io::Read;
use std::path::{Path, PathBuf};

use vault_container::parse_id_hex;
use vault_core::{CreateOptions, EraseScope, ItemKind, ItemSummary, VaultEngine};
use vault_crypto::SecretBytes;

const USAGE: &str = r#"vault-cli — native Vault command line interface

USAGE:
    vault-cli <command> [options]

CORE COMMANDS:
    init [--recovery]              Create a new vault in the vault directory
    status                         Show vault status (no unlock required)
    security                       Show the security report
    verify [--deep]                Verify container integrity (deep = decrypt all)
    audit [--limit N]              Show recent audit events

CONTENT COMMANDS:
    add note --title T [--text C] [--folder ID]
                                   Add a note ('--text -' reads stdin)
    add password --name N [--username U] [--password P] [--url U]
                 [--notes X] [--category C] [--favorite]
                                   Add a password entry
    import <path> [--name N] [--folder ID]
                                   Encrypt a file into the vault
    list [--kind file|note|password] [--folder ID]
                                   List items
    note <ID>                      Show a note
    password <ID>                  Show a password record (reveals the secret)
    export <ID> --out <path>       Decrypt an item to a file
    search <query...>              Search unlocked metadata
    delete <ID>                    Delete an item (crypto-erases its key)
    favorite <ID>                  Toggle the favorite flag

FOLDERS:
    folder create <name> [--parent ID]
    folder list
    folder delete <ID>

KEY MANAGEMENT:
    password-change                Change the master password
    recovery enable                Issue a new recovery key (shown once)
    recovery disable               Destroy the recovery envelope
    recover                        Unlock with a recovery key + set new password
    erase --scope session|recovery|domain|vault [--yes]
                                   Crypto-erase (domain/vault scopes need --yes)

GLOBAL OPTIONS:
    --dir <path>                   Vault directory (or env VAULT_DIR;
                                   default: %LOCALAPPDATA%\Vault / ~/.vault)
    -h, --help                     Show this help

ENVIRONMENT (automation/tests only):
    VAULT_PASSWORD                 Master password (warning printed)
    VAULT_NEW_PASSWORD             New password for change/recover
    VAULT_RECOVERY_KEY             Recovery key display form for 'recover'
"#;

type Res<T> = Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ------------------------------------------------------------------ args

fn take_opt(args: &mut Vec<String>, name: &str) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            if i + 1 < args.len() {
                let v = args.remove(i + 1);
                args.remove(i);
                return Some(v);
            }
            args.remove(i);
            return Some(String::new());
        }
        if let Some(rest) = args[i].strip_prefix(name) {
            if let Some(v) = rest.strip_prefix('=') {
                let v = v.to_string();
                args.remove(i);
                return Some(v);
            }
        }
        i += 1;
    }
    None
}

fn take_flag(args: &mut Vec<String>, name: &str) -> bool {
    if let Some(pos) = args.iter().position(|a| a == name) {
        args.remove(pos);
        return true;
    }
    false
}

// ------------------------------------------------------------- passwords

fn master_password() -> Res<SecretBytes> {
    if let Ok(p) = std::env::var("VAULT_PASSWORD") {
        eprintln!("warning: master password read from VAULT_PASSWORD (test/automation only)");
        return Ok(SecretBytes::from_str(&p));
    }
    let p = rpassword::prompt_password("Master password: ").map_err(err)?;
    Ok(SecretBytes::from_str(&p))
}

fn new_password_pair() -> Res<SecretBytes> {
    if let Ok(p) = std::env::var("VAULT_NEW_PASSWORD") {
        eprintln!("warning: new password read from VAULT_NEW_PASSWORD (test/automation only)");
        return Ok(SecretBytes::from_str(&p));
    }
    let a = rpassword::prompt_password("New master password: ").map_err(err)?;
    let b = rpassword::prompt_password("Confirm new password: ").map_err(err)?;
    if a != b {
        return Err("passwords do not match".into());
    }
    Ok(SecretBytes::from_str(&a))
}

fn initial_password() -> Res<SecretBytes> {
    if let Ok(p) = std::env::var("VAULT_PASSWORD") {
        eprintln!("warning: master password read from VAULT_PASSWORD (test/automation only)");
        return Ok(SecretBytes::from_str(&p));
    }
    let a = rpassword::prompt_password("Choose a master password (min 8 chars): ").map_err(err)?;
    let b = rpassword::prompt_password("Confirm master password: ").map_err(err)?;
    if a != b {
        return Err("passwords do not match".into());
    }
    Ok(SecretBytes::from_str(&a))
}

// --------------------------------------------------------------- helpers

fn default_dir() -> PathBuf {
    if let Ok(d) = std::env::var("VAULT_DIR") {
        return PathBuf::from(d);
    }
    #[cfg(windows)]
    {
        if let Ok(base) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(base).join("Vault");
        }
    }
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
        return PathBuf::from(home).join(".vault");
    }
    PathBuf::from(".vault")
}

fn open_engine(dir: &Path) -> Res<VaultEngine> {
    VaultEngine::open(dir).map_err(err)
}

fn unlock_engine(dir: &Path) -> Res<VaultEngine> {
    let mut engine = open_engine(dir)?;
    let pw = master_password()?;
    engine.unlock(&pw).map_err(err)?;
    Ok(engine)
}

fn parse_kind(s: &str) -> Res<ItemKind> {
    match s {
        "file" | "files" => Ok(ItemKind::File),
        "note" | "notes" => Ok(ItemKind::Note),
        "password" | "passwords" | "pass" => Ok(ItemKind::Password),
        _ => Err(format!("unknown kind {s:?} (expected file|note|password)")),
    }
}

fn parse_id(s: &str) -> Res<[u8; 16]> {
    parse_id_hex(s).ok_or_else(|| format!("invalid id {s:?} (expected 32 hex chars)"))
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

fn kind_str(k: ItemKind) -> &'static str {
    match k {
        ItemKind::File => "file",
        ItemKind::Note => "note",
        ItemKind::Password => "password",
    }
}

fn print_items(items: &[ItemSummary]) {
    if items.is_empty() {
        println!("(no items)");
        return;
    }
    for it in items {
        let star = if it.favorite { "*" } else { " " };
        let folder = match it.folder {
            Some(f) => vault_crypto::to_hex16(&f),
            None => "-".to_string(),
        };
        println!(
            "{star} {:8}  {}  {:>10} B  folder={}  updated={}",
            kind_str(it.kind),
            vault_crypto::to_hex16(&it.id),
            it.size,
            &folder[..8.min(folder.len())],
            fmt_ms(it.updated_ms),
        );
        println!("          {}", it.name);
    }
    println!("{} item(s)", items.len());
}

fn read_stdin_or(value: &str) -> Res<String> {
    if value == "-" {
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf).map_err(err)?;
        Ok(buf)
    } else {
        Ok(value.to_string())
    }
}

fn print_recovery_key(display: &str) {
    println!();
    println!("=================== RECOVERY KEY (shown exactly once) ===================");
    println!("{display}");
    println!("========================================================================");
    println!("Store it offline. Vault does not persist it and cannot show it again.");
}

// ------------------------------------------------------------- commands

fn cmd_init(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let with_recovery = take_flag(args, "--recovery");
    if !args.is_empty() {
        return Err(format!("unexpected arguments: {}", args.join(" ")));
    }
    if dir.join("VAULTHDR").exists() {
        return Err("a vault already exists at this location (see: status)".into());
    }
    let pw = initial_password()?;
    if pw.len() < 8 {
        return Err("password must be at least 8 characters".into());
    }
    let (engine, recovery) =
        VaultEngine::create(dir, &pw, CreateOptions { kdf: None, with_recovery }).map_err(err)?;
    let st = engine.status();
    println!("vault created at {}", dir.display());
    println!("vault id: {}", st.vault_id);
    println!(
        "kdf: argon2id m={} KiB t={} p={}",
        st.kdf_memory_kib, st.kdf_iterations, st.kdf_parallelism
    );
    if let Some(display) = recovery {
        print_recovery_key(&display);
    } else {
        println!("tip: run 'vault-cli recovery enable' to issue a recovery key.");
    }
    Ok(())
}

fn cmd_status(dir: &Path) -> Res<()> {
    let engine = open_engine(dir)?;
    let st = engine.status();
    println!("location:       {}", dir.display());
    println!("vault id:       {}", st.vault_id);
    println!("initialized:    {}", st.initialized);
    println!("unlocked:       {}", st.unlocked);
    println!("format version: {}", st.format_version);
    println!("created:        {}", fmt_ms(st.created_ms));
    println!("generation:     {}", st.generation);
    println!("recovery:       {}", if st.has_recovery { "configured" } else { "not configured" });
    println!(
        "kdf:            argon2id m={} KiB t={} p={}",
        st.kdf_memory_kib, st.kdf_iterations, st.kdf_parallelism
    );
    println!("lockdown:       {}", st.lockdown_state);
    println!("failed attempts: {}", st.failed_attempts);
    if st.lockout_until_ms > 0 {
        println!("lockout until:  {}", fmt_ms(st.lockout_until_ms));
    }
    println!("platform:       {} (binary verified: {})", st.platform_capability, st.binary_verified);
    Ok(())
}

fn cmd_add(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let kind = if args.is_empty() { String::new() } else { args.remove(0) };
    match kind.as_str() {
        "note" | "notes" => {
            let title = take_opt(args, "--title")
                .ok_or("add note requires --title")?;
            let text = take_opt(args, "--text").unwrap_or_default();
            let folder = match take_opt(args, "--folder") {
                Some(f) => Some(parse_id(&f)?),
                None => None,
            };
            let content = read_stdin_or(&text)?;
            let mut engine = unlock_engine(dir)?;
            let id = engine.add_note(&title, &content, folder).map_err(err)?;
            println!("note added: {}", vault_crypto::to_hex16(&id));
            Ok(())
        }
        "password" | "pass" | "passwords" => {
            let name = take_opt(args, "--name").ok_or("add password requires --name")?;
            let username = take_opt(args, "--username").unwrap_or_default();
            let password = take_opt(args, "--password").unwrap_or_default();
            let url = take_opt(args, "--url").unwrap_or_default();
            let notes = take_opt(args, "--notes").unwrap_or_default();
            let category = take_opt(args, "--category").unwrap_or_else(|| "other".into());
            let favorite = take_flag(args, "--favorite");
            let mut engine = unlock_engine(dir)?;
            let id = engine
                .add_password(&name, &username, &password, &url, &notes, &category, favorite)
                .map_err(err)?;
            println!("password entry added: {}", vault_crypto::to_hex16(&id));
            Ok(())
        }
        "" => Err("usage: vault-cli add note|password ...".into()),
        other => Err(format!("unknown item kind {other:?}")),
    }
}

fn cmd_import(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let src = args.first().cloned().ok_or("usage: vault-cli import <path>")?;
    args.remove(0);
    let name = take_opt(args, "--name");
    let folder = match take_opt(args, "--folder") {
        Some(f) => Some(parse_id(&f)?),
        None => None,
    };
    let mut engine = unlock_engine(dir)?;
    let id = engine
        .import_file(Path::new(&src), folder, name.as_deref())
        .map_err(err)?;
    println!("imported: {}", vault_crypto::to_hex16(&id));
    Ok(())
}

fn cmd_list(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let kind = take_opt(args, "--kind");
    let folder = match take_opt(args, "--folder") {
        Some(f) => Some(parse_id(&f)?),
        None => None,
    };
    let engine = unlock_engine(dir)?;
    let items = match (kind, folder) {
        (None, None) => engine.list_all().map_err(err)?,
        (Some(k), None) => {
            let k = parse_kind(&k)?;
            let mut v: Vec<_> = engine.list_all().map_err(err)?;
            v.retain(|it| it.kind == k);
            v
        }
        (None, Some(f)) => engine.list(Some(f)).map_err(err)?,
        (Some(k), Some(f)) => engine.list_kind(parse_kind(&k)?, Some(f)).map_err(err)?,
    };
    print_items(&items);
    Ok(())
}

fn cmd_note(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let id = parse_id(args.first().ok_or("usage: vault-cli note <id>")?)?;
    let engine = unlock_engine(dir)?;
    let note = engine.get_note(&id).map_err(err)?;
    println!("title:   {}", note.title);
    println!("created: {}", fmt_ms(note.created_ms));
    println!("updated: {}", fmt_ms(note.updated_ms));
    if !note.tags.is_empty() {
        println!("tags:    {}", note.tags.join(", "));
    }
    println!("---");
    println!("{}", note.content);
    Ok(())
}

fn cmd_password(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let id = parse_id(args.first().ok_or("usage: vault-cli password <id>")?)?;
    let engine = unlock_engine(dir)?;
    let rec = engine.get_password(&id).map_err(err)?;
    println!("name:     {}", rec.name);
    println!("username: {}", rec.username);
    println!("password: {}", rec.password);
    println!("url:      {}", rec.url);
    println!("category: {}", rec.category);
    println!("favorite: {}", rec.favorite);
    if !rec.notes.is_empty() {
        println!("notes:    {}", rec.notes);
    }
    println!("updated:  {}", fmt_ms(rec.updated_ms));
    Ok(())
}

fn cmd_export(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let id = parse_id(args.first().ok_or("usage: vault-cli export <id> --out <path>")?)?;
    args.remove(0);
    let out = take_opt(args, "--out").ok_or("export requires --out <path>")?;
    let mut engine = unlock_engine(dir)?;
    engine.export_file(&id, Path::new(&out)).map_err(err)?;
    println!("exported to {}", out);
    Ok(())
}

fn cmd_search(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    if args.is_empty() {
        return Err("usage: vault-cli search <query>".into());
    }
    let query = args.join(" ");
    let engine = unlock_engine(dir)?;
    let items = engine.search(&query).map_err(err)?;
    print_items(&items);
    Ok(())
}

fn cmd_delete(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let id = parse_id(args.first().ok_or("usage: vault-cli delete <id>")?)?;
    let mut engine = unlock_engine(dir)?;
    engine.delete_object(&id).map_err(err)?;
    println!("deleted (object key destroyed)");
    Ok(())
}

fn cmd_favorite(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let id = parse_id(args.first().ok_or("usage: vault-cli favorite <id>")?)?;
    let mut engine = unlock_engine(dir)?;
    engine.toggle_favorite(&id).map_err(err)?;
    println!("favorite toggled");
    Ok(())
}

fn cmd_folder(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let sub = args.first().cloned().unwrap_or_default();
    if !args.is_empty() {
        args.remove(0);
    }
    match sub.as_str() {
        "create" => {
            let name = args.first().cloned().ok_or("usage: vault-cli folder create <name> [--parent id]")?;
            let parent = match take_opt(args, "--parent") {
                Some(p) => Some(parse_id(&p)?),
                None => None,
            };
            let mut engine = unlock_engine(dir)?;
            let id = engine.create_folder(&name, parent).map_err(err)?;
            println!("folder: {}", vault_crypto::to_hex16(&id));
            Ok(())
        }
        "list" => {
            let engine = unlock_engine(dir)?;
            let folders = engine.list_folders().map_err(err)?;
            if folders.is_empty() {
                println!("(no folders)");
            }
            for f in folders {
                let parent = f.parent.map(|p| vault_crypto::to_hex16(&p)).unwrap_or_else(|| "-".into());
                println!(
                    "{}  parent={}  items={}  {}",
                    vault_crypto::to_hex16(&f.id),
                    &parent[..8.min(parent.len())],
                    f.item_count,
                    f.name
                );
            }
            Ok(())
        }
        "delete" => {
            let id = parse_id(args.first().ok_or("usage: vault-cli folder delete <id>")?)?;
            let mut engine = unlock_engine(dir)?;
            engine.delete_folder(&id).map_err(err)?;
            println!("folder deleted (children promoted to root)");
            Ok(())
        }
        _ => Err("usage: vault-cli folder create|list|delete ...".into()),
    }
}

fn cmd_stats(dir: &Path) -> Res<()> {
    let engine = unlock_engine(dir)?;
    let s = engine.stats().map_err(err)?;
    println!("files:     {}", s.files);
    println!("notes:     {}", s.notes);
    println!("passwords: {}", s.passwords);
    println!("folders:   {}", s.folders);
    println!("favorites: {}", s.favorites);
    println!("total:     {} B", s.total_bytes);
    Ok(())
}

fn cmd_verify(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let deep = take_flag(args, "--deep");
    let mut engine = unlock_engine(dir)?;
    let report = engine.verify_integrity(deep).map_err(err)?;
    println!("mode:    {}", if deep { "deep (decrypt every object)" } else { "structural" });
    println!("objects: {}", report.checked_objects);
    println!("result:  {}", if report.ok { "OK" } else { "FAILED" });
    for f in &report.failed {
        println!("  FAIL {f}");
    }
    for w in &report.warnings {
        println!("  WARN {w}");
    }
    if !report.ok {
        return Err("integrity check failed".into());
    }
    Ok(())
}

fn cmd_audit(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let limit: usize = take_opt(args, "--limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let mut engine = unlock_engine(dir)?;
    let events = engine.audit_events(limit).map_err(err)?;
    if events.is_empty() {
        println!("(no audit events)");
    }
    for e in events {
        println!(
            "#{:<4} {}  {:<24} {:<10} {:<6} {}",
            e.seq,
            fmt_ms(e.timestamp_ms),
            e.event,
            e.component,
            e.result,
            e.detail
        );
    }
    Ok(())
}

fn cmd_security(dir: &Path) -> Res<()> {
    let mut engine = unlock_engine(dir)?;
    let r = engine.security_report();
    println!("lockdown:      {}", r.lockdown_state);
    println!("platform:      {}", r.platform_capability);
    println!("binary check:  {}", if r.binary_verified { "verified" } else { "MISMATCH" });
    println!("generation:    {} (witnessed {})", r.generation, r.witnessed_generation);
    println!("recovery:      {}", if r.has_recovery { "configured" } else { "not configured" });
    println!(
        "kdf:           argon2id m={} KiB t={}",
        r.kdf_memory_kib, r.kdf_iterations
    );
    println!("objects:       {}", r.object_count);
    println!("integrity:     {}", if r.integrity_ok { "OK" } else { "ATTENTION" });
    let events = engine.lockdown_events();
    if events.is_empty() {
        println!("lockdown events: none");
    } else {
        println!("lockdown events:");
        for e in events.iter().rev().take(10) {
            println!(
                "  {} [{:?}] {} — {}",
                fmt_ms(e.timestamp_ms),
                e.severity,
                e.rule,
                e.detail
            );
        }
    }
    Ok(())
}

fn cmd_password_change(dir: &Path) -> Res<()> {
    let mut engine = open_engine(dir)?;
    let current = master_password()?;
    engine.unlock(&current).map_err(err)?;
    let new = new_password_pair()?;
    engine.change_password(&current, &new).map_err(err)?;
    println!("master password changed");
    Ok(())
}

fn cmd_recovery(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let sub = args.first().cloned().unwrap_or_default();
    if !args.is_empty() {
        args.remove(0);
    }
    match sub.as_str() {
        "enable" => {
            let mut engine = unlock_engine(dir)?;
            let display = engine.enable_recovery().map_err(err)?;
            print_recovery_key(&display);
            Ok(())
        }
        "disable" => {
            let mut engine = unlock_engine(dir)?;
            engine.disable_recovery().map_err(err)?;
            println!("recovery envelope destroyed");
            Ok(())
        }
        _ => Err("usage: vault-cli recovery enable|disable".into()),
    }
}

fn cmd_recover(dir: &Path) -> Res<()> {
    let display = match std::env::var("VAULT_RECOVERY_KEY") {
        Ok(k) => {
            eprintln!("warning: recovery key read from VAULT_RECOVERY_KEY (test/automation only)");
            k
        }
        Err(_) => rpassword::prompt_password("Recovery key: ").map_err(err)?,
    };
    let new = new_password_pair()?;
    let mut engine = open_engine(dir)?;
    engine.unlock_with_recovery(display.trim(), &new).map_err(err)?;
    println!("vault recovered; the master password has been re-wrapped.");
    Ok(())
}

fn cmd_erase(dir: &Path, args: &mut Vec<String>) -> Res<()> {
    let scope = take_opt(args, "--scope").ok_or("usage: vault-cli erase --scope <scope> [--yes]")?;
    let yes = take_flag(args, "--yes");
    let scope = EraseScope::parse(&scope).ok_or("unknown scope (session|object|recovery|domain|vault)")?;
    if matches!(scope, EraseScope::Vault | EraseScope::Domain) && !yes {
        return Err("refusing irreversible crypto-erase without --yes".into());
    }
    let pw = master_password()?;
    let mut engine = open_engine(dir)?;
    engine.unlock(&pw).map_err(err)?;
    engine.crypto_erase(scope, Some(&pw)).map_err(err)?;
    match scope {
        EraseScope::Session => println!("session keys destroyed (process-local)"),
        EraseScope::Recovery => println!("recovery material destroyed"),
        EraseScope::Vault => println!("vault crypto-erased; key material destroyed"),
        EraseScope::Domain => println!("root key rotated; previous domain keys destroyed"),
        EraseScope::Object => unreachable!("object scope rejected by engine"),
    }
    Ok(())
}

// ----------------------------------------------------------------- main

fn run() -> Res<()> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let dir = match take_opt(&mut args, "--dir") {
        Some(d) => PathBuf::from(d),
        None => default_dir(),
    };
    let help = take_flag(&mut args, "--help") || take_flag(&mut args, "-h");
    let command = if args.is_empty() {
        String::new()
    } else {
        args.remove(0)
    };
    if help || command.is_empty() || command == "help" || command == "--help" {
        print!("{USAGE}");
        return Ok(());
    }

    match command.as_str() {
        "init" | "create" => cmd_init(&dir, &mut args),
        "status" => cmd_status(&dir),
        "add" => cmd_add(&dir, &mut args),
        "import" | "add-file" => cmd_import(&dir, &mut args),
        "list" | "ls" => cmd_list(&dir, &mut args),
        "note" => cmd_note(&dir, &mut args),
        "password" | "show" => cmd_password(&dir, &mut args),
        "export" => cmd_export(&dir, &mut args),
        "search" => cmd_search(&dir, &mut args),
        "delete" | "rm" => cmd_delete(&dir, &mut args),
        "favorite" | "fav" => cmd_favorite(&dir, &mut args),
        "folder" => cmd_folder(&dir, &mut args),
        "stats" => cmd_stats(&dir),
        "verify" => cmd_verify(&dir, &mut args),
        "audit" => cmd_audit(&dir, &mut args),
        "security" => cmd_security(&dir),
        "password-change" => cmd_password_change(&dir),
        "recovery" => cmd_recovery(&dir, &mut args),
        "recover" => cmd_recover(&dir),
        "erase" => cmd_erase(&dir, &mut args),
        "lock" => {
            println!("vault-cli is stateless; the session ends when the command exits.");
            Ok(())
        }
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    }
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
