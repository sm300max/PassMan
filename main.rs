use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use cursive::{
    view::Nameable,
    views::{
        Button, Dialog, EditView, LinearLayout, ListView, Panel, SelectView, TextView,
    },
    Cursive, CursiveExt,
};
use rand::{rngs::ThreadRng, Rng};
use rusqlite::{params, Connection, Result as SqlResult};
use std::time::{Duration, Instant};
use clipboard::ClipboardProvider;
use lazy_static::lazy_static;

const DB_PATH: &str = "passwords.db";
const INACTIVITY_LOCK: Duration = Duration::from_secs(300);

lazy_static! {
    static ref ARGON_PARAMS: Params = Params::new(4096, 3, 2, None).unwrap();
}

struct PasswordManager {
    conn: Connection,
    master_key: Option<[u8; 32]>,
    last_activity: Instant,
    salt: [u8; 16],
}

impl PasswordManager {
    fn new() -> SqlResult<Self> {
        let conn = Connection::open(DB_PATH)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                username BLOB NOT NULL,
                password BLOB NOT NULL,
                url BLOB,
                notes BLOB,
                category TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        Ok(Self {
            conn,
            master_key: None,
            last_activity: Instant::now(),
            salt: rand::random(),
        })
    }

    fn derive_key(&self, password: &str) -> Result<[u8; 32], String> {
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            ARGON_PARAMS.clone(),
        );
        
        let mut output_key = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &self.salt, &mut output_key)
            .map_err(|e| e.to_string())?;
            
        Ok(output_key)
    }

    fn check_activity(&mut self) {
        if self.last_activity.elapsed() > INACTIVITY_LOCK {
            self.lock();
        }
    }

    fn lock(&mut self) {
        self.master_key = None;
    }

    fn encrypt(&self, data: &str) -> Result<Vec<u8>, String> {
        let master_key = self.master_key.ok_or("Not authenticated")?;
        let key = Key::<Aes256Gcm>::from_slice(&master_key);
        let cipher = Aes256Gcm::new(key);
        let mut rng = ThreadRng::default();
        let nonce_value: [u8; 12] = rng.random();
        let nonce = Nonce::from_slice(&nonce_value);

        cipher
            .encrypt(nonce, data.as_bytes())
            .map(|mut ciphertext| {
                ciphertext.extend_from_slice(&nonce_value);
                ciphertext
            })
            .map_err(|e| e.to_string())
    }

    #[allow(dead_code)]
    fn decrypt(&self, data: &[u8]) -> Result<String, String> {
        let master_key = self.master_key.ok_or("Not authenticated")?;
        let key = Key::<Aes256Gcm>::from_slice(&master_key);
        let cipher = Aes256Gcm::new(key);
        let (ciphertext, nonce) = data.split_at(data.len() - 12);
        let nonce = Nonce::from_slice(nonce);

        cipher
            .decrypt(nonce, ciphertext)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .map_err(|e| e.to_string())
    }

    fn add_entry(&self, title: &str, username: &str, password: &str, url: &str, notes: &str) -> SqlResult<()> {
        let enc_username = self.encrypt(username).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let enc_password = self.encrypt(password).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let enc_url = self.encrypt(url).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let enc_notes = self.encrypt(notes).map_err(|_| rusqlite::Error::InvalidQuery)?;

        self.conn.execute(
            "INSERT INTO entries 
            (title, username, password, url, notes) 
            VALUES (?1, ?2, ?3, ?4, ?5)",
            params![title, enc_username, enc_password, enc_url, enc_notes],
        )?;
        Ok(())
    }

    fn get_entries(&self) -> SqlResult<Vec<(i32, String)>> {
        let mut stmt = self.conn.prepare("SELECT id, title FROM entries")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        
        rows.collect::<SqlResult<Vec<_>>>()
    }

    fn generate_password(length: usize) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                             abcdefghijklmnopqrstuvwxyz\
                             0123456789\
                             !@#$%^&*()";

        let mut rng = ThreadRng::default();
        (0..length)
            .map(|_| {
                let idx = rng.random_range(0..CHARS.len());
                CHARS[idx] as char
            })
            .collect()
    }
}

fn main() {
    let mut siv = Cursive::default();
    
    siv.add_global_callback('q', |s| s.quit());
    
    siv.add_layer(
        Dialog::new()
            .title("Password Manager")
            .content(
                ListView::new()
                    .child("Master Password", EditView::new().secret().with_name("password"))
            )
            .button("Unlock", |s| {
                let pass = s.call_on_name("password", |v: &mut EditView| v.get_content()).unwrap();
                match PasswordManager::new() {
                    Ok(mut pm) => {
                        match pm.derive_key(&pass) {
                            Ok(key) => {
                                pm.master_key = Some(key);
                                pm.last_activity = Instant::now();
                                s.set_user_data(pm);
                                show_main_ui(s);
                            }
                            Err(e) => s.add_layer(Dialog::info(format!("Key error: {}", e))),
                        }
                    }
                    Err(e) => s.add_layer(Dialog::info(format!("DB error: {}", e))),
                }
            })
            .button("Quit", |s| s.quit())
    );
    
    siv.run();
}

fn show_main_ui(s: &mut Cursive) {
    s.pop_layer();
    
    let pm = s.user_data::<PasswordManager>().unwrap();
    pm.check_activity();
    if pm.master_key.is_none() {
        s.add_layer(Dialog::info("Session expired! Please login again."));
        return;
    }
    
    let entries = match pm.get_entries() {
        Ok(e) => e,
        Err(e) => {
            s.add_layer(Dialog::info(format!("Error: {}", e)));
            return;
        }
    };
    
    let mut select = SelectView::new();
    for (id, title) in entries {
        select.add_item(title, id);
    }
    
    s.add_layer(
        Dialog::around(
            LinearLayout::vertical()
                .child(Panel::new(select).title("Entries"))
                .child(
                    LinearLayout::horizontal()
                        .child(Button::new("Add", |s| {
                            s.with_user_data(|pm: &mut PasswordManager| {
                                pm.last_activity = Instant::now();
                            });
                            show_add_dialog(s);
                        }))
                        .child(Button::new("Delete", |s| {
                            s.with_user_data(|pm: &mut PasswordManager| {
                                pm.last_activity = Instant::now();
                            });
                            s.add_layer(Dialog::info("Delete not implemented"));
                        }))
                )
        )
        .title("Password Manager")
        .button("Generate", |s| {
            s.with_user_data(|pm: &mut PasswordManager| {
                pm.last_activity = Instant::now();
            });
            show_generator(s);
        })
        .button("Lock", |s| {
            s.user_data::<PasswordManager>().unwrap().lock();
            s.pop_layer();
        })
        .button("Quit", |s| s.quit())
    );
}

fn show_add_dialog(s: &mut Cursive) {
    s.add_layer(
        Dialog::new()
            .title("Add Entry")
            .content(
                ListView::new()
                    .child("Title", EditView::new().with_name("title"))
                    .child("Username", EditView::new().with_name("username"))
                    .child("Password", EditView::new().secret().with_name("password"))
                    .child("URL", EditView::new().with_name("url"))
                    .child("Notes", EditView::new().with_name("notes"))
            )
            .button("Save", |s| {
                let title = s.call_on_name("title", |v: &mut EditView| v.get_content()).unwrap();
                let username = s.call_on_name("username", |v: &mut EditView| v.get_content()).unwrap();
                let password = s.call_on_name("password", |v: &mut EditView| v.get_content()).unwrap();
                let url = s.call_on_name("url", |v: &mut EditView| v.get_content()).unwrap();
                let notes = s.call_on_name("notes", |v: &mut EditView| v.get_content()).unwrap();
                
                let pm = s.user_data::<PasswordManager>().unwrap();
                match pm.add_entry(&title, &username, &password, &url, &notes) {
                    Ok(_) => {
                        s.pop_layer();
                        show_main_ui(s);
                    }
                    Err(e) => s.add_layer(Dialog::info(format!("Error: {}", e))),
                }
            })
            .button("Cancel", |s| { s.pop_layer(); })
    );
}

fn show_generator(s: &mut Cursive) {
    s.add_layer(
        Dialog::new()
            .title("Password Generator")
            .content(
                ListView::new()
                    .child("Length", EditView::new().with_name("length"))
                    .child("Password", TextView::new("").with_name("output"))
            )
            .button("Generate", |s| {
                let length = s.call_on_name("length", |v: &mut EditView| v.get_content())
                    .unwrap()
                    .parse::<usize>()
                    .unwrap_or(12);
                
                let pass = PasswordManager::generate_password(length);
                s.call_on_name("output", |v: &mut TextView| {
                    v.set_content(pass.clone());
                });
                
                let mut clipboard = clipboard::ClipboardContext::new().unwrap();
                clipboard.set_contents(pass).unwrap();
            })
            .button("Close", |s| { s.pop_layer(); })
    );
}
