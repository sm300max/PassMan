use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Version, Argon2, Params, PasswordHasher};
use cursive::{
    view::Nameable,
    views::{
        Button, Dialog, EditView, LinearLayout, ListView, Panel, SelectView, TextView,
    },
    Cursive, CursiveExt,
};
use rand::{rngs::OsRng as RandOsRng, Rng};
use rusqlite::{params, Connection, Result as SqlResult};
use std::time::{Duration, Instant};
use clipboard::ClipboardProvider;

const DB_PATH: &str = "passwords.db";
const INACTIVITY_LOCK: Duration = Duration::from_secs(300);
const ARGON_PARAMS: Params = Params::new(4096, 3, 2, None).unwrap();

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
            ARGON_PARAMS,
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
        let nonce_value: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_value);

        cipher
            .encrypt(nonce, data.as_bytes())
            .map(|mut ciphertext| {
                ciphertext.extend_from_slice(&nonce_value);
                ciphertext
            })
            .map_err(|e| e.to_string())
    }

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

        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARS.len());
                CHARS[idx] as char
            })
            .collect()
    }
}

// Остальная часть кода с UI остается без изменений