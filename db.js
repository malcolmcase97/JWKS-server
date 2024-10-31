import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import path from 'path';

const DATABASE_FILE = process.env.DATABASE_FILE || path.join(process.cwd(), 'database.db');

async function openDatabase() {
    const db = await open({
        filename: DATABASE_FILE,
        driver: sqlite3.Database
    });
    return db;
}

// Create tables if they don't exist
async function setupDatabase() {
    const db = await openDatabase();
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    `);
    console.log("Database setup complete.");
}

setupDatabase().catch(err => {
    console.error("Error setting up database:", err);
});

export { openDatabase };
