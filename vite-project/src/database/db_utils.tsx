import sqlite3 from 'sqlite3';
import { open, Database } from 'sqlite';
import fs from 'fs';

const DB_PATH = './minitwit.db';

let db: Database | null = null;

/** Returns a new connection to the database */
export async function connectDb(): Promise<Database> {
    db = await open({
        filename: DB_PATH,
        driver: sqlite3.Database,
    });
    console.log('Connected to SQLite database.');
    return db;
}

export async function queryDb(query: string, args: any[] = [], one: boolean = false): Promise<any> {
    if (!db) throw new Error("Database not connected");

    const result = await db.all(query, args);
    return one ? result[0] || null : result;
}


export async function initDb(schemaFile: string = 'schema.sql'): Promise<void> {
    if (!db) throw new Error('Database not connected');

    const schema = fs.readFileSync(schemaFile, 'utf-8');
    await db.exec(schema);
    console.log('Database schema initialized.');
}


export async function closeDb(): Promise<void> {
    if (db) {
        await db.close();
        console.log('Database connection closed.');
    }
}
