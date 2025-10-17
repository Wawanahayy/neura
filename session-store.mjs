// session-store.mjs
import fs from 'node:fs';

const FILE = '.sessions.json';

export const load = ()=> fs.existsSync(FILE) ? JSON.parse(fs.readFileSync(FILE,'utf8')) : {};
export const save = (db)=> fs.writeFileSync(FILE, JSON.stringify(db, null, 2));
export const getFor = (db, addr)=> db[addr?.toLowerCase()] || null;
export const putFor = (db, addr, sess)=> { db[addr.toLowerCase()] = sess; return db; };
