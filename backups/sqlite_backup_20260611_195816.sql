-- SQLite database backup
-- Created: 2026-06-11 19:58:16

CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );

INSERT INTO users (id, username, password) VALUES (1, 'admin', 'admin123');
INSERT INTO users (id, username, password) VALUES (3, 'alice', 'alice123');
INSERT INTO users (id, username, password) VALUES (4, 'bob', 'bob123');
INSERT INTO users (id, username, password) VALUES (5, 'charlie', 'charlie123');
INSERT INTO users (id, username, password) VALUES (6, 'diana', 'diana123');
INSERT INTO users (id, username, password) VALUES (7, 'evan', 'evan123');
INSERT INTO users (id, username, password) VALUES (8, 'farah', 'farah123');
INSERT INTO users (id, username, password) VALUES (9, 'guest', 'guest123');
INSERT INTO users (id, username, password) VALUES (10, 'test', 'test123');
INSERT INTO users (id, username, password) VALUES (11, 'demo', 'demo123');
