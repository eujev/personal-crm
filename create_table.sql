CREATE TABLE people(
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id INTEGER NOT NULL,
    firstname TEXT NOT NULL,
    lastname TEXT,
    birthday TEXT,
    address TEXT,
    mail TEST,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
