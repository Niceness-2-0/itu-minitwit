DROP TABLE IF EXISTS "user" CASCADE;
CREATE TABLE "user" (
  user_id SERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  email TEXT NOT NULL,
  pw_hash TEXT NOT NULL
);

DROP TABLE IF EXISTS follower CASCADE;
CREATE TABLE follower (
  who_id INTEGER,
  whom_id INTEGER,
  PRIMARY KEY (who_id, whom_id)
);

DROP TABLE IF EXISTS message CASCADE;
CREATE TABLE message (
  message_id SERIAL PRIMARY KEY,
  author_id INTEGER NOT NULL,
  "text" TEXT NOT NULL,
  pub_date INTEGER,
  flagged INTEGER
);