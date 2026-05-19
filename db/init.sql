CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user', 'reviewer')),
    is_disabled BOOLEAN DEFAULT FALSE
);

CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    owner_id INTEGER REFERENCES users(id),
    title TEXT NOT NULL,
    filename TEXT NOT NULL,
    storage_key TEXT UNIQUE NOT NULL,
    document_hash VARCHAR(64),
    metadata TEXT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE document_shares (
    id SERIAL PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id),
    shared_with INTEGER REFERENCES users(id),
    UNIQUE (document_id, shared_with)
);

CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    actor_id INTEGER REFERENCES users(id),
    action_type TEXT NOT NULL,
    target_user_id INTEGER REFERENCES users(id),
    target_document_id INTEGER REFERENCES documents(id),
    justification TEXT,
    result TEXT NOT NULL
);

INSERT INTO users (username, password, role, is_disabled) VALUES
('admin', 'pbkdf2:sha256:1000000$Xr8a7NqErCjGNwtW$4d60f56130cf74984181f5d3cf4dcbb426e1597c5eb9cc8991f949e00acaf665', 'admin', FALSE),
('alice', 'pbkdf2:sha256:1000000$qQzGdTse5Idflc1f$07ec2fedf3d08188fd6bd14bd5535434a87807c16df8ebf2ba257bbb234fd90f', 'user', FALSE),
('bob', 'pbkdf2:sha256:1000000$SkexOgCNsUX76SFS$115a8afb2ef5beaab37745c777e54c965be85abad01f514f4b47d66be31157f5', 'reviewer', FALSE);