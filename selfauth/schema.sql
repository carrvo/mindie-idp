CREATE TABLE logins (
    app_url       CHAR(64)                               NOT NULL,
    app_key       VARCHAR(255)                           NOT NULL,
    user_url      VARCHAR(255)                           NOT NULL,
    user_hash     VARCHAR(255)                           NOT NULL,
    CONSTRAINT login_key PRIMARY KEY (app_url, user_url)
);
