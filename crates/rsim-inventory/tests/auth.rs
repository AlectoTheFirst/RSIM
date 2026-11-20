//! The SQL tests of the users, the sessions and the API tokens. They need
//! `RSIM_TEST_DATABASE_URL`; with it unset they print that they are skipped
//! and pass.

use rsim_inventory::{
    Attempt, Db, Error, Principal, Role, TOKEN_PREFIX, Via, hash_password, new_secret, secret_hash,
    test_database,
};

/// The Argon2id hash of a random password.
fn password_hash() -> String {
    let (password, _) = new_secret("").unwrap();
    hash_password(&password).unwrap()
}

async fn with_admin(name: &str) -> Option<(Db, Principal, Vec<u8>)> {
    let db = test_database(name).await?;
    assert!(db.setup_open().await.unwrap());
    let (_, session) = new_secret("").unwrap();
    let admin = db
        .setup("admin", &password_hash(), &session, "192.0.2.1")
        .await
        .unwrap();
    Some((db, admin, session))
}

#[tokio::test]
async fn the_setup_makes_one_admin_only() {
    let Some((db, admin, session)) = with_admin("auth_setup").await else {
        return;
    };
    assert_eq!(admin.role, Role::Admin);
    assert!(!db.setup_open().await.unwrap());
    let (_, other) = new_secret("").unwrap();
    let again = db
        .setup("other", &password_hash(), &other, "192.0.2.2")
        .await;
    assert!(matches!(again, Err(Error::Conflict(_))), "{again:?}");
    let p = db.session(&session).await.unwrap().unwrap();
    assert_eq!(p.name, "admin");
    assert_eq!(p.via, Via::Session);
    assert!(p.has("rsim.admin"));
}

#[tokio::test]
async fn parallel_setups_make_one_admin() {
    let Some(db) = test_database("auth_setup_race").await else {
        return;
    };
    let hash = password_hash();
    let mut tasks = Vec::new();
    for i in 0..4 {
        // Each task has a connection of its own, so the setups meet in the
        // database.
        let db = db.reopen();
        let hash = hash.clone();
        tasks.push(tokio::spawn(async move {
            let (_, s) = new_secret("").unwrap();
            db.setup(&format!("admin{i}"), &hash, &s, "192.0.2.1").await
        }));
    }
    let mut ok = 0;
    for t in tasks {
        if t.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, 1);
    assert_eq!(db.users().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_session_ends_at_sign_out_and_for_a_disabled_user() {
    let Some((db, admin, session)) = with_admin("auth_sessions").await else {
        return;
    };
    db.end_session(&session, "192.0.2.1").await.unwrap();
    assert_eq!(db.session(&session).await.unwrap(), None);

    db.put_user(
        "admin",
        "viewer1",
        Role::Viewer,
        false,
        Some(&password_hash()),
    )
    .await
    .unwrap();
    let acc = db.account("viewer1").await.unwrap().unwrap();
    let (_, s) = new_secret("").unwrap();
    db.start_session(acc.user_id, "viewer1", &s, "192.0.2.3")
        .await
        .unwrap();
    let p = db.session(&s).await.unwrap().unwrap();
    assert_eq!(p.scopes, ["rsim.read"]);
    db.put_user(&admin.name, "viewer1", Role::Viewer, true, None)
        .await
        .unwrap();
    assert_eq!(db.session(&s).await.unwrap(), None);
}

#[tokio::test]
async fn a_token_works_until_it_is_revoked_and_keeps_only_role_scopes() {
    let Some((db, admin, _)) = with_admin("auth_tokens").await else {
        return;
    };
    let (text, hash) = new_secret(TOKEN_PREFIX).unwrap();
    let info = db
        .create_token(
            &admin,
            "ci",
            &["rsim.read".into(), "rsim.inventory.write".into()],
            Some(30),
            &hash,
        )
        .await
        .unwrap();
    assert!(info.expires_at.is_some());
    let p = db.api_token(&secret_hash(&text)).await.unwrap().unwrap();
    assert_eq!(p.via, Via::Token(info.id));
    assert_eq!(p.scopes, ["rsim.read", "rsim.inventory.write"]);

    db.put_user(
        &admin.name,
        "second",
        Role::Admin,
        false,
        Some(&password_hash()),
    )
    .await
    .unwrap();
    db.put_user("second", "admin", Role::Viewer, false, None)
        .await
        .unwrap();
    let p = db.api_token(&hash).await.unwrap().unwrap();
    assert_eq!(p.scopes, ["rsim.read"]);

    db.revoke_token(&p, info.id).await.unwrap();
    assert_eq!(db.api_token(&hash).await.unwrap(), None);
    let listed = db.tokens(admin.user_id).await.unwrap();
    assert!(listed[0].revoked);
    assert_eq!(db.api_token(&secret_hash("rsim_00")).await.unwrap(), None);
}

#[tokio::test]
async fn a_token_cannot_name_a_scope_outside_its_role() {
    let Some((db, _, _)) = with_admin("auth_token_scope").await else {
        return;
    };
    db.put_user("admin", "v", Role::Viewer, false, Some(&password_hash()))
        .await
        .unwrap();
    let acc = db.account("v").await.unwrap().unwrap();
    let v = Principal {
        user_id: acc.user_id,
        name: "v".into(),
        role: Role::Viewer,
        scopes: vec!["rsim.read".into()],
        via: Via::Session,
    };
    let (_, hash) = new_secret(TOKEN_PREFIX).unwrap();
    let r = db
        .create_token(&v, "x", &["rsim.admin".into()], None, &hash)
        .await;
    assert!(matches!(r, Err(Error::Invalid(_))), "{r:?}");
}

#[tokio::test]
async fn the_last_admin_stays() {
    let Some((db, _, _)) = with_admin("auth_last_admin").await else {
        return;
    };
    for r in [
        db.put_user("admin", "admin", Role::Operator, false, None)
            .await
            .map(|_| ()),
        db.put_user("admin", "admin", Role::Admin, true, None)
            .await
            .map(|_| ()),
        db.delete_user("admin", "admin").await,
    ] {
        assert!(matches!(r, Err(Error::Conflict(_))), "{r:?}");
    }
}

#[tokio::test]
async fn the_name_limit_and_the_client_limit_hold_each_alone() {
    let Some((db, _, _)) = with_admin("auth_limit").await else {
        return;
    };
    let go = |a: Attempt| matches!(a, Attempt::Go(_));
    // 5 attempts on one name from 5 addresses reach the name limit.
    for i in 0..5 {
        let a = db
            .begin_sign_in("admin", &format!("198.51.100.{i}"))
            .await
            .unwrap();
        assert!(go(a), "{i}");
    }
    let a = db.begin_sign_in("admin", "198.51.100.200").await.unwrap();
    assert!(
        matches!(a, Attempt::Wait(w) if (1..=900).contains(&w)),
        "{a:?}"
    );
    // 5 attempts from one address on 5 names reach the client limit.
    for i in 0..5 {
        let a = db
            .begin_sign_in(&format!("user{i}"), "203.0.113.5")
            .await
            .unwrap();
        assert!(go(a), "{i}");
    }
    let a = db.begin_sign_in("fresh", "203.0.113.5").await.unwrap();
    assert!(matches!(a, Attempt::Wait(_)), "{a:?}");
    assert!(go(db.begin_sign_in("fresh", "203.0.113.6").await.unwrap()));
}

#[tokio::test]
async fn parallel_attempts_do_not_pass_the_limit() {
    let Some((db, _, _)) = with_admin("auth_limit_race").await else {
        return;
    };
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let db = db.reopen();
        tasks.push(tokio::spawn(async move {
            db.begin_sign_in("admin", "198.51.100.9").await.unwrap()
        }));
    }
    let mut go = 0;
    for t in tasks {
        if matches!(t.await.unwrap(), Attempt::Go(_)) {
            go += 1;
        }
    }
    assert_eq!(go, 5);
}

#[tokio::test]
async fn a_success_removes_its_attempt() {
    let Some((db, _, _)) = with_admin("auth_limit_success").await else {
        return;
    };
    for _ in 0..10 {
        let Attempt::Go(id) = db.begin_sign_in("admin", "198.51.100.1").await.unwrap() else {
            panic!("a forgotten attempt counts");
        };
        db.forget_attempt(id).await.unwrap();
    }
    assert_eq!(
        db.sign_in_wait("admin", "198.51.100.1").await.unwrap(),
        None
    );
}
