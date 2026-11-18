//! The SQL tests. They need `RSIM_TEST_DATABASE_URL`; with it unset they
//! print that they are skipped and pass.

use rsim_inventory::{
    Action, CaptureBgp, Change, Credential, CredentialSource, Device, EdgeDeviceBinding, Error,
    FabricPortBinding, Group, Ha, JumpHost, Origin, Route, Settings, SshAlgorithms, env,
    import_changes, test_database,
};

fn credential(name: &str, key: &str) -> Credential {
    Credential {
        name: name.into(),
        source: CredentialSource::Env,
        key: key.into(),
        description: None,
    }
}

fn group(name: &str) -> Group {
    Group {
        name: name.into(),
        vendor: "vyos".into(),
        description: Some("core routers".into()),
        settings: Settings {
            credential: Some("vyos".into()),
            route: Some("bastion".into()),
            capture_bgp: Some(CaptureBgp::All),
            timeout_seconds: Some(90),
            ..Settings::default()
        },
    }
}

fn device(name: &str, group: &str) -> Device {
    Device {
        name: name.into(),
        group: group.into(),
        address: "192.0.2.1".into(),
        site: Some("ams".into()),
        location: Some("rack 4".into()),
        console_site: None,
        settings: Settings {
            ha: Some(Ha::One),
            section_timeout_seconds: Some(5),
            ..Settings::default()
        },
    }
}

fn base() -> Vec<Change> {
    vec![
        Change::PutCredential(credential("vyos", "VYOS")),
        Change::PutCredential(credential("jump-a", "JUMP_A")),
        Change::PutJumpHost(JumpHost {
            name: "a".into(),
            address: "192.0.2.20".into(),
            credential: "jump-a".into(),
            ssh_algorithms: SshAlgorithms::Legacy,
        }),
        Change::PutRoute(Route {
            name: "bastion".into(),
            proxy: Some("socks5://192.0.2.9:1080".into()),
            proxy_credential: None,
            jumps: vec!["a".into()],
        }),
        Change::PutRoute(Route {
            name: "direct".into(),
            proxy: None,
            proxy_credential: None,
            jumps: vec![],
        }),
        Change::PutGroup(group("core")),
        Change::PutDevice(device("r1", "core")),
    ]
}

#[tokio::test]
async fn the_migrations_run_once() {
    let Some(db) = test_database("the_migrations_run_once").await else {
        return;
    };
    assert!(db.migrate().await.unwrap().is_empty());
    let inv = db.load().await.unwrap();
    assert_eq!(inv.version, 0);
    assert!(inv.devices.is_empty());
}

#[tokio::test]
async fn a_write_increases_the_version_and_records_the_audit() {
    let Some(db) = test_database("a_write_increases_the_version").await else {
        return;
    };
    assert_eq!(db.apply("tester", &base()).await.unwrap(), 1);
    let inv = db.load().await.unwrap();
    assert_eq!(inv.version, 1);
    assert_eq!(inv.groups, [group("core")]);
    assert_eq!(inv.devices, [device("r1", "core")]);
    assert_eq!(inv.route("bastion").unwrap().jumps, ["a"]);
    assert!(inv.route("direct").unwrap().jumps.is_empty());
    let r = &inv.resolve().unwrap()[0];
    assert_eq!(r.settings.route.value.as_deref(), Some("bastion"));
    assert_eq!(r.settings.route.origin, Origin::Group);
    assert_eq!(r.settings.section_timeout_seconds.value, 5);
    assert_eq!(r.settings.ha.value, Ha::One);
    assert_eq!(r.settings.retries.value, 0);

    // The same records again change nothing.
    assert_eq!(db.apply("tester", &base()).await.unwrap(), 1);

    let mut d = device("r1", "core");
    d.settings.route = Some("direct".into());
    assert_eq!(
        db.apply("tester", &[Change::PutDevice(d.clone())])
            .await
            .unwrap(),
        2
    );
    let page = db.audit(100, None).await.unwrap();
    assert_eq!(page.records.len(), 8);
    let last = &page.records[0];
    assert_eq!(
        (
            last.kind.as_str(),
            last.key.as_str(),
            last.action,
            last.version
        ),
        ("device", "r1", Action::Update, 2)
    );
    assert_eq!(last.actor, "tester");
    assert_eq!(
        last.old.as_ref().unwrap()["settings"]["route"],
        serde_json::Value::Null
    );
    assert_eq!(last.new.as_ref().unwrap()["settings"]["route"], "direct");
    assert!(
        last.at.ends_with('Z') && last.at.contains('T'),
        "{}",
        last.at
    );
    assert_eq!(page.records[7].action, Action::Create);
    assert_eq!(page.records[7].version, 1);

    let first = db.audit(3, None).await.unwrap();
    assert_eq!(first.records.len(), 3);
    let next = db.audit(100, first.next_before).await.unwrap();
    assert_eq!(next.records.len(), 5);
    assert!(next.next_before.is_none());

    assert_eq!(
        db.apply("tester", &[Change::DeleteDevice("r1".into())])
            .await
            .unwrap(),
        3
    );
    let del = &db.audit(1, None).await.unwrap().records[0];
    assert_eq!(del.action, Action::Delete);
    assert!(del.new.is_none());
}

#[tokio::test]
async fn a_bad_change_writes_nothing() {
    let Some(db) = test_database("a_bad_change_writes_nothing").await else {
        return;
    };
    db.apply("tester", &base()).await.unwrap();
    let before = db.load().await.unwrap();

    let in_use = db
        .apply("tester", &[Change::DeleteGroup("core".into())])
        .await
        .unwrap_err();
    assert!(matches!(in_use, Error::Conflict(_)), "{in_use:?}");

    let missing = db
        .apply("tester", &[Change::DeleteDevice("nope".into())])
        .await
        .unwrap_err();
    assert!(matches!(missing, Error::NotFound(_)), "{missing:?}");

    let mut bad = device("r2", "core");
    bad.settings.timeout_seconds = Some(0);
    let invalid = db
        .apply(
            "tester",
            &[
                Change::PutDevice(device("r3", "core")),
                Change::PutDevice(bad),
            ],
        )
        .await
        .unwrap_err();
    assert!(matches!(invalid, Error::Invalid(_)), "{invalid:?}");

    let unknown_jump = db
        .apply(
            "tester",
            &[Change::PutRoute(Route {
                name: "x".into(),
                proxy: None,
                proxy_credential: None,
                jumps: vec!["nope".into()],
            })],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(unknown_jump, Error::Conflict(_)),
        "{unknown_jump:?}"
    );

    let bad_key = db
        .apply("tester", &[Change::PutCredential(credential("y", "lower"))])
        .await
        .unwrap_err();
    assert!(matches!(bad_key, Error::Invalid(_)), "{bad_key:?}");

    assert_eq!(db.load().await.unwrap(), before);
    assert_eq!(db.audit(100, None).await.unwrap().records.len(), 7);
}

#[tokio::test]
async fn the_bindings_join_devices() {
    let Some(db) = test_database("the_bindings_join_devices").await else {
        return;
    };
    let mut changes = base();
    let mut account = device("equinix-main", "core");
    account.address = "api.equinix.com".into();
    changes.push(Change::PutDevice(account));
    changes.push(Change::PutFabricPort(FabricPortBinding {
        account: "equinix-main".into(),
        fabric_port: "port-1".into(),
        device: "r1".into(),
        port: "eth1".into(),
    }));
    changes.push(Change::PutEdgeDevice(EdgeDeviceBinding {
        account: "equinix-main".into(),
        edge_device: "ne-1".into(),
        device: "r1".into(),
    }));
    db.apply("tester", &changes).await.unwrap();
    let b = db.load().await.unwrap().bindings;
    assert_eq!(b.fabric_ports.len(), 1);
    assert_eq!(b.fabric_ports[0].port, "eth1");
    assert_eq!(b.edge_devices[0].device, "r1");

    let unknown = db
        .apply(
            "tester",
            &[Change::PutFabricPort(FabricPortBinding {
                account: "equinix-main".into(),
                fabric_port: "port-2".into(),
                device: "nope".into(),
                port: "eth1".into(),
            })],
        )
        .await
        .unwrap_err();
    assert!(matches!(unknown, Error::Conflict(_)), "{unknown:?}");

    db.apply(
        "tester",
        &[
            Change::DeleteFabricPort {
                account: "equinix-main".into(),
                fabric_port: "port-1".into(),
            },
            Change::DeleteEdgeDevice {
                account: "equinix-main".into(),
                edge_device: "ne-1".into(),
            },
        ],
    )
    .await
    .unwrap();
    assert_eq!(db.load().await.unwrap().bindings, Default::default());
}

#[tokio::test]
async fn an_env_import_round_trips() {
    let Some(db) = test_database("an_env_import_round_trips").await else {
        return;
    };
    let text = "VYOS_CORE1_IP=10.0.0.1\nVYOS_EDGE_IP=10.0.0.2\nVYOS_EDGE_VIA=\n\
                VYOS_VIA=bastion-a\nVYOS_PROXY=socks5://p:q@192.0.2.9:1080\n\
                VYOS_USER=ro\nVYOS_PASS=secret-pass\nVYOS_CAPTURE_BGP=all\n\
                JUMP_BASTION_A_IP=192.0.2.20\nJUMP_BASTION_A_USER=hop\nJUMP_BASTION_A_PASS=h\n\
                NXOS_LEAF_1_IP=192.0.2.31\nNXOS_LEAF_1_JSON=native\nNXOS_LEAF_1_CHANNELS=4\n\
                NXOS_USER=ro\nNXOS_PASS=p\nUNIFI_CONTROLLER=192.0.2.8\nUNIFI_API_KEY=k\n\
                UNIFI_TLS=none\n";
    let records = env::import(&env::parse_env(text)).unwrap();
    let version = db
        .apply("import", &import_changes(records.clone()))
        .await
        .unwrap();
    assert_eq!(version, 1);
    let inv = db.load().await.unwrap();
    let mut credentials = records.credentials.clone();
    credentials.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(inv.credentials, credentials);
    let mut devices = records.devices.clone();
    devices.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(inv.devices, devices);
    let dump = serde_json::to_string(&inv).unwrap();
    for secret in ["secret-pass", "p:q", "\"k\""] {
        assert!(!dump.contains(secret), "{secret} is in the inventory");
    }
    let audit = serde_json::to_string(&db.audit(1000, None).await.unwrap()).unwrap();
    assert!(!audit.contains("secret-pass") && !audit.contains("p:q"));
    // A second import of the same file changes nothing.
    assert_eq!(
        db.apply("import", &import_changes(records)).await.unwrap(),
        1
    );
}

#[tokio::test]
async fn each_list_is_in_byte_order_of_its_key() {
    let Some(db) = test_database("each_list_is_in_byte_order").await else {
        return;
    };
    // A collation of a language puts 'ab' before 'a-c' and 'a1' before 'B1';
    // byte order puts them the other way.
    let mut changes = Vec::new();
    for n in ["ab", "a-c"] {
        changes.push(Change::PutCredential(credential(n, "VYOS")));
        changes.push(Change::PutJumpHost(JumpHost {
            name: n.into(),
            address: "192.0.2.20".into(),
            credential: n.into(),
            ssh_algorithms: SshAlgorithms::Modern,
        }));
        changes.push(Change::PutRoute(Route {
            name: n.into(),
            proxy: None,
            proxy_credential: None,
            jumps: vec![n.into()],
        }));
        changes.push(Change::PutGroup(Group {
            name: n.into(),
            vendor: "vyos".into(),
            description: None,
            settings: Settings::default(),
        }));
    }
    for d in ["a1", "B1"] {
        changes.push(Change::PutDevice(Device {
            name: d.into(),
            group: "ab".into(),
            address: "192.0.2.1".into(),
            site: None,
            location: None,
            console_site: None,
            settings: Settings::default(),
        }));
        for p in ["pc", "p-c"] {
            changes.push(Change::PutFabricPort(FabricPortBinding {
                account: d.into(),
                fabric_port: p.into(),
                device: d.into(),
                port: "eth1".into(),
            }));
            changes.push(Change::PutEdgeDevice(EdgeDeviceBinding {
                account: d.into(),
                edge_device: p.into(),
                device: d.into(),
            }));
        }
    }
    db.apply("tester", &changes).await.unwrap();
    let inv = db.load().await.unwrap();
    let sorted = |v: Vec<String>| {
        let mut s = v.clone();
        s.sort();
        assert_eq!(v, s);
        v
    };
    assert_eq!(
        sorted(inv.credentials.iter().map(|c| c.name.clone()).collect()),
        ["a-c", "ab"]
    );
    sorted(inv.jump_hosts.iter().map(|j| j.name.clone()).collect());
    sorted(inv.routes.iter().map(|r| r.name.clone()).collect());
    sorted(inv.groups.iter().map(|g| g.name.clone()).collect());
    let devices = sorted(inv.devices.iter().map(|d| d.name.clone()).collect());
    assert_eq!(devices, ["B1", "a1"]);
    sorted(
        inv.bindings
            .fabric_ports
            .iter()
            .map(|b| format!("{}\0{}", b.account, b.fabric_port))
            .collect(),
    );
    sorted(
        inv.bindings
            .edge_devices
            .iter()
            .map(|b| format!("{}\0{}", b.account, b.edge_device))
            .collect(),
    );
    let resolved: Vec<String> = inv.resolve().unwrap().into_iter().map(|d| d.name).collect();
    assert_eq!(resolved, devices);
}
