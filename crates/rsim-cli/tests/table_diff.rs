//! The difference of the rows of a table between 2 frames.

use rsim_cli::frame::{self, Cell, Change, Frame, FrameBuilder};
use rsim_cli::tables::key_text;
use rsim_contract::table::{self, DiffCounts, RowChange, Selection};

/// A frame of the table `routes` with the rows `(prefix, metric, span)` of
/// the device r1 in the VRF `default`.
fn routes(rows: &[(&str, Option<u64>, &str)]) -> Frame {
    let def = table::table("routes").unwrap();
    let mut b = FrameBuilder::new(def);
    for (prefix, metric, span) in rows {
        let spans = [span.to_string()];
        b.push(&[
            Cell::Text("r1"),
            Cell::Text("default"),
            Cell::Text(prefix),
            Cell::Text("static"),
            Cell::Boolean(true),
            Cell::Integer(1),
            metric.map_or(Cell::Null, Cell::Integer),
            Cell::Text("192.0.2.1"),
            Cell::Text("eth0"),
            Cell::Null,
            Cell::Null,
            Cell::List(&spans),
        ]);
    }
    b.finish(&key_text)
}

#[test]
fn a_difference_has_the_changed_the_removed_and_the_added_rows_in_key_order() {
    let def = table::table("routes").unwrap();
    let before = routes(&[
        ("192.0.2.0/24", Some(0), "a:1-1"),
        ("10.0.0.0/8", Some(0), "a:2-2"),
        ("10.1.0.0/16", Some(0), "a:3-3"),
    ]);
    let after = routes(&[
        ("10.0.0.0/8", Some(5), "b:1-1"),
        ("172.16.0.0/12", Some(0), "b:2-2"),
        ("192.0.2.0/24", Some(0), "b:3-3"),
    ]);
    // Both frames are in key order: 10.0.0.0/8, then 10.1.0.0/16 or
    // 172.16.0.0/12, then 192.0.2.0/24. The span of 192.0.2.0/24 differs,
    // and a span is not compared.
    assert_eq!(
        frame::diff(def, &before, &after, &key_text),
        [Change::Changed(0, 0), Change::Removed(1), Change::Added(1)]
    );
    assert!(frame::diff(def, &before, &before, &key_text).is_empty());

    let page = frame::diff_page(
        def,
        &before,
        &after,
        &Selection {
            columns: Some(vec!["prefix".into(), "metric".into()]),
            limit: Some(2),
            ..Selection::default()
        },
        &key_text,
    )
    .unwrap();
    assert_eq!(
        page.counts,
        DiffCounts {
            added: 1,
            removed: 1,
            changed: 1
        }
    );
    assert_eq!((page.total, page.next.as_deref()), (3, Some("o2")));
    assert_eq!(page.rows[0].change, RowChange::Changed);
    assert_eq!(
        page.rows[0].row,
        [serde_json::json!("10.0.0.0/8"), serde_json::json!(5)]
    );
    assert_eq!(
        page.rows[0].before.as_deref(),
        Some(&[serde_json::json!("10.0.0.0/8"), serde_json::json!(0)][..])
    );
    assert_eq!(page.rows[1].change, RowChange::Removed);
    assert_eq!(page.rows[1].row[0], "10.1.0.0/16");
    assert!(page.rows[1].before.is_none());
}

#[test]
fn rows_with_a_repeated_key_pair_by_equal_values() {
    let def = table::table("routes").unwrap();
    // 2 rows with 1 key on each side. The rows with the metric 2 pair, and
    // the 2 rows left are 1 changed row.
    let before = routes(&[
        ("10.0.0.0/8", Some(1), "a:1-1"),
        ("10.0.0.0/8", Some(2), "a:2-2"),
    ]);
    let after = routes(&[
        ("10.0.0.0/8", Some(2), "b:1-1"),
        ("10.0.0.0/8", Some(3), "b:2-2"),
    ]);
    assert_eq!(
        frame::diff(def, &before, &after, &key_text),
        [Change::Changed(0, 1)]
    );
    // 2 rows left on 1 side and none on the other are removed.
    let one = routes(&[("10.0.0.0/8", Some(2), "b:1-1")]);
    let three = routes(&[
        ("10.0.0.0/8", Some(1), "a:1-1"),
        ("10.0.0.0/8", Some(2), "a:2-2"),
        ("10.0.0.0/8", None, "a:3-3"),
    ]);
    assert_eq!(
        frame::diff(def, &three, &one, &key_text),
        [Change::Removed(0), Change::Removed(2)]
    );
}

#[test]
fn a_difference_refuses_a_filter_and_a_sort() {
    let def = table::table("routes").unwrap();
    let f = routes(&[]);
    let sel = Selection {
        sort: Some(vec!["prefix".into()]),
        ..Selection::default()
    };
    assert!(frame::diff_page(def, &f, &f, &sel, &key_text).is_err());
}
