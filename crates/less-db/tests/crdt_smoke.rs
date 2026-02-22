use json_joy::json_crdt::codec::structural::binary;
use json_joy::json_crdt::nodes::TsKey;
use json_joy::json_crdt::Model;
use json_joy::json_crdt::ModelApi;
use json_joy::json_crdt_diff::diff_node;
use serde_json::json;

#[test]
fn create_model_and_view() {
    let model = Model::create();
    let view = model.view();
    assert!(view.is_null(), "New model should have null view");
}

#[test]
fn model_with_session_id() {
    let model = Model::new(12345);
    assert_eq!(model.clock.sid, 12345);
}

#[test]
fn set_root_and_view() {
    let mut model = Model::new(100);
    let data = json!({"name": "Alice", "age": 30});

    {
        let mut api = ModelApi::new(&mut model);
        api.set_root(&data).expect("set_root should succeed");
        api.apply();
    }

    let view = model.view();
    assert_eq!(view["name"], json!("Alice"));
    assert_eq!(view["age"], json!(30));
}

#[test]
fn binary_round_trip() {
    let mut model = Model::new(200);
    let data = json!({"key": "value", "nested": {"a": 1}});

    {
        let mut api = ModelApi::new(&mut model);
        api.set_root(&data).expect("set_root should succeed");
        api.apply();
    }

    // Encode to binary
    let bytes = binary::encode(&model);
    assert!(
        !bytes.is_empty(),
        "Binary encoding should produce non-empty bytes"
    );

    // Decode back
    let decoded = binary::decode(&bytes).expect("Binary decode should succeed");
    let decoded_view = decoded.view();

    assert_eq!(decoded_view["key"], json!("value"));
    assert_eq!(decoded_view["nested"]["a"], json!(1));
}

#[test]
fn diff_and_apply_patch() {
    let mut model = Model::new(300);
    let initial = json!({"name": "Bob", "score": 10});

    {
        let mut api = ModelApi::new(&mut model);
        api.set_root(&initial).expect("set_root should succeed");
        api.apply();
    }

    // Diff against updated value
    let updated = json!({"name": "Bob", "score": 20});
    let root_node = model
        .index
        .get(&TsKey::from(model.root.val))
        .expect("root node should exist");
    let diff_patch = diff_node(
        root_node,
        &model.index,
        model.clock.sid,
        model.clock.time,
        &updated,
    );

    if let Some(patch) = diff_patch {
        model.apply_patch(&patch);
    }
    let view = model.view();

    assert_eq!(view["name"], json!("Bob"));
    assert_eq!(view["score"], json!(20));
}

#[test]
fn fork_via_binary_round_trip() {
    let mut model = Model::new(400);
    let data = json!({"x": 1});

    {
        let mut api = ModelApi::new(&mut model);
        api.set_root(&data).expect("set_root should succeed");
        api.apply();
    }

    // "Fork" by encoding and decoding
    let bytes = binary::encode(&model);
    let mut forked = binary::decode(&bytes).expect("decode should succeed");

    // Modify the fork
    let new_data = json!({"x": 2});
    let root_node = forked
        .index
        .get(&TsKey::from(forked.root.val))
        .expect("root node should exist");
    let diff_patch = diff_node(
        root_node,
        &forked.index,
        forked.clock.sid,
        forked.clock.time,
        &new_data,
    );
    if let Some(patch) = diff_patch {
        forked.apply_patch(&patch);
    }

    // Original should be unchanged
    assert_eq!(model.view()["x"], json!(1));
    assert_eq!(forked.view()["x"], json!(2));
}
