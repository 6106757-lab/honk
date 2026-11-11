//! Regression tests for the inbound-tag routing contract.

#[test]
fn inbound_is_a_first_class_rule_type() {
    let condition = honk_config::routing::RoutingCondition {
        inbound: vec!["shop1".to_owned()],
        ..Default::default()
    };
    assert_eq!(
        condition.clash_rule_parts(),
        Some(("inbound", "shop1".to_owned()))
    );
}

#[test]
fn defaults_keep_listeners_loopback_and_bounded() {
    let config = honk_config::ListenerConfig {
        name: "shop1".to_owned(),
        port: 12000,
        ..Default::default()
    };
    assert_eq!(config.listen.to_string(), "127.0.0.1");
    assert!(config.handshake_timeout_ms > 0);
    assert!(config.request_timeout_ms > 0);
    assert!(config.max_header_bytes > 0);
    assert!(honk_config::validate_listeners(&[config]).is_ok());
}
