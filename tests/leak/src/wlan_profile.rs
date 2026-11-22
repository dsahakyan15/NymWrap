use super::*;
fn fixture(extra: &str, setting: &str) -> String {
    let hex = "SYNTHETIC_SSID_741"
        .bytes()
        .map(|b| format!("{b:02X}"))
        .collect::<String>();
    format!(
        r#"<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">{extra}<SSIDConfig><SSID><hex>{hex}</hex><name>UNTRUSTED_NAME_CANARY</name></SSID></SSIDConfig><MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3"><enableRandomization>{setting}</enableRandomization></MacRandomization></WLANProfile>"#
    )
}
#[test]
fn comments_lookalike_namespaces_and_key_material_cannot_replace_the_actual_ssid_or_policy() {
    let xml = fixture(
        "<!-- <SSID><hex>414141</hex></SSID><enableRandomization>true</enableRandomization> -->",
        "false",
    );
    let profile = parse(&xml).unwrap();
    assert_eq!(profile.ssid, "SYNTHETIC_SSID_741");
    assert_eq!(profile.randomized, Some(false));
    let xml = fixture(
        r#"<SSIDConfig xmlns="urn:untrusted"><SSID><hex>414141</hex></SSID></SSIDConfig><MSM><security><sharedKey><keyMaterial>PRIVATE_KEY_MATERIAL_CANARY</keyMaterial></sharedKey></security></MSM>"#,
        "true",
    );
    let profile = parse(&xml).unwrap();
    assert_eq!(profile.ssid, "SYNTHETIC_SSID_741");
    assert_eq!(profile.randomized, Some(true));
}
#[test]
fn duplicate_fields_entities_dtd_wrong_roots_and_oversize_profiles_are_rejected() {
    for xml in [
        fixture(
            "<!DOCTYPE x [<!ENTITY y SYSTEM 'file:///synthetic'>]>",
            "true",
        ),
        fixture("", "&y;"),
        fixture("", "invalid"),
        fixture(
            "<SSIDConfig><SSID><hex>414141</hex></SSID></SSIDConfig>",
            "true",
        ),
        "<wrong/>".into(),
        "x".repeat(65537),
    ] {
        assert!(parse(&xml).is_err());
    }
    let xml=fixture("","true").replace("<MacRandomization xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v3\"><enableRandomization>true</enableRandomization></MacRandomization>","");
    assert_eq!(parse(&xml).unwrap().randomized, None);
}
