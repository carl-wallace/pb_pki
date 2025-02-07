use pb_pki::get_roots;

#[test]
fn parse_embedded_roots() {
    #[cfg(feature = "dev")]
    {
        let ta_bytes = include_bytes!("../roots/NIPR/dev/DOD_ENG_Root-3.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();

        let ta_bytes = include_bytes!("../roots/NIPR/dev/DOD_ENG_Root-6.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
    #[cfg(feature = "om_nipr")]
    {
        let ta_bytes = include_bytes!("../roots/NIPR/om/DOD_JITC_Root_CA-3.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();

        let ta_bytes = include_bytes!("../roots/NIPR/om/DOD_JITC_Root_CA-5.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();

        let ta_bytes = include_bytes!("../roots/NIPR/om/DOD_JITC_Root_CA-6.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
    #[cfg(feature = "om_sipr")]
    {
        let ta_bytes = include_bytes!("../roots/SIPR/om/NSS_JITC_Root_CA-1.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();

        let ta_bytes = include_bytes!("../roots/SIPR/om/NSS_JITC_Root_CA-2.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();

        let ta_bytes = include_bytes!("../roots/SIPR/om/NSS_JITC_Root_CA-4.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
    #[cfg(feature = "nipr")]
    {
        let ta_bytes = include_bytes!("../roots/NIPR/prod/DOD_Root_CA-3.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();

        let ta_bytes = include_bytes!("../roots/NIPR/prod/DOD_Root_CA-5.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();

        let ta_bytes = include_bytes!("../roots/NIPR/prod/DOD_Root_CA-6.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
    #[cfg(feature = "sipr")]
    {
        let ta_bytes = include_bytes!("../roots/SIPR/prod/NSS_Root_CA-1.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();

        let ta_bytes = include_bytes!("../roots/SIPR/prod/NSS_Root_CA-2.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();

        let ta_bytes = include_bytes!("../roots/SIPR/prod/NSS_Root_CA-4.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
}

#[cfg(all(
    feature = "dev",
    feature = "sipr",
    feature = "nipr",
    feature = "om_sipr",
    feature = "om_nipr"
))]
#[test]
fn all_features_get_roots() {
    let roots = get_roots();
    assert_eq!(roots.len(), 14);
}

#[cfg(all(
    feature = "dev",
    not(feature = "sipr"),
    not(feature = "nipr"),
    not(feature = "om_sipr"),
    not(feature = "om_nipr")
))]
#[test]
fn dev_only_get_roots() {
    let roots = get_roots();
    assert_eq!(roots.len(), 2);
}

#[cfg(all(
    feature = "sipr",
    not(feature = "dev"),
    not(feature = "nipr"),
    not(feature = "om_sipr"),
    not(feature = "om_nipr")
))]
#[test]
fn sipr_only_get_roots() {
    let roots = get_roots();
    assert_eq!(roots.len(), 3);
}

#[cfg(all(
    feature = "nipr",
    not(feature = "dev"),
    not(feature = "sipr"),
    not(feature = "om_sipr"),
    not(feature = "om_nipr")
))]
#[test]
fn nipr_only_get_roots() {
    let roots = get_roots();
    assert_eq!(roots.len(), 3);
}

#[cfg(all(
    feature = "om_sipr",
    not(feature = "dev"),
    not(feature = "sipr"),
    not(feature = "nipr"),
    not(feature = "om_nipr")
))]
#[test]
fn om_sipr_only_get_roots() {
    let roots = get_roots();
    assert_eq!(roots.len(), 3);
}

#[cfg(all(
    feature = "om_nipr",
    not(feature = "dev"),
    not(feature = "sipr"),
    not(feature = "nipr"),
    not(feature = "om_sipr")
))]
#[test]
fn om_sipr_only_get_roots() {
    let roots = get_roots();
    assert_eq!(roots.len(), 3);
}
