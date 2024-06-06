#[test]
fn parse_embedded_roots() {
    #[cfg(feature = "dev")]
    {
        let ta_bytes = include_bytes!("../roots/NIPR/dev/DOD_ENG_Root-3.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
    #[cfg(feature = "dev")]
    {
        let ta_bytes = include_bytes!("../roots/NIPR/dev/DOD_ENG_Root-6.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
    #[cfg(feature = "om_nipr")]
    {
        let ta_bytes = include_bytes!("../roots/NIPR/om/DOD_JITC_Root_CA-3.der.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();

        let ta_bytes = include_bytes!("../roots/NIPR/om/DOD_JITC_Root_CA-6.der.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
    #[cfg(feature = "om_sipr")]
    {
        let ta_bytes = include_bytes!("../roots/SIPR/om/NSS_JITC_Root_CA-2.der-2.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
    #[cfg(feature = "nipr")]
    {
        let ta_bytes = include_bytes!("../roots/NIPR/prod/DOD_Root_CA-3.der.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();

        let ta_bytes = include_bytes!("../roots/NIPR/prod/DOD_Root_CA-6.der.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
    #[cfg(feature = "sipr")]
    {
        let ta_bytes = include_bytes!("../roots/SIPR/prod/NSS_Root_CA-2.der-2.der");
        reqwest::Certificate::from_der(ta_bytes).unwrap();
    }
}
