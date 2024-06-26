#![doc = include_str!("../README.md")]

use std::time::Duration;

use log::error;
use reqwest::{Client, Identity};

use certval::{CertFile, CertSource, CertVector, Error, PkiEnvironment, TaSource};

/// Adds trust anchor certificates to the provided `TaSource` then adds it to the provided `PkiEnvironment`.
/// Creates one or more `CertSource` instances populated with CA certificates and adds those to the
/// provided `PkiEnvironment`.
///
/// If the requested environment is not available, returns `Error::Unrecognized`.
///
/// ```no_run
/// use certval::{PkiEnvironment, TaSource};
/// use pb_pki::prepare_certval_environment;
/// use log::error;
///
/// let mut pe = PkiEnvironment::default();
/// pe.populate_5280_pki_environment();
///
/// let mut ta_store = TaSource::new();
///
/// if let Err(e) = prepare_certval_environment(&mut pe, &mut ta_store, "DEV") {
///     error!("prepare_certval_environment failed with: {e}");
/// }
/// ```
pub fn prepare_certval_environment(
    pe: &mut PkiEnvironment,
    ta_store: &mut TaSource,
    env: &str,
) -> Result<(), Error> {
    let mut acted = false;
    #[cfg(feature = "dev")]
    if env == "DEV" {
        acted = true;
        let ta_bytes = include_bytes!("../roots/NIPR/dev/DOD_ENG_Root-3.der");
        let cf = CertFile {
            filename: "dev root".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let ta_bytes = include_bytes!("../roots/NIPR/dev/DOD_ENG_Root-6.der");
        let cf = CertFile {
            filename: "dev root".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let cbor = include_bytes!("../cas/NIPR/dev/dev.cbor");
        let mut cert_source = CertSource::new_from_cbor(cbor)?;
        cert_source.initialize(&Default::default())?;
        pe.add_certificate_source(Box::new(cert_source.clone()));
    }
    #[cfg(feature = "om_nipr")]
    if env == "OM_NIPR" {
        acted = true;
        let ta_bytes = include_bytes!("../roots/NIPR/om/DOD_JITC_Root_CA-3.der");
        let cf = CertFile {
            filename: "om nipr root 3".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let ta_bytes = include_bytes!("../roots/NIPR/om/DOD_JITC_Root_CA-6.der");
        let cf = CertFile {
            filename: "om nipr root 6".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let cbor = include_bytes!("../cas/NIPR/om/om.cbor");
        let mut cert_source = CertSource::new_from_cbor(cbor)?;
        cert_source.initialize(&Default::default())?;
        pe.add_certificate_source(Box::new(cert_source.clone()));
    }
    #[cfg(feature = "om_sipr")]
    if env == "OM_SIPR" {
        acted = true;
        let ta_bytes = include_bytes!("../roots/SIPR/om/NSS_JITC_Root_CA-2.der");
        let cf = CertFile {
            filename: "om sipr root".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let cbor = include_bytes!("../cas/SIPR/om/om.cbor");
        let mut cert_source = CertSource::new_from_cbor(cbor)?;
        cert_source.initialize(&Default::default())?;
        pe.add_certificate_source(Box::new(cert_source.clone()));
    }
    #[cfg(feature = "nipr")]
    if env == "NIPR" {
        acted = true;
        let ta_bytes = include_bytes!("../roots/NIPR/prod/DOD_Root_CA-3.der");
        let cf = CertFile {
            filename: "nipr root 3".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let ta_bytes = include_bytes!("../roots/NIPR/prod/DOD_Root_CA-6.der");
        let cf = CertFile {
            filename: "nipr root 6".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let cbor = include_bytes!("../cas/NIPR/prod/prod.cbor");
        let mut cert_source = CertSource::new_from_cbor(cbor)?;
        cert_source.initialize(&Default::default())?;
        pe.add_certificate_source(Box::new(cert_source.clone()));
    }
    #[cfg(feature = "sipr")]
    if env == "SIPR" {
        acted = true;
        let ta_bytes = include_bytes!("../roots/SIPR/prod/NSS_Root_CA-2.der");
        let cf = CertFile {
            filename: "sipr root".to_string(),
            bytes: ta_bytes.to_vec(),
        };
        ta_store.push(cf);

        let cbor = include_bytes!("../cas/SIPR/prod/prod.cbor");
        let mut cert_source = CertSource::new_from_cbor(cbor)?;
        cert_source.initialize(&Default::default())?;
        pe.add_certificate_source(Box::new(cert_source.clone()));
    }

    if !acted {
        error!("The environment value ({env}) passed to prepare_certval_environment did not match any available features.");
        Err(Error::Unrecognized)
    } else {
        ta_store.initialize()?;
        pe.add_trust_anchor_source(Box::new(ta_store.clone()));
        Ok(())
    }
}

/// Prepares a `Client` instance configured to use CA certificates and trust anchor certificates
/// from the environments configured at compile-time. An optional `Identity` can be provided to use
/// mutually authenticated TLS. Pass `None` as the `identity` parameter for server authenticated TLS.
///
/// ```no_run
/// use std::fs;
/// use pb_pki::get_reqwest_client;
/// use reqwest::header::CONTENT_TYPE;
///
/// let pem_contents : Vec<u8> = fs::read("key.pem").unwrap();
/// let pkcs8 = reqwest::Identity::from_pem(&pem_contents).unwrap();
/// let client = get_reqwest_client(30, Some(pkcs8)).unwrap();
/// ```
pub fn get_reqwest_client(
    timeout_secs: u64,
    identity: Option<Identity>,
) -> Result<Client, reqwest::Error> {
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .use_rustls_tls()
        .connection_verbose(true);

    if let Some(identity) = identity {
        builder = builder.identity(identity);
    }

    #[cfg(feature = "dev")]
    {
        let ta_bytes = include_bytes!("../roots/NIPR/dev/DOD_ENG_Root-3.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse dev/DoDENGRootCA3DoDENGRootCA3: {e:?}"),
        };
        let ta_bytes = include_bytes!("../roots/NIPR/dev/DOD_ENG_Root-6.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse dev/DoDENGRootCA3DoDENGRootCA3: {e:?}"),
        };
    }
    #[cfg(feature = "om_nipr")]
    {
        let ta_bytes = include_bytes!("../roots/NIPR/om/DOD_JITC_Root_CA-3.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse NIPR/om/DoDJITCRootCA3: {e:?}"),
        };

        let ta_bytes = include_bytes!("../roots/NIPR/om/DOD_JITC_Root_CA-6.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse NIPR/om/DoDJITCRootCA6: {e:?}"),
        };
    }
    #[cfg(feature = "om_sipr")]
    {
        let ta_bytes = include_bytes!("../roots/SIPR/om/NSS_JITC_Root_CA-2.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse SIPR/om/NSSJITCRootCA-2: {e:?}"),
        };
    }
    #[cfg(feature = "nipr")]
    {
        let ta_bytes = include_bytes!("../roots/NIPR/prod/DOD_Root_CA-3.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse NIPR/prod/DoDRootCA3: {e:?}"),
        };

        let ta_bytes = include_bytes!("../roots/NIPR/prod/DOD_Root_CA-6.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse NIPR/prod/DoDRootCA6: {e:?}"),
        };
    }
    #[cfg(feature = "sipr")]
    {
        let ta_bytes = include_bytes!("../roots/SIPR/prod/NSS_Root_CA-2.der");
        match reqwest::Certificate::from_der(ta_bytes) {
            Ok(ta_cert) => builder = builder.add_root_certificate(ta_cert),
            Err(e) => error!("Failed to parse SIPR/prod/NSSRootCA-2: {e:?}"),
        };
    }

    match builder.build() {
        Ok(client) => Ok(client),
        Err(e) => {
            error!("Failed to create HTTP Client: {e:?}");
            Err(e)
        }
    }
}

#[cfg(not(any(
    feature = "sipr",
    feature = "om_sipr",
    feature = "dev",
    feature = "om_nipr",
    feature = "nipr"
)))]
compile_error! {
    "At least one of feature \"dev\", \"om\", \"om_nipr\", \"om_sipr\", or \"sipr\" must be enabled for this crate."
}

#[cfg(any(feature = "om_nipr", feature = "nipr"))]
compile_error! {
    "The `om_nipr` and `nipr` features are currently disabled until the CA used in those environments has been updated."
}
