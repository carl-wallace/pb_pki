# Purebred PKI

The `pb_pki` crate contains certification authority (CA) certificates and trust anchor (TA) certificates for various
environments and provides two interfaces for using these resources with the `reqwest` and `certval` crates.

## Features

As with all Purebred apps, information is incorporated into the app for a target environment, i.e., NIPR, SIPR, NIPR test, SIPR test, development.
Unlike apps not written in Rust, a single `pb_pki` build can target multiple environments. Target environments are represented as features
when `pb_pki` is built. The following environment-related features are available:

| Feature  | Description                 |
|----------|-----------------------------|
| dev      | Development environment     |
| om_nipr* | Test environment for NIPR   |
| nipr*    | NIPR production environment |
| om_sipr  | Test environment for SIPR   |
| sipr     | SIPR production environment |

The `dev` feature is the default. At least one environment-related feature must be elected when `pb_pki` is built, else compilation fails.
Features are additive. For example, either of the following commands can be used to produce a `pb_pki` library that targets dev, om_sipr and sipr.
```bash
cargo build --features om_sipr,sipr --release
cargo build --no-default-features --features dev,om_sipr,sipr --release
```
\* NIPR CAs presently return BER-encoded data, which is not supported by Rust applications using this crate. The NIPR features
have been temporarily disabled until the NIPR CAs have been updated and return DER-encoded data.

## Certificates
The CA certificates and TA certificates for each environment are listed below.

### Development NIPR
#### Trust anchor certificates
* DOD_ENG_Root-3.der
* DOD_ENG_Root-6.cer

#### Certification authority certificates
* PB_Derility_CA-3.cer.der
* PB_Email_CA-49.der
* PB_Email_CA-71.der
* PB_ID_CA-49.der
* PB_ID_CA-71.der
* PB_SW_CA-53.der
* PB_SW_CA-75.der

### O&M NIPR
#### Trust anchor certificates
* DOD_JITC_Root_CA-3.der
* DOD_JITC_Root_CA-6.der

#### Certification authority certificates
* DOD_JITC_Derility_CA_3.der
* DOD_JITC_Email_CA-59.der
* DOD_JITC_Email_CA-63.der
* DOD_JITC_Email_CA-65.der
* DOD_JITC_Email_CA-71.der
* DOD_JITC_Email_CA-73.der
* DOD_JITC_ID_CA-59.der
* DOD_JITC_ID_CA-63.der
* DOD_JITC_ID_CA-65.der
* DOD_JITC_ID_CA-71.der
* DOD_JITC_ID_CA-73.der
* DOD_JITC_SW_CA-60.der
* DOD_JITC_SW_CA-61.der
* DOD_JITC_SW_CA-67.der
* DOD_JITC_SW_CA-75.der
* DOD_OM_Derility_CA-1.der
* DOD_OM_Derility_CA_4.der
* DOD_OM_Email_CA-62.der
* DOD_OM_Email_CA-64.der
* DOD_OM_Email_CA-70.der
* DOD_OM_Email_CA-72.der
* DOD_OM_ID_CA-62.der
* DOD_OM_ID_CA-64.der
* DOD_OM_ID_CA-70.der
* DOD_OM_ID_CA-72.der
* DOD_OM_SW_CA-66.der
* DOD_OM_SW_CA-74.der

### NIPR
#### Trust anchor certificates
* DOD_Root_CA-3.der
* DOD_Root_CA-6.der

#### Certification authority certificates
* DOD_Derility_CA-1.der
* DOD_Email_CA-59.der
* DOD_Email_CA-62.der
* DOD_Email_CA-63.der
* DOD_Email_CA-64.der
* DOD_Email_CA-65.der
* DOD_Email_CA-71.der
* DOD_ID_CA-59.der
* DOD_ID_CA-62.der
* DOD_ID_CA-63.der
* DOD_ID_CA-64.der
* DOD_ID_CA-65.der
* DOD_ID_CA-71.der
* DOD_Root_CA_2.der
* DOD_Root_CA_3.der
* DOD_Root_CA_4.der
* DOD_Root_CA_5.der
* DOD_SW_CA-60.der
* DOD_SW_CA-61.der
* DOD_SW_CA-66.der
* DOD_SW_CA-67.der
* DOD_SW_CA-75.der

### O&M SIPR
#### Trust anchor certificates
* NSS_JITC_Root_CA-2.der

#### Certification authority certificates
* NSS_DOD_JITC_Intermediate_CA-1.der
* NSS_DOD_JITC_Intermediate_CA-2.der
* NSS_DOD_JITC_Intermediate_CA-3.der
* NSS_DOD_JITC_Subordinate_CA-3.der
* NSS_DOD_JITC_Subordinate_CA-5.der
* NSS_JITC_CA-2.der
* NSS_JITC_CA-4.der
* NSS_JITC_Derility_CA-1.der
* NSS_JITC_SW_CA-2.der
* NSS_JITC_SW_CA-4.der
* NSS_JITC_SW_CA-6.der
* NSS_JITC_SW_CA-7.der
* NSS_JITC_SW_CA-9.der
* NSS_OM_Derility_CA-2.der
* NSS_OM_SW_CA-10.der
* NSS_OM_SW_CA-8.der

### SIPR
#### Trust anchor certificates
* NSS_Root_CA-2.der

#### Certification authority certificates
* NSS_CA-2.der
* NSS_CA-4.der
* NSS_DOD_Intermediate_CA-1.der
* NSS_DOD_Intermediate_CA-2.der
* NSS_DOD_Intermediate_CA-3.der
* NSS_DOD_Subordinate_CA-3.der
* NSS_DOD_Subordinate_CA-5.der
* NSS_Derility_CA-1.der
* NSS_Derility_CA-2.der
* NSS_Root_CA-1.der
* NSS_Root_CA-2.der
* NSS_Root_CA-4.der
* NSS_SW_CA-10.der
* NSS_SW_CA-2.der
* NSS_SW_CA-4.der
* NSS_SW_CA-6.der
* NSS_SW_CA-7.der
* NSS_SW_CA-8.der
* NSS_SW_CA-9.der

