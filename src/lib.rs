//! A library that can read an eMRTD.
//!
//! A library that can read an eMRTD (Electronic Machine Readable Travel Document).
//!
//! The `emrtd` crate provides a simple API that can be used to communicate with
//! eMRTDs and read the data that resides within them. With the help of `openssl`,
//! it can perform Passive Authentication.
//!
//! **NOTE:**
//! Please note that this crate is provided 'as is' and is not considered production-ready. Use at your own risk.
//!
//! Currently Active Authentication (AA), Chip Authentication (CA), PACE or EAC
//! are **not** supported.
//!
//! Enable the `passive_auth` feature for Passive Authentication (PA), but note
//! that it depends on [`openssl`](https://docs.rs/openssl/latest/openssl/) crate.
//!
//! # Quick Start
//!
//! ```
//! use emrtd::{bytes2hex, get_jpeg_from_ef_dg2, other_mrz, EmrtdComms, EmrtdError};
//! use tracing::{error, info};
//!
//! #[cfg(feature = "passive_auth")]
//! use emrtd::{parse_master_list, passive_authentication, validate_dg};
//!
//! fn main() -> Result<(), EmrtdError> {
//!     tracing_subscriber::fmt()
//!         .with_max_level(tracing::Level::TRACE)
//!         .init();
//!
//!     let doc_no = "DOCUMENT NUMBER";
//!     let birthdate = "BIRTH DATE IN YYMMDD";
//!     let expirydate = "EXPIRY DATE IN YYMMDD";
//!
//!     // Establish a PC/SC context.
//!     let ctx = match pcsc::Context::establish(pcsc::Scope::User) {
//!         Ok(ctx) => ctx,
//!         Err(err) => {
//!             error!("Failed to establish context: {err}");
//!             return Ok(());
//!         }
//!     };
//!
//!     // List available readers.
//!     let mut readers_buf = [0; 2048];
//!     let mut readers = match ctx.list_readers(&mut readers_buf) {
//!         Ok(readers) => readers,
//!         Err(err) => {
//!             error!("Failed to list readers: {err}");
//!             return Ok(());
//!         }
//!     };
//!
//!     // Use the first reader.
//!     let reader = match readers.next() {
//!         Some(reader) => reader,
//!         None => {
//!             error!("No readers are connected.");
//!             return Ok(());
//!         }
//!     };
//!     info!("Using reader: {reader:?}");
//!
//!     // Connect to the card.
//!     let card = match ctx.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY) {
//!         Ok(card) => card,
//!         Err(pcsc::Error::NoSmartcard) => {
//!             error!("A smartcard is not present in the reader.");
//!             return Ok(());
//!         }
//!         Err(err) => {
//!             error!("Failed to connect to card: {err}");
//!             return Ok(());
//!         }
//!     };
//!
//!     let mut sm_object = EmrtdComms::<pcsc::Card>::new(card);
//!
//!     // Get the card's ATR.
//!     info!("ATR from attribute: {}", bytes2hex(&sm_object.get_atr()?));
//!
//!     // Read EF.CardAccess
//!     sm_object.select_ef(b"\x01\x1C", "EF.CardAccess", false)?;
//!     let ef_cardacess = sm_object.read_data_from_ef(false)?;
//!     info!("Data from the EF.CardAccess: {}", bytes2hex(&ef_cardacess));
//!
//!     // Read EF.DIR
//!     // let ef_dir = sm_object.read_data_from_ef(b"\x2F\x00", "EF.DIR");
//!     // info!("Data from the EF.DIR: {}", bytes2hex(&ef_dir));
//!
//!     // Select eMRTD application
//!     sm_object.select_emrtd_application()?;
//!
//!     let secret = match other_mrz(&doc_no, &birthdate, &expirydate) {
//!         Ok(secret) => secret,
//!         Err(EmrtdError) => {
//!             error!("Invalid MRZ string.");
//!             return Ok(());
//!         }
//!     };
//!
//!     sm_object.establish_bac_session_keys(secret.as_bytes())?;
//!
//!     // Read EF.COM
//!     sm_object.select_ef(b"\x01\x1E", "EF.COM", true)?;
//!     let ef_com = sm_object.read_data_from_ef(true)?;
//!     info!("Data from the EF.COM: {}", bytes2hex(&ef_com));
//!
//!     // Read EF.SOD
//!     sm_object.select_ef(b"\x01\x1D", "EF.SOD", true)?;
//!     let ef_sod = sm_object.read_data_from_ef(true)?;
//!     info!("Data from the EF.SOD: {}", bytes2hex(&ef_sod));
//!
//!     let result;
//!     #[cfg(feature = "passive_auth")]
//!     {
//!         let master_list = include_bytes!("../data/DE_ML_2024-04-10-10-54-13.ml");
//!         let csca_cert_store = parse_master_list(master_list)?;
//!         result = passive_authentication(&ef_sod, &csca_cert_store).unwrap();
//!         info!("{:?} {:?} {:?}", result.0.type_(), result.1, result.2);
//!     }
//!
//!     // Read EF.DG1
//!     sm_object.select_ef(b"\x01\x01", "EF.DG1", true)?;
//!     let ef_dg1 = sm_object.read_data_from_ef(true)?;
//!     info!("Data from the EF.DG1: {}", bytes2hex(&ef_dg1));
//!     #[cfg(feature = "passive_auth")]
//!     validate_dg(&ef_dg1, 1, result.0, &result.1)?;
//!
//!     // Read EF.DG2
//!     sm_object.select_ef(b"\x01\x02", "EF.DG2", true)?;
//!     let ef_dg2 = sm_object.read_data_from_ef(true)?;
//!     info!("Data from the EF.DG2: {}", bytes2hex(&ef_dg2));
//!     #[cfg(feature = "passive_auth")]
//!     validate_dg(&ef_dg2, 2, result.0, &result.1)?;
//!
//!     let jpeg = get_jpeg_from_ef_dg2(&ef_dg2)?;
//!     std::fs::write("face.jpg", jpeg).expect("Error writing file");
//!
//!     return Ok(());
//! }
//! ```

#![forbid(unsafe_code)]

extern crate alloc;
use alloc::{borrow::ToOwned, collections::BTreeMap, format, string::String, vec, vec::Vec};
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use constant_time_eq::constant_time_eq;
use core::{
    fmt::{self, Debug, Write},
    iter, mem,
};
#[cfg(feature = "passive_auth")]
use openssl::{
    hash::{hash, MessageDigest},
    sign::Verifier,
    stack::Stack,
    x509::{
        store::{X509Store, X509StoreBuilder},
        X509StoreContext, X509,
    },
};
use pcsc::{Attribute::AtrString, Card};
use rand::{rngs::OsRng, CryptoRng, RngCore};
#[cfg(feature = "passive_auth")]
use rasn::{der, types::Oid};
#[cfg(feature = "passive_auth")]
use rasn_cms::{CertificateChoices, RevocationInfoChoice};
use sha1_checked::Sha1;
use sha2::{Digest, Sha256};
use std::num::TryFromIntError;
#[cfg(feature = "passive_auth")]
use tracing::warn;
use tracing::{error, info, trace};

#[derive(Debug)]
#[non_exhaustive]
pub enum EmrtdError {
    RecvApduError(u8, u8),
    ParseMrzCharError(char),
    ParseMrzFieldError(&'static str, String),
    ParseAsn1DataError(usize, usize),
    InvalidMacKeyError(usize, usize),
    ParseDataError(String),
    InvalidArgument(&'static str),
    VerifyMacError(),
    InvalidResponseError(),
    OverflowSscError(),
    InvalidOidError(),
    ParseAsn1TagError(String, String),
    InvalidFileStructure(&'static str),
    VerifySignatureError(&'static str),
    VerifyHashError(String),
    CalculateHashError(&'static str),
    PcscError(pcsc::Error),
    #[cfg(feature = "passive_auth")]
    OpensslErrorStack(openssl::error::ErrorStack),
    #[cfg(feature = "passive_auth")]
    RasnEncodeError(rasn::error::EncodeError),
    #[cfg(feature = "passive_auth")]
    RasnDecodeError(rasn::error::DecodeError),
    PadError(cipher::inout::PadError),
    UnpadError(cipher::block_padding::UnpadError),
    IntCastError(TryFromIntError),
}
impl fmt::Display for EmrtdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::RecvApduError(ref sw1, ref sw2) => write!(
                f,
                "APDU command failed with status code: {sw1:02X} {sw2:02X}"
            ),
            Self::ParseMrzCharError(ref c) => {
                write!(f, "MRZ can not contain the character: {c}")
            }
            Self::ParseMrzFieldError(mrz_field, ref value) => {
                write!(f, "MRZ field {mrz_field} is invalid: {value}")
            }
            Self::ParseAsn1DataError(ref e_len, ref f_len) => write!(
                f,
                "ASN.1 data is incomplete, expected len: {e_len}, found len: {f_len}"
            ),
            Self::InvalidMacKeyError(ref e_len, ref f_len) => write!(
                f,
                "Invalid MAC key, expected len: {e_len}, found len: {f_len}"
            ),
            Self::ParseDataError(ref error) => write!(f, "Invalid data length: {error}"),
            Self::InvalidArgument(error_msg) => write!(f, "Invalid argument: {error_msg}"),
            Self::VerifyMacError() => {
                write!(f, "Encrypted message MAC is not correct")
            }
            Self::InvalidResponseError() => {
                write!(f, "Card response is invalid")
            }
            Self::OverflowSscError() => write!(f, "SSC overflew error"),
            Self::InvalidOidError() => write!(f, "Invalid OID given"),
            Self::ParseAsn1TagError(ref expected, ref found) => {
                write!(f, "Invalid ASN.1 tag, expected: {expected}, found: {found}")
            }
            Self::InvalidFileStructure(error_msg) => {
                write!(f, "Invalid EF structure: {error_msg}")
            }
            Self::VerifySignatureError(error_msg) => {
                write!(f, "Signature verification failure: {error_msg}")
            }
            Self::VerifyHashError(ref error_msg) => {
                write!(f, "Failure during comparison of hashes: {error_msg}")
            }
            Self::CalculateHashError(error_msg) => {
                write!(f, "Failure during calculation of hashes: {error_msg}")
            }
            Self::PcscError(ref e) => fmt::Display::fmt(&e, f),
            #[cfg(feature = "passive_auth")]
            Self::OpensslErrorStack(ref e) => fmt::Display::fmt(&e, f),
            #[cfg(feature = "passive_auth")]
            Self::RasnEncodeError(ref e) => fmt::Display::fmt(&e, f),
            #[cfg(feature = "passive_auth")]
            Self::RasnDecodeError(ref e) => fmt::Display::fmt(&e, f),
            Self::PadError(ref e) => fmt::Display::fmt(&e, f),
            Self::UnpadError(ref e) => fmt::Display::fmt(&e, f),
            Self::IntCastError(ref e) => fmt::Display::fmt(&e, f),
        }
    }
}
// TODO, change to core::error soon, hopefully?
impl std::error::Error for EmrtdError {}

#[derive(Debug)]
pub enum KeyType {
    Encryption,
    Mac,
}

#[derive(Debug)]
pub enum EncryptionAlgorithm {
    DES3,
    AES128,
    AES192,
    AES256,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MacAlgorithm {
    DES,
    AESCMAC,
}

/// Generated and edited using `rasn_compiler`
/// <https://librasn.github.io>
/// <https://docs.rs/rasn-compiler/latest/rasn_compiler/>
///
#[allow(clippy::doc_markdown)]
/// LDSSecurityObjectV1 { joint-iso-itu-t(2) international(23) icao(136) mrtd(1) security(1) ldsSecurityObject(1)}
///
/// DEFINITIONS IMPLICIT TAGS ::= BEGIN
/// -- Constants
/// ub-DataGroups INTEGER ::= 16
/// -- Object Identifiers
/// id-icao OBJECT IDENTIFIER::={joint-iso-itu-t(2) international(23) icao(136) }
/// id-icao-mrtd OBJECT IDENTIFIER ::= {id-icao 1}
/// id-icao-mrtd-security OBJECT IDENTIFIER ::= {id-icao-mrtd 1}
/// id-icao-mrtd-security-ldsSecurityObject OBJECT IDENTIFIER ::= {id-icao-mrtd-security 1}
///
/// -- LDS Security Object
/// LDSSecurityObjectVersion ::= INTEGER {v0(0), v1(1)
/// -- If LDSSecurityObjectVersion is V1, ldsVersionInfo MUST be present
/// }
/// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
///
/// LDSSecurityObject ::= SEQUENCE {
/// version LDSSecurityObjectVersion,
/// hashAlgorithm DigestAlgorithmIdentifier,
/// dataGroupHashValues SEQUENCE SIZE (2..ub-DataGroups) OF
/// DataGroupHash,
/// ldsVersionInfo LDSVersionInfo OPTIONAL
/// -- If present, version MUST be V1
/// }
/// DataGroupHash ::= SEQUENCE {
/// dataGroupNumber DataGroupNumber,
/// dataGroupHashValue OCTET STRING }
///
/// DataGroupHash ::= SEQUENCE {
/// dataGroupNumber DataGroupNumber,
/// dataGroupHashValue OCTET STRING }
/// DataGroupNumber ::= INTEGER {
/// dataGroup1 (1),
/// dataGroup2 (2),
/// dataGroup3 (3),
/// dataGroup4 (4),
/// dataGroup5 (5),
/// dataGroup6 (6),
/// dataGroup7 (7),
/// dataGroup8 (8),
/// dataGroup9 (9),
/// dataGroup10 (10),
/// dataGroup11 (11),
/// dataGroup12 (12),
/// dataGroup13 (13),
/// dataGroup14 (14),
/// dataGroup15 (15),
/// dataGroup16 (16)}
///
/// LDSVersionInfo ::= SEQUENCE {
/// ldsVersion PrintableString
/// unicodeVersion PrintableString }
///
/// END
///
#[cfg(feature = "passive_auth")]
pub mod lds_security_object {
    extern crate alloc;
    use rasn::prelude::*;
    use rasn_cms::AlgorithmIdentifier;

    pub type DataGroupNumber = Integer;
    pub type DigestAlgorithmIdentifier = AlgorithmIdentifier;
    pub type LDSSecurityObjectVersion = Integer;

    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    pub struct DataGroupHash {
        pub data_group_number: DataGroupNumber,
        pub data_group_hash_value: OctetString,
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    pub struct LDSSecurityObject {
        pub version: LDSSecurityObjectVersion,
        pub hash_algorithm: DigestAlgorithmIdentifier,
        #[rasn(size("2..=16"))]
        pub data_group_hash_values: SequenceOf<DataGroupHash>,
        pub lds_version_info: Option<LDSVersionInfo>,
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    pub struct LDSVersionInfo {
        pub lds_version: PrintableString,
        pub unicode_version: PrintableString,
    }
}

/// Generated and edited using `rasn_compiler`
/// <https://librasn.github.io>
/// <https://docs.rs/rasn-compiler/latest/rasn_compiler/>
///
#[allow(clippy::doc_markdown)]
/// CscaMasterList { joint-iso-itu-t(2) international-organization(23) icao(136) mrtd(1) security(1) masterlist(2)}
///
/// DEFINITIONS IMPLICIT TAGS ::= BEGIN
/// IMPORTS
/// Certificate FROM PKIX1Explicit88 { iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) pkix(7) mod(0) pkix1-explicit(18) };
///
/// -- CSCA Master List
///
/// CscaMasterListVersion ::= INTEGER {v0(0)}
/// CscaMasterList ::= SEQUENCE {
/// version CscaMasterListVersion,
/// certList SET OF Certificate }
///
/// -- Object Identifiers
///
/// id-icao-cscaMasterList OBJECT IDENTIFIER ::= {id-icao-mrtd-security 2}
/// id-icao-cscaMasterListSigningKey OBJECT IDENTIFIER ::= {id-icao-mrtd-security 3}
/// END
///
#[cfg(feature = "passive_auth")]
pub mod csca_master_list {
    extern crate alloc;
    use rasn::prelude::*;
    use rasn_pkix::Certificate;

    pub type CscaMasterListCertList = SetOf<Certificate>;
    pub type CscaMasterListVersion = Integer;

    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq)]
    pub struct CscaMasterList {
        pub version: CscaMasterListVersion,
        pub cert_list: CscaMasterListCertList,
    }
}

/// Calculates the check digit for the given data using a specific algorithm.
/// Calculation is explained at ICAO Doc 9303-3 Section 4.9:
/// <https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf>
///
/// # Arguments
///
/// * `data` - Data for which the check digit needs to be calculated.
///
/// # Returns
///
/// Result containing the calculated check digit or an `EmrtdError`.
///
/// # Errors
///
/// * `EmrtdError` if an invalid character is given.
fn calculate_check_digit(data: &str) -> Result<char, EmrtdError> {
    #[rustfmt::skip]
    let values: BTreeMap<char, u32> = [
        ('0', 0), ('1', 1), ('2', 2), ('3', 3), ('4', 4), ('5', 5), ('6', 6), ('7', 7),
        ('8', 8), ('9', 9), ('<', 0), ('A', 10), ('B', 11), ('C', 12), ('D', 13), ('E', 14),
        ('F', 15), ('G', 16), ('H', 17), ('I', 18), ('J', 19), ('K', 20), ('L', 21), ('M', 22),
        ('N', 23), ('O', 24), ('P', 25), ('Q', 26), ('R', 27), ('S', 28), ('T', 29), ('U', 30),
        ('V', 31), ('W', 32), ('X', 33), ('Y', 34), ('Z', 35),
    ]
    .iter()
    .copied()
    .collect();

    let weights = [7, 3, 1];
    let mut total = 0;

    for (counter, value) in data.chars().enumerate() {
        if let Some(weighted_value) = values.get(&value).copied() {
            total += weights[counter % 3] * weighted_value;
        } else {
            error!("Can not calculate check digit for invalid character: `{value}`");
            return Err(EmrtdError::ParseMrzCharError(value));
        }
    }

    let check_digit =
        char::from_digit(total % 10, 10).expect("usize % 10 can not be greater than 10");
    Ok(check_digit)
}

/// Manually calculates the MRZ (Machine Readable Zone) string for BAC (Basic Access Control).
///
/// This function takes document number, birthdate, and expiry date as input, and calculates
/// the MRZ string by appending check digits to each corresponding input.
///
/// # Arguments
///
/// * `doc_no` - Document number for MRZ calculation.
/// * `birthdate` - Birthdate for MRZ calculation.
/// * `expirydate` - Expiry date for MRZ calculation.
///
/// # Returns
///
/// Result containing a formatted MRZ string suitable for use in BAC (Basic Access Control) or an `EmrtdError`.
///
/// # Errors
///
/// * `EmrtdError` if MRZ field length is invalid or contains invalid characters
///
/// # Example
///
/// ```
/// # use emrtd::EmrtdError;
/// #
/// # fn main() -> Result<(), EmrtdError> {
/// use emrtd::other_mrz;
/// let result = other_mrz("L898902C3", "740812", "120415")?;
/// assert_eq!(result, String::from("L898902C3674081221204159"));
/// #
/// #     Ok(())
/// # }
/// ```
pub fn other_mrz(doc_no: &str, birthdate: &str, expirydate: &str) -> Result<String, EmrtdError> {
    // Document number can be up to 9 characters on TD3 sized eMRTDs (https://www.icao.int/publications/Documents/9303_p4_cons_en.pdf Appendix B)
    // Document number can be up to 22 characters on TD1 sized eMRTDs (https://www.icao.int/publications/Documents/9303_p5_cons_en.pdf 4.2.2)
    // Document number can be up to 14 characters on TD2 sized eMRTDs (https://www.icao.int/publications/Documents/9303_p6_cons_en.pdf 4.2.2.2)
    if doc_no.len() > 22
        || doc_no
            .chars()
            .any(|c| !"0123456789<ABCDEFGHIJKLMNOPQRSTUVWXYZ".contains(c))
    {
        error!("Error during other_mrz, document number length must be less than 23 and should not contain illegal characters, received {doc_no}");
        return Err(EmrtdError::ParseMrzFieldError(
            "Document number",
            doc_no.to_owned(),
        ));
    }
    if birthdate.len() != 6
        || birthdate
            .chars()
            .any(|c| !"0123456789<ABCDEFGHIJKLMNOPQRSTUVWXYZ".contains(c))
    {
        error!("Error during other_mrz, birth date length must be 6 and should not contain illegal characters, received {birthdate}");
        return Err(EmrtdError::ParseMrzFieldError(
            "Birth date",
            birthdate.to_owned(),
        ));
    }
    if expirydate.len() != 6
        || expirydate
            .chars()
            .any(|c| !"0123456789<ABCDEFGHIJKLMNOPQRSTUVWXYZ".contains(c))
    {
        error!("Error during other_mrz, expiry date length must be 6 and should not contain illegal characters, received {expirydate}");
        return Err(EmrtdError::ParseMrzFieldError(
            "Expiry date",
            expirydate.to_owned(),
        ));
    }

    let formatted_mrz = format!(
        "{:<9}{}{}{}{}{}",
        doc_no,
        calculate_check_digit(doc_no)?,
        birthdate,
        calculate_check_digit(birthdate)?,
        expirydate,
        calculate_check_digit(expirydate)?
    );

    Ok(formatted_mrz)
}

/// Helper function that converts a byte slice into a hex string.
///
/// # Arguments
///
/// * `bytes` - Bytes to be converted to a hex string.
///
/// # Returns
///
/// A hex string representation of the input bytes.
///
/// # Example
///
/// ```
/// # use emrtd::EmrtdError;
/// #
/// # fn main() -> Result<(), EmrtdError> {
/// use emrtd::bytes2hex;
/// let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
/// let hex_string = bytes2hex(&bytes);
/// assert_eq!(hex_string, "DEADBEEF");
/// #
/// #     Ok(())
/// # }
/// ```
#[must_use]
pub fn bytes2hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, &byte| {
        write!(&mut acc, "{byte:02X}").expect("Failed to write to string");
        acc
    })
}

/// Parses the ASN.1 length field.
///
/// ASN.1 length encoding can use a single byte for short lengths (up to 127) or multiple bytes
/// for longer lengths.
///
/// # Arguments
///
/// * `data` - The ASN.1 data.
/// * `tag_len` - Length of ASN.1 tag (T of TLV).
///
/// # Returns
///
/// Result containing a tuple with the start index and length field value, or an `EmrtdError`.
///
/// For example, if `tag_len` is 3 and the length field is a single byte with value 42,
/// the returned value will be (4, 42).
///
/// If `tag_len` is 3 and the length field is 3 bytes long with value 2024,
/// the returned value will be (6, 2024).
///
/// # Errors
///
/// * `EmrtdError` if the input is incomplete, i.e. if the data is too short to read the length value.
fn len2int(data: &[u8], tag_len: usize) -> Result<(usize, usize), EmrtdError> {
    if data.len() < tag_len + 1 {
        error!(
            "Error during len2int, `data.len()`: `{}` is less than `tag_len`: `{}`",
            data.len(),
            tag_len
        );
        return Err(EmrtdError::ParseAsn1DataError(tag_len + 1, data.len()));
    }

    if data[tag_len] & 0x80 == 0 {
        Ok((tag_len + 1, data[tag_len] as usize))
    } else {
        let length_of_length = ((1 << 7) ^ data[tag_len]) as usize;

        if data.len() < tag_len + 1 + length_of_length {
            error!("Error during len2int, `data.len()`: `{}` is less than `tag_len + 1 + length_of_length`: `{}`", data.len(), tag_len + 1 + length_of_length);
            return Err(EmrtdError::ParseAsn1DataError(
                tag_len + 1 + length_of_length,
                data.len(),
            ));
        }

        let mut buf = [0_u8; mem::size_of::<usize>()];
        buf[mem::size_of::<usize>() - length_of_length..]
            .copy_from_slice(&data[tag_len + 1..tag_len + 1 + length_of_length]);

        Ok((tag_len + 1 + length_of_length, usize::from_be_bytes(buf)))
    }
}

/// Encodes the length field in ASN.1 format.
///
/// If the length is less than 128, a single octet is used to represent the length.
/// Otherwise, the long form is used, where the first octet specifies the number of
/// octets used for the length, followed by the length encoded in big-endian order.
///
/// # Arguments
///
/// * `length` - The length to be encoded.
///
/// # Returns
///
/// The ASN.1 encoded length.
///
/// # Panics
/// Should not panic.
///
/// # Examples
///
/// ```
/// # use emrtd::EmrtdError;
/// #
/// # fn main() -> Result<(), EmrtdError> {
/// use emrtd::int2asn1len;
/// use hex_literal::hex;
///
/// let result = int2asn1len(0);
/// assert_eq!(result, hex!("00").to_vec());
///
/// let result = int2asn1len(42);
/// assert_eq!(result, hex!("2A").to_vec());
///
/// let result = int2asn1len(127);
/// assert_eq!(result, hex!("7F").to_vec());
///
/// let result = int2asn1len(2024);
/// assert_eq!(result, hex!("8207E8").to_vec());
///
/// let result = int2asn1len(65536);
/// assert_eq!(result, hex!("83010000").to_vec());
///
/// let result = int2asn1len(usize::MAX);
/// assert_eq!(result, hex!("88FFFFFFFFFFFFFFFF").to_vec());
/// #
/// #     Ok(())
/// # }
/// ```
#[must_use]
pub fn int2asn1len(length: usize) -> Vec<u8> {
    if length < 128 {
        vec![u8::try_from(length).expect("`length` is less than 128")]
    } else {
        let mut length_bytes: Vec<u8> = Vec::new();
        let mut len = length;

        let mut octet_count: u8 = 0;
        while len > 0 {
            octet_count += 1;
            len >>= 8;
        }
        length_bytes.push(0x80 | octet_count);
        for i in (0..octet_count).rev() {
            let masked_bits = (length >> (8 * i)) & 0xFF;
            length_bytes
                .push(u8::try_from(masked_bits).expect("Bits are masked, must fit in a u8"));
        }
        length_bytes
    }
}

/// Generates a key seed from the given secret.
///
/// Calculates the SHA-1 of `secret` and returns the result.
///
/// Calculation is explained at ICAO Doc 9303-11 Section 4.3.2:
/// <https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf>
///
/// # Arguments
///
/// * `secret` - The secret from which to generate the key seed.
///
/// # Returns
///
/// The generated key seed if successful.
///
/// # Errors
///
/// `EmrtdError` if 'SHA1' fails.
fn generate_key_seed(secret: &[u8]) -> Result<Vec<u8>, EmrtdError> {
    let hash_result = Sha1::try_digest(secret);
    if hash_result.has_collision() {
        error!("SHA1 hash calculation during generate_key_seed had collision");
        return Err(EmrtdError::CalculateHashError(
            "SHA1 hash calculation during generate_key_seed had collision",
        ));
    }
    Ok(hash_result.hash().as_slice().to_vec())
}

/// Encrypts data using the specified block cipher and mode.
///
/// # Arguments
///
/// * `key` - The encryption key.
/// * `iv` - An optional initialization vector.
/// * `data` - The data to be encrypted.
///
/// # Returns
///
/// Encrypted data if successful.
///
/// # Errors
///
/// `EmrtdError` if encryption fails.
fn encrypt<CM>(key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, EmrtdError>
where
    CM: BlockEncryptMut + KeyIvInit,
{
    if key.len() != CM::key_size() {
        error!(
            "Wrong key size for cipher encryption, expected {}, found {}",
            CM::key_size(),
            key.len()
        );
        return Err(EmrtdError::InvalidArgument(
            "Wrong key size for cipher encryption",
        ));
    }
    if let Some(iv) = iv {
        if iv.len() != CM::iv_size() {
            error!(
                "Wrong IV size for cipher encryption, expected {}, found {}",
                CM::iv_size(),
                iv.len()
            );
            return Err(EmrtdError::InvalidArgument(
                "Wrong IV size for cipher encryption",
            ));
        }
    }
    if data.len() % CM::block_size() != 0 {
        error!(
            "Wrong data size for cipher encryption, expected {}, found {}",
            CM::block_size(),
            data.len()
        );
        return Err(EmrtdError::InvalidArgument(
            "Wrong data size for cipher encryption",
        ));
    }

    Ok(CM::new(key.into(), iv.unwrap_or_default().into())
        .encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data))
}

/// Encrypts data using the specified block cipher in Electronic Codebook (ECB) mode.
///
/// # Arguments
///
/// * `key` - The encryption key.
/// * `data` - The data to be encrypted.
///
/// # Returns
///
/// Encrypted data if successful.
///
/// # Errors
///
/// `EmrtdError` if encryption fails.
fn encrypt_ecb<CM>(key: &[u8], data: &[u8]) -> Result<Vec<u8>, EmrtdError>
where
    CM: BlockEncryptMut + KeyInit,
{
    if key.len() != CM::key_size() {
        error!(
            "Wrong key size for cipher encryption, expected {}, found {}",
            CM::key_size(),
            key.len()
        );
        return Err(EmrtdError::InvalidArgument(
            "Wrong key size for cipher encryption",
        ));
    }
    if data.len() % CM::block_size() != 0 {
        error!(
            "Wrong data size for cipher encryption, expected {}, found {}",
            CM::block_size(),
            data.len()
        );
        return Err(EmrtdError::InvalidArgument(
            "Wrong data size for cipher encryption",
        ));
    }

    Ok(CM::new(key.into()).encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data))
}

/// Decrypts data using the specified block cipher and mode.
///
/// # Arguments
///
/// * `key` - The decryption key.
/// * `iv` - An optional initialization vector.
/// * `data` - The data to be decrypted.
///
/// # Returns
///
/// Decrypted data if successful.
///
/// # Errors
///
/// `EmrtdError` if decryption fails.
fn decrypt<CM>(key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, EmrtdError>
where
    CM: BlockDecryptMut + KeyIvInit,
{
    if key.len() != CM::key_size() {
        error!(
            "Wrong key size for cipher decryption, expected {}, found {}",
            CM::key_size(),
            key.len()
        );
        return Err(EmrtdError::InvalidArgument(
            "Wrong key size for cipher decryption",
        ));
    }
    if let Some(iv) = iv {
        if iv.len() != CM::iv_size() {
            error!(
                "Wrong IV size for cipher decryption, expected {}, found {}",
                CM::iv_size(),
                iv.len()
            );
            return Err(EmrtdError::InvalidArgument(
                "Wrong IV size for cipher decryption",
            ));
        }
    }
    if data.len() % CM::block_size() != 0 {
        error!(
            "Wrong data size for cipher decryption, expected {}, found {}",
            CM::block_size(),
            data.len()
        );
        return Err(EmrtdError::InvalidArgument(
            "Wrong data size for cipher decryption",
        ));
    }

    CM::new(key.into(), iv.unwrap_or_default().into())
        .decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data)
        .map_err(EmrtdError::UnpadError)
}

/// Decrypts data using the specified block cipher in Electronic Codebook (ECB) mode.
///
/// # Arguments
///
/// * `key` - The decryption key.
/// * `data` - The data to be decrypted.
///
/// # Returns
///
/// Decrypted data if successful.
///
/// # Errors
///
/// `EmrtdError` if decryption fails.
fn decrypt_ecb<CM>(key: &[u8], data: &[u8]) -> Result<Vec<u8>, EmrtdError>
where
    CM: BlockDecryptMut + KeyInit,
{
    if key.len() != CM::key_size() {
        error!(
            "Wrong key size for cipher decryption, expected {}, found {}",
            CM::key_size(),
            key.len()
        );
        return Err(EmrtdError::InvalidArgument(
            "Wrong key size for cipher decryption",
        ));
    }
    if data.len() % CM::block_size() != 0 {
        error!(
            "Wrong data size for cipher decryption, expected {}, found {}",
            CM::block_size(),
            data.len()
        );
        return Err(EmrtdError::InvalidArgument(
            "Wrong data size for cipher decryption, expected {}, found {}",
        ));
    }

    CM::new(key.into())
        .decrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(data)
        .map_err(EmrtdError::UnpadError)
}

/// Computes a key based on the given key seed, key type, and encryption algorithm.
///
/// For calculation examples see ICAO Doc 9303-11 Appendix D.1:
/// <https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf>
///
/// # Arguments
///
/// * `key_seed` - The key seed.
/// * `key_type` - The type of the key (Encryption or Mac) to be created.
/// * `alg` - The encryption algorithm to be used (DES3, AES128, AES192, or AES256).
///
/// # Returns
///
/// Result containing the computed 3DES or AES key if successful.
///
/// # Errors
///
/// `EmrtdError` key computation fails.
fn compute_key(
    key_seed: &[u8],
    key_type: &KeyType,
    alg: &EncryptionAlgorithm,
) -> Result<Vec<u8>, EmrtdError> {
    let c: &[u8] = match *key_type {
        KeyType::Encryption => b"\x00\x00\x00\x01",
        KeyType::Mac => b"\x00\x00\x00\x02",
    };

    let mut d = key_seed.to_vec();
    d.extend_from_slice(c);

    match alg {
        EncryptionAlgorithm::DES3 => {
            let hash_result = Sha1::try_digest(&d);
            if hash_result.has_collision() {
                error!("SHA1 hash calculation during 3DES compute_key had collision");
                return Err(EmrtdError::CalculateHashError(
                    "SHA1 hash calculation during 3DES compute_key had collision",
                ));
            }
            let hash_bytes = hash_result.hash().as_slice().to_vec();
            let key_1_2 = des3_adjust_parity_bits(hash_bytes.iter().copied().take(16).collect());
            match *key_type {
                KeyType::Encryption => Ok([&key_1_2[..], &key_1_2[..8]].concat()),
                KeyType::Mac => Ok(key_1_2),
            }
        }
        EncryptionAlgorithm::AES128 => {
            let hash_result = Sha1::try_digest(&d);
            if hash_result.has_collision() {
                error!("SHA1 hash calculation during AES-128 compute_key had collision");
                return Err(EmrtdError::CalculateHashError(
                    "SHA1 hash calculation during AES-128 compute_key had collision",
                ));
            }
            let hash_bytes = hash_result.hash().as_slice().to_vec();
            Ok(hash_bytes.iter().copied().take(16).collect())
        }
        EncryptionAlgorithm::AES192 => {
            let hash_result = Sha256::digest(&d);
            let hash_bytes = hash_result.as_slice().to_vec();
            Ok(hash_bytes.iter().copied().take(24).collect())
        }
        EncryptionAlgorithm::AES256 => {
            let hash_result = Sha256::digest(&d);
            let hash_bytes = hash_result.as_slice().to_vec();
            Ok(hash_bytes)
        }
    }
}

/// Computes a MAC of data using the given key and MAC algorithm.
///
/// # Arguments
///
/// * `key` - The MAC key.
/// * `data` - The data to calculate the MAC of.
/// * `alg` - The MAC algorithm to be used (DES or AES-CMAC).
///
/// # Returns
///
/// Result containing the computed MAC or an `EmrtdError`.
///
/// # Errors
///
/// * `EmrtdError` if `key` or `data` length is wrong or cipher operation fails.
fn compute_mac(key: &[u8], data: &[u8], alg: &MacAlgorithm) -> Result<Vec<u8>, EmrtdError> {
    match *alg {
        MacAlgorithm::DES => {
            if key.len() != 16 {
                error!("Can not compute MAC, MAC key is invalid.");
                return Err(EmrtdError::InvalidMacKeyError(16, key.len()));
            }

            if data.len() % 8 != 0 {
                error!("Can not compute MAC, data length is invalid.");
                return Err(EmrtdError::ParseDataError(format!(
                    "MAC calculation should be a multiple of 8, but found {}",
                    key.len()
                )));
            }

            let key1 = &key[..8];
            let key2 = &key[8..];

            let mut h = encrypt_ecb::<ecb::Encryptor<des::Des>>(key1, &data[..8])?;

            for i in 1..(data.len() / 8) {
                h = encrypt_ecb::<ecb::Encryptor<des::Des>>(
                    key1,
                    &xor_slices(&h, &data[8 * i..8 * (i + 1)])?,
                )?;
            }

            let mac_x = encrypt_ecb::<ecb::Encryptor<des::Des>>(
                key1,
                &decrypt_ecb::<ecb::Decryptor<des::Des>>(key2, &h)?,
            )?;

            Ok(mac_x)
        }
        MacAlgorithm::AESCMAC => {
            unimplemented!("AES-CMAC MAC calculation is not yet implemented");
        }
    }
}

/// XORs two byte slices and returns the result.
///
/// # Arguments
///
/// * `a` - First input.
/// * `b` - Second input.
///
/// # Returns
///
/// Result containing the `XORed` result or an `EmrtdError`.
///
/// # Errors
///
/// * `EmrtdError` if input `a` and `b` have different lengths.
fn xor_slices(a: &[u8], b: &[u8]) -> Result<Vec<u8>, EmrtdError> {
    if a.len() == b.len() {
        let result: Vec<u8> = a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect();
        return Ok(result);
    }
    error!(
        "XORed slices must have the same length, found {}, {}",
        a.len(),
        b.len()
    );
    Err(EmrtdError::ParseDataError(format!(
        "XORed slices must have the same length, found {}, {}",
        a.len(),
        b.len()
    )))
}

/// Pads the input data using padding method 2.
///
/// <https://en.wikipedia.org/wiki/ISO/IEC_9797-1#Padding_method_2>
///
/// # Arguments
///
/// * `data` - Data to be padded.
/// * `pad_to` - Length to pad to.
///
/// # Returns
///
/// Padded data or an `EmrtdError` if `pad_to` is 0.
///
/// # Errors
///
/// * `EmrtdError` if `pad_to` is 0.
fn padding_method_2(data: &[u8], pad_to: usize) -> Result<Vec<u8>, EmrtdError> {
    if pad_to == 0 {
        error!("pad_to must be greater than 0, found {}", pad_to);
        return Err(EmrtdError::InvalidArgument("pad_to must be greater than 0"));
    }

    let mut data = data.to_vec();
    data.push(0x80);
    if data.len() % pad_to != 0 {
        let padding_len = pad_to - (data.len() % pad_to);
        data.extend(iter::repeat(0).take(padding_len));
    }
    Ok(data)
}

/// Removes the padding added by padding method 2 from the input data.
///
/// <https://en.wikipedia.org/wiki/ISO/IEC_9797-1#Padding_method_2>
///
/// # Arguments
///
/// * `data` - The padded data.
///
/// # Returns
///
/// If the padding exists, data with the padding removed, otherwise original data.
fn remove_padding(data: &[u8]) -> &[u8] {
    for (i, &b) in data.iter().rev().enumerate() {
        if b == 0x80 {
            return &data[..data.len() - 1 - i];
        }
    }
    data
}

/// Adjusts the parity bits of a 3DES key.
///
/// # Arguments
///
/// * `key` - The 3DES key.
///
/// # Returns
///
/// 3DES key with adjusted parity bits.
fn des3_adjust_parity_bits(mut key: Vec<u8>) -> Vec<u8> {
    for byte in &mut key {
        let mut bitmask = 1;
        let mut b = *byte;
        for _ in 0..8 {
            bitmask ^= b & 0x1;
            b >>= 1;
        }
        *byte ^= bitmask;
    }
    key
}

/// Convert an OID (Object Identifier) byte array to its corresponding digest algorithm name.
///
/// # Arguments
///
/// * `oid` - OID.
///
/// # Returns
///
/// The name of the digest algorithm if the OID is recognized, else an `EmrtdError`.
///
/// # Errors
///
/// * `EmrtdError` if an unsupported OID is given.
#[cfg(feature = "passive_auth")]
fn oid2digestalg(oid: &rasn::types::ObjectIdentifier) -> Result<MessageDigest, EmrtdError> {
    let digest_alg_oid_dict: [(&Oid, MessageDigest); 6] = [
        (
            Oid::const_new(&[2, 16, 840, 1, 101, 3, 4, 2, 4]),
            MessageDigest::sha224(),
        ),
        (
            Oid::const_new(&[2, 16, 840, 1, 101, 3, 4, 2, 3]),
            MessageDigest::sha512(),
        ),
        (
            Oid::const_new(&[2, 16, 840, 1, 101, 3, 4, 2, 2]),
            MessageDigest::sha384(),
        ),
        (
            Oid::const_new(&[2, 16, 840, 1, 101, 3, 4, 2, 1]),
            MessageDigest::sha256(),
        ),
        (Oid::const_new(&[1, 3, 14, 3, 2, 26]), MessageDigest::sha1()),
        (
            Oid::const_new(&[1, 2, 840, 113549, 2, 5]),
            MessageDigest::md5(),
        ),
    ];
    for (digest_oid, digest) in digest_alg_oid_dict {
        if oid.eq(digest_oid) {
            return Ok(digest);
        }
    }
    error!("Invalid OID while finding a digest algorithm");
    Err(EmrtdError::InvalidOidError())
}

/// Validate the ASN.1 tag of the provided data. Multi-byte tags are supported.
///
/// # Arguments
///
/// * `data` - The data to validate.
/// * `tag` - The expected ASN.1 tag.
///
/// # Returns
///
/// Nothing if the tag is valid, or an `EmrtdError` if validation fails.
///
/// # Errors
///
/// * `EmrtdError` if the data is incomplete or the tags don't match.
fn validate_asn1_tag(data: &[u8], tag: &[u8]) -> Result<(), EmrtdError> {
    data.get(..tag.len()).map_or_else(
        || {
            error!(
            "Error while validating ASN1 tag, `data.len()`: `{}` is less than `tag.len()`: `{}`",
            data.len(),
            tag.len()
        );
            Err(EmrtdError::ParseAsn1DataError(tag.len(), data.len()))
        },
        |d| {
            if d.starts_with(tag) {
                Ok(())
            } else {
                error!(
                    "Error while validating ASN1 tag, expected: {}, found {}",
                    bytes2hex(tag),
                    bytes2hex(d)
                );
                Err(EmrtdError::ParseAsn1TagError(bytes2hex(tag), bytes2hex(d)))
            }
        },
    )
}

/// Retrieve the ASN.1 child from the provided data.
///
/// # Arguments
///
/// * `data` - The data containing the ASN.1 structure.
/// * `tag_len` - The length of the tag.
///
/// # Returns
///
/// A `Result` containing the child element and the remaining data,
/// or an `EmrtdError` if extraction fails.
///
/// # Errors
///
/// * `EmrtdError` if the data is incomplete.
fn get_asn1_child(data: &[u8], tag_len: usize) -> Result<(&[u8], &[u8]), EmrtdError> {
    if data.len() < tag_len {
        error!(
            "Error during get_asn1_child, `data.len()`: `{}` is less than `tag_len`: `{}`",
            data.len(),
            tag_len
        );
        return Err(EmrtdError::ParseAsn1DataError(tag_len, data.len()));
    }

    let (tl, v) = len2int(data, tag_len)?;
    if data.len() < tl + v {
        error!(
            "Error during get_asn1_child, `data.len()`: `{}` is less than `tl + v`: `{}`",
            data.len(),
            tl + v
        );
        return Err(EmrtdError::ParseAsn1DataError(tl + v, data.len()));
    }
    Ok((&data[tl..tl + v], &data[tl + v..]))
}

/// Parses the master list data and constructs an `X509Store`.
///
/// # Arguments
///
/// * `master_list` - The master list data to be parsed as a byte slice.
///
/// # Returns
///
/// * `X509Store` containing the parsed CSCA certificates if successful.
///
/// # Errors
///
/// `EmrtdError` if parsing fails.
///
/// # Panics
///
/// Might panic under different circumstances.
///
/// # Examples
///
/// ```
/// # use emrtd::EmrtdError;
/// #
/// # fn main() -> Result<(), EmrtdError> {
/// use emrtd::parse_master_list;
/// use tracing::{info, error};
///
/// let master_list_bytes = &[/* EF.SOD Data */];
///
/// match parse_master_list(master_list_bytes) {
///     Ok(cert_store) => {
///         info!("Master list successfully parsed, number of certificates in the store {}", cert_store.all_certificates().len());
///     },
///     Err(err) => error!("Master list parsing failed: {:?}", err),
/// }
/// #
/// #     Ok(())
/// # }
/// ```
#[cfg(feature = "passive_auth")]
pub fn parse_master_list(master_list: &[u8]) -> Result<X509Store, EmrtdError> {
    // We expect a Master List as specified in
    // ICAO Doc 9303-12 Section 9
    // <https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf>

    // RFC 5652 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-12.1>
    //
    // ContentInfo ::= SEQUENCE {
    //   contentType ContentType,
    //   content [0] EXPLICIT ANY DEFINED BY contentType }
    //
    // ContentType ::= OBJECT IDENTIFIER
    let content_info =
        der::decode::<rasn_cms::ContentInfo>(master_list).map_err(EmrtdError::RasnDecodeError)?;

    // RFC 5652 Section 5.1, SignedData Type
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-5.1>
    // Verify the id-signedData OID
    if content_info
        .content_type
        .ne(Oid::const_new(&[1, 2, 840, 113549, 1, 7, 2]))
    {
        error!("Master List ContentInfo contentType OID must be id-signedData");
        return Err(EmrtdError::InvalidFileStructure(
            "Master List ContentInfo contentType OID must be id-signedData",
        ));
    }

    // RFC 5652 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-12.1>
    //
    // SignedData ::= SEQUENCE {
    //   version CMSVersion,
    //   digestAlgorithms DigestAlgorithmIdentifiers,
    //   encapContentInfo EncapsulatedContentInfo,
    //   certificates [0] IMPLICIT CertificateSet OPTIONAL,
    //   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
    //   signerInfos SignerInfos }
    let signed_data = der::decode::<rasn_cms::SignedData>(content_info.content.as_bytes())
        .map_err(EmrtdError::RasnDecodeError)?;

    // RFC 5652 Sections 12.1 and 10.2.5
    // <https://datatracker.ietf.org/doc/html/rfc5652>
    // First item in the SignedData Sequence is version
    // ICAO Doc 9303-12 Section 9
    // <https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf>
    // For Master Lists it is always set to Value 3
    if signed_data.version.ne(&rasn::types::Integer::from(3)) {
        error!("Master List SignedData version must be V3");
        return Err(EmrtdError::InvalidFileStructure(
            "Master List SignedData version must be V3",
        ));
    }

    // RFC 5652 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-12.1>
    // Second item in the SignedData Sequence is digestAlgorithms
    //
    // It is mandatory by ICAO Doc 9303-12 Section 9
    // <https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf>
    if signed_data.digest_algorithms.is_empty() {
        error!("Master List SignedData digestAlgorithms can not be empty");
        return Err(EmrtdError::InvalidFileStructure(
            "Master List SignedData digestAlgorithms can not be empty",
        ));
    }

    // RFC 5652 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-12.1>
    // Third item in the SignedData Sequence is encapContentInfo
    // It contains CscaMasterList
    //
    // ICAO Doc 9303-12 Section 9
    // <https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf>
    // CscaMasterList {joint-iso-itu-t(2) international-organization(23) icao(136) mrtd(1) security(1) masterlist(2)}
    if signed_data
        .encap_content_info
        .content_type
        .ne(Oid::const_new(&[2, 23, 136, 1, 1, 2]))
    {
        error!("Master List SignedData encapContentInfo OID must be id-icao-cscaMasterList");
        return Err(EmrtdError::InvalidFileStructure(
            "Master List SignedData encapContentInfo OID must be id-icao-cscaMasterList",
        ));
    }

    // It is mandatory by ICAO Doc 9303-12 Section 9
    // <https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf>
    let Some(csca_master_list_bytes) = signed_data.encap_content_info.content else {
        error!("Master List SignedData must contain eContent CscaMasterList");
        return Err(EmrtdError::InvalidFileStructure(
            "Master List SignedData must contain eContent CscaMasterList",
        ));
    };

    // RFC 5652 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-12.1>
    // Fourth item in the SignedData Sequence is certificates
    //
    // It is mandatory by ICAO Doc 9303-12 Section 9
    // <https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf>
    //
    // > The Master List Signer certificate MUST be included and the
    // > CSCA certificate, which can be used to verify the signature in the
    // > signerInfos field SHOULD be included.
    let master_list_signer = {
        let mut possible_master_list_signer = None;
        let mut possible_csca_cert = None;
        for cert in signed_data.certificates.iter().flatten() {
            if let CertificateChoices::Certificate(c) = cert {
                match &c.tbs_certificate.extensions {
                    Some(exts) => {
                        if exts.is_empty() {
                            error!("Certificate Extensions must exist certificates in Master List");
                            return Err(EmrtdError::InvalidFileStructure(
                                "Certificate Extensions must exist certificates in Master List",
                            ));
                        }
                        if possible_master_list_signer.is_none() {
                            for ext in exts.iter() {
                                // It is mandatory by ICAO Doc 9303-12 Section 7.1.1.3
                                // <https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf>
                                //
                                // > The Object Identifier (OID) that must be included in the extendedKeyUsage
                                // extension for Master List Signer certificates is 2.23.136.1.1.3.
                                if ext.extn_id.eq(Oid::const_new(&[2, 5, 29, 37]))
                                    && ext.extn_value.len() == 10
                                    && constant_time_eq(
                                        &ext.extn_value,
                                        b"\x30\x08\x06\x06\x67\x81\x08\x01\x01\x03",
                                    )
                                {
                                    let master_list_signer_bytes =
                                        der::encode(&c).map_err(EmrtdError::RasnEncodeError)?;
                                    let master_list_signer =
                                        X509::from_der(&master_list_signer_bytes)
                                            .map_err(EmrtdError::OpensslErrorStack)?;
                                    possible_master_list_signer = Some(master_list_signer);
                                    break;
                                // It is mandatory by ICAO Doc 9303-12 Table 6
                                // <https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf>
                                //
                                // > Basic constraints cA is mandatory for CSCA certificates
                                // > PathLenConstraint must always be '0'
                                } else if ext.extn_id.eq(Oid::const_new(&[2, 5, 29, 19]))
                                    && ext.extn_value.len() == 8
                                    && constant_time_eq(
                                        &ext.extn_value,
                                        b"\x30\x06\x01\x01\xFF\x02\x01\x00",
                                    )
                                {
                                    let csca_cert_bytes =
                                        der::encode(&c).map_err(EmrtdError::RasnEncodeError)?;
                                    let csca_cert = X509::from_der(&csca_cert_bytes)
                                        .map_err(EmrtdError::OpensslErrorStack)?;
                                    possible_csca_cert = Some(csca_cert);
                                    break;
                                }
                            }
                        }
                    }
                    None => {
                        error!("Certificate Extensions must exist certificates in Master List");
                        return Err(EmrtdError::InvalidFileStructure(
                            "Certificate Extensions must exist certificates in Master List",
                        ));
                    }
                }
            }
        }
        // Make sure we got a possible certificate
        match possible_master_list_signer {
            Some(c) => {
                // And verify that the Master List Signer was issued by CSCA certificate if it exists
                match possible_csca_cert {
                    Some(csca_cert) => {
                        let chain = Stack::new().map_err(EmrtdError::OpensslErrorStack)?;
                        let mut store_bldr =
                            X509StoreBuilder::new().map_err(EmrtdError::OpensslErrorStack)?;
                        store_bldr
                            .add_cert(csca_cert)
                            .map_err(EmrtdError::OpensslErrorStack)?;
                        let store = store_bldr.build();

                        let mut context =
                            X509StoreContext::new().map_err(EmrtdError::OpensslErrorStack)?;
                        let master_list_verification = context
                            .init(&store, &c, &chain, |c| {
                                let verification = c.verify_cert()?;
                                if verification {
                                    Ok((verification, ""))
                                } else {
                                    Ok((verification, c.error().error_string()))
                                }
                            })
                            .map_err(EmrtdError::OpensslErrorStack)?;
                        if !master_list_verification.0 {
                            warn!("Error while verifying Master List Signer Certificate signature: {}", master_list_verification.1);
                        }
                        info!(
                            "Master List Signer Certificate signature verification result: {}",
                            master_list_verification.0
                        );
                    }
                    None => {
                        warn!("Master List Signer Certificate signature is not verified, no CSCA certificate found in signed_data.certificates");
                    }
                }
                c
            }
            None => unimplemented!("Master List must include a Master List Signer"),
        }
    };

    // RFC 3369 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-12.1>
    // Fifth item in the SignedData Sequence is crls
    //
    // It should **not** be present ICAO Doc 9303-10 Section 4.6.2.2
    // <https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf>
    if signed_data.crls.is_some() {
        error!("Master List must not contain a CRL");
        return Err(EmrtdError::InvalidFileStructure(
            "Master List must not contain a CRL",
        ));
    }

    // RFC 5652 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-12.1>
    // Last item in the SignedData Sequence is signerInfos
    //
    // It is recommended to provide only 1 SignerInfo by
    // ICAO Doc 9303-12 Section 9
    // <https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf>
    if signed_data.signer_infos.is_empty() {
        error!("Master List must include at least one SignerInfo");
        return Err(EmrtdError::InvalidFileStructure(
            "Master List must include at least one SignerInfo",
        ));
    }
    // Only one signer_info is supported
    if signed_data.signer_infos.len() > 1 {
        unimplemented!("Master Lists that include more than one SignerInfo are not supported")
    }

    let signer_info = signed_data
        .signer_infos
        .first()
        .expect("len of SignerInfos is 1");

    // RFC 5652 Section 5.3
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-5.3>
    // > version is the syntax version number.  If the SignerIdentifier is
    // > the CHOICE issuerAndSerialNumber, then the version MUST be 1.  If
    // > the SignerIdentifier is subjectKeyIdentifier, then the version
    // > MUST be 3.
    //
    // It is recommended to provide subjectKeyIdentifier (v3) instead of issuerandSerialNumber (v1)
    // by ICAO Doc 9303-12 Section 9
    // <https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf>
    match signer_info.sid {
        rasn_cms::SignerIdentifier::IssuerAndSerialNumber(_) => {
            // Recommended
            if signer_info.version.ne(&rasn::types::Integer::from(1)) {
                error!("Master List SignedData signerInfo IssuerAndSerialNumber is provided but version is not 1");
                return Err(EmrtdError::InvalidFileStructure("Master List SignedData signerInfo IssuerAndSerialNumber is provided but version is not 1"));
            }
        }
        rasn_cms::SignerIdentifier::SubjectKeyIdentifier(_) => {
            if signer_info.version.ne(&rasn::types::Integer::from(3)) {
                error!("Master List SignedData signerInfo SubjectKeyIdentifier is provided but version is not 3");
                return Err(EmrtdError::InvalidFileStructure("Master List SignedData signerInfo SubjectKeyIdentifier is provided but version is not 3"));
            }
        }
    };

    // RFC 5652 Section 5.3
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-5.3>
    // > The message digest algorithm SHOULD be among those
    // > listed in the digestAlgorithms field of the associated SignerData.
    // > Implementations MAY fail to validate signatures that use a digest
    // > algorithm that is not included in the SignedData digestAlgorithms
    // > set.
    if !signed_data
        .digest_algorithms
        .contains(&signer_info.digest_algorithm)
    {
        error!("Master List SignedData signerInfo DigestAlgorithm must be included in SignedData digestAlgorithms set");
        return Err(EmrtdError::InvalidFileStructure(
            "Master List SignedData signerInfo DigestAlgorithm must be included in SignedData digestAlgorithms set",
        ));
    }
    // Ignore digest_algorithm parameters
    let digest_algorithm = oid2digestalg(&signer_info.digest_algorithm.algorithm)?;

    // RFC 5652 Section 5.3
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-5.3>
    //
    // > signedAttrs is a collection of attributes that are signed.  The
    // > field is optional, but it MUST be present if the content type of
    // > the EncapsulatedContentInfo value being signed is not id-data.
    //
    // EncapsulatedContentInfo
    // by ICAO Doc 9303-12 Section 9
    // <https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf>
    // is `(OID joint-iso-itu-t(2) international-organization(23) icao(136) mrtd(1) security(1) masterlist(2))`
    // So this field is mandatory
    let signed_attrs = match &signer_info.signed_attrs {
        None => {
            error!("Master List SignedData signerInfo signed_attrs can't be empty");
            return Err(EmrtdError::InvalidFileStructure(
                "Master List SignedData signerInfo signed_attrs can't be empty",
            ));
        }
        Some(signed_attrs) => signed_attrs,
    };

    // RFC 5652 Section 5.3
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-5.3>
    //
    // > If the field is present, it MUST
    // > contain, at a minimum, the following two attributes:
    // >
    // >   * A content-type attribute [...]
    // >   * A message-digest attribute [...]
    //
    // RFC 5652 Section 11.1
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-11.1>
    //
    // > The following object identifier identifies the content-type
    // > attribute:
    // >
    // >    id-contentType OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    // >        us(840) rsadsi(113549) pkcs(1) pkcs9(9) 3 }
    // >
    // > Content-type attribute values have ASN.1 type ContentType:
    // >
    // >    ContentType ::= OBJECT IDENTIFIER
    //
    // RFC 5652 Section 11.2
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-11.2>
    //
    // > The following object identifier identifies the message-digest
    // > attribute:
    // >
    // >    id-messageDigest OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    // >        us(840) rsadsi(113549) pkcs(1) pkcs9(9) 4 }
    // >
    // > Message-digest attribute values have ASN.1 type MessageDigest:
    // >
    // >    MessageDigest ::= OCTET STRING
    //
    // ICAO Doc 9303-12 Section 9
    // <https://www.icao.int/publications/Documents/9303_p12_cons_en.pdf>
    // also makes signing time mandatory
    // > signedAttrs MUST include signing time (see [PKCS #9]).
    // But we skip verifying that.
    let mut content_type = None;
    let mut message_digest = None;

    for signed_attr in signed_attrs {
        if signed_attr
            .r#type
            .eq(Oid::const_new(&[1, 2, 840, 113549, 1, 9, 3]))
        {
            // ContentType
            if signed_attr.values.len() != 1 {
                error!("Master List SignedData signerInfo signed_attrs contentType attribute values must have a single item");
                return Err(EmrtdError::InvalidFileStructure("Master List SignedData signerInfo signed_attrs contentType attribute values must have a single item"));
            }
            let temp = signed_attr
                .values
                .first()
                .expect("There is only one item")
                .as_bytes();
            content_type = Some(
                der::decode::<rasn::types::ObjectIdentifier>(temp)
                    .map_err(EmrtdError::RasnDecodeError)?,
            );
        } else if signed_attr
            .r#type
            .eq(Oid::const_new(&[1, 2, 840, 113549, 1, 9, 4]))
        {
            // MessageDigest
            if signed_attr.values.len() != 1 {
                error!("Master List SignedData signerInfo signed_attrs messageDigest attribute values must have a single item");
                return Err(EmrtdError::InvalidFileStructure("Master List SignedData signerInfo signed_attrs messageDigest attribute values must have a single item"));
            }
            let temp = signed_attr
                .values
                .first()
                .expect("There is only one item")
                .as_bytes();
            message_digest = Some(
                der::decode::<rasn::types::OctetString>(temp)
                    .map_err(EmrtdError::RasnDecodeError)?,
            );
        }
    }

    let (Some(content_type), Some(message_digest)) = (content_type, message_digest) else {
        error!("Master List SignedData signerInfo signed_attrs contentType or messageDigest values do not exist");
        return Err(EmrtdError::InvalidFileStructure("Master List SignedData signerInfo signed_attrs contentType or messageDigest values do not exist"));
    };

    // RFC 5652 Section 5.3
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-5.3>
    //
    // > A content-type attribute having as its value the content type
    // > of the EncapsulatedContentInfo value being signed.
    //
    // contentType inside signedAttrs must be id-icao-cscaMasterList
    if content_type.ne(Oid::const_new(&[2, 23, 136, 1, 1, 2])) {
        error!("Master List SignedData signerInfo signed_attrs contentType must be id-icao-cscaMasterList");
        return Err(EmrtdError::InvalidFileStructure("Master List SignedData signerInfo signed_attrs contentType must be id-icao-cscaMasterList",));
    }

    // RFC 5652 Section 5.4
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-5.4>
    //
    // Message Digest Calculation Process as specified in RFC 5652
    let csca_master_list_hash =
        hash(digest_algorithm, &csca_master_list_bytes).map_err(EmrtdError::OpensslErrorStack)?;

    if csca_master_list_hash.ne(&message_digest) {
        error!("Digest of cscaMasterList does not match with the digest in SignedAttributes");
        return Err(EmrtdError::InvalidFileStructure(
            "Digest of cscaMasterList does not match with the digest in SignedAttributes",
        ));
    }
    info!("Digest of cscaMasterList matches with the digest in SignedAttributes");

    // Ignore unsignedAttrs
    _ = signer_info.unsigned_attrs;

    // RFC 5652 Section 5.4
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-5.4>
    //
    // > [...] A separate encoding of the signedAttrs field is performed for message digest calculation.
    // > The IMPLICIT [0] tag in the signedAttrs is not used for the DER
    // > encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
    // > encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0]
    // > tag, MUST be included in the message digest calculation along with
    // > the length and content octets of the SignedAttributes value.
    let mut signed_attrs_bytes = der::encode(&signed_attrs).map_err(EmrtdError::RasnEncodeError)?;
    signed_attrs_bytes[0] = b'\x31';

    // Signature Verification
    // Follows RFC 5652 Section 5.6 Signature Verification Process
    // <https://datatracker.ietf.org/doc/html/rfc5652#section-5.6>
    let _signature_algorithm = &signer_info.signature_algorithm;
    let signature = &signer_info.signature;
    info!("{:?}", master_list_signer);
    let pub_key = master_list_signer
        .public_key()
        .map_err(EmrtdError::OpensslErrorStack)?;
    let mut verifier =
        Verifier::new(digest_algorithm, &pub_key).map_err(EmrtdError::OpensslErrorStack)?;
    verifier
        .update(&signed_attrs_bytes)
        .map_err(EmrtdError::OpensslErrorStack)?;
    let sig_verified = verifier
        .verify(signature)
        .map_err(EmrtdError::OpensslErrorStack)?;
    info!("Signature verification: {sig_verified}");

    if !sig_verified {
        error!("Signature verification failure during Master List parsing");
        return Err(EmrtdError::VerifySignatureError(
            "Signature verification failure during Master List parsing",
        ));
    }

    // Parse the eContent
    let csca_master_list = der::decode::<csca_master_list::CscaMasterList>(&csca_master_list_bytes)
        .map_err(EmrtdError::RasnDecodeError)?;

    if csca_master_list.version.ne(&rasn::types::Integer::from(0)) {
        error!("MasterList CscaMasterListVersion must be V0");
        return Err(EmrtdError::InvalidFileStructure(
            "MasterList CscaMasterListVersion must be V0",
        ));
    }

    // Create a store that can be used to verify DSC certificate during passive authentication
    let mut store_bldr = X509StoreBuilder::new().map_err(EmrtdError::OpensslErrorStack)?;

    for csca_cert in csca_master_list.cert_list {
        match der::encode(&csca_cert).map_err(EmrtdError::RasnEncodeError) {
            Ok(c) => {
                let x509cert = X509::from_der(&c).map_err(EmrtdError::OpensslErrorStack)?;
                store_bldr
                    .add_cert(x509cert)
                    .map_err(EmrtdError::OpensslErrorStack)?;
            }
            Err(e) => return Err(e),
        }
    }

    let store = store_bldr.build();

    Ok(store)
}

/// Perform passive authentication on the EF.SOD (Security Object Data) of an eMRTD (electronic Machine Readable Travel Document).
///
/// This function follows the specifications outlined in ICAO Doc 9303-10 Section 4.6.2 and RFC 3369.
/// It verifies the integrity and authenticity of the EF.SOD by validating its structure, signature, and other relevant attributes.
///
/// # Arguments
///
/// * `ef_sod` - The EF.SOD (Security Object Data) read from an eMRTD.
///
/// # Returns
///
/// A `Result` containing a tuple with the following elements if the passive authentication was successful:
/// * `MessageDigest` - The message digest algorithm used for hashing the data groups (EF.DG1..16).
/// * `Vec<DataGroupHash>` - A vector containing hashes of the data groups as specified in the `LDSSecurityObject`.
/// * `X509` - Document Signer Certificate (DSC) used for signing the EF.SOD.
///
/// If passive authentication fails due to any reason such as invalid structure, mismatched hashes, or signature verification failure,
/// an `EmrtdError` is returned indicating the specific failure reason.
///
/// # Errors
///
/// Returns an `EmrtdError` if passive authentication fails.
///
/// # Panics
///
/// Might panic under different circumstances.
///
/// # Examples
///
/// ```
/// # use emrtd::EmrtdError;
/// #
/// # fn main() -> Result<(), EmrtdError> {
/// use emrtd::passive_authentication;
/// use openssl::x509::store::X509StoreBuilder;
/// use tracing::{info, error};
///
/// let store = X509StoreBuilder::new().map_err(EmrtdError::OpensslErrorStack)?.build();
///
/// let ef_sod_data = &[/* EF.SOD Data */];
/// match passive_authentication(ef_sod_data, &store) {
///     Ok((digest_algorithm, dg_hashes, dsc)) => {
///         info!("Passive authentication successful!");
///         info!("Message Digest Algorithm (openssl NID): {:?}", digest_algorithm.type_());
///         info!("Data Group Hashes: {:?}", dg_hashes);
///         info!("Document Signer Certificate: {:?}", dsc);
///     }
///     Err(err) => error!("Passive authentication failed: {:?}", err),
/// }
/// #
/// #     Ok(())
/// # }
/// ```
///
/// # TODOs
///
/// * Instead of returning error immediately after an error, collect all errors and return at the end
/// of the function, i.e. in case of signature verification failure, maybe the user can still get the DG hashes
#[cfg(feature = "passive_auth")]
pub fn passive_authentication(
    ef_sod: &[u8],
    cert_store: &X509Store,
) -> Result<(MessageDigest, Vec<lds_security_object::DataGroupHash>, X509), EmrtdError> {
    // ICAO Doc 9303-10 Section 4.6.2
    // <https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf>
    // Strip Document Security Object Tag 0x77
    validate_asn1_tag(ef_sod, b"\x77")?;
    let (ef_sod_rem, empty) = get_asn1_child(ef_sod, 1)?;
    if !empty.is_empty() {
        error!("EF.SOD file tag is wrong, must be '0x77'");
        return Err(EmrtdError::InvalidFileStructure(
            "EF.SOD file tag is wrong, must be '0x77'",
        ));
    }

    // RFC 3369 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-12.1>
    //
    // ContentInfo ::= SEQUENCE {
    //   contentType ContentType,
    //   content [0] EXPLICIT ANY DEFINED BY contentType }
    //
    // ContentType ::= OBJECT IDENTIFIER
    let content_info =
        der::decode::<rasn_cms::ContentInfo>(ef_sod_rem).map_err(EmrtdError::RasnDecodeError)?;

    // RFC 3369 Section 5.1, SignedData Type
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-5.1>
    // Verify the id-signedData OID
    if content_info
        .content_type
        .ne(Oid::const_new(&[1, 2, 840, 113549, 1, 7, 2]))
    {
        error!("EF.SOD ContentInfo contentType OID must be id-signedData");
        return Err(EmrtdError::InvalidFileStructure(
            "EF.SOD ContentInfo contentType OID must be id-signedData",
        ));
    }

    // RFC 3369 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-12.1>
    //
    // SignedData ::= SEQUENCE {
    //   version CMSVersion,
    //   digestAlgorithms DigestAlgorithmIdentifiers,
    //   encapContentInfo EncapsulatedContentInfo,
    //   certificates [0] IMPLICIT CertificateSet OPTIONAL,
    //   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
    //   signerInfos SignerInfos }
    let signed_data = der::decode::<rasn_cms::SignedData>(content_info.content.as_bytes())
        .map_err(EmrtdError::RasnDecodeError)?;

    // RFC 3369 Sections 12.1 and 10.2.5
    // <https://datatracker.ietf.org/doc/html/rfc3369>
    // First item in the SignedData Sequence is version
    // ICAO Doc 9303-10 Section 4.6.2.2
    // <https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf>
    // For eMRTDs it is always set to Value 3
    if signed_data.version.ne(&rasn::types::Integer::from(3)) {
        error!("EF.SOD SignedData version must be V3");
        return Err(EmrtdError::InvalidFileStructure(
            "EF.SOD SignedData version must be V3",
        ));
    }

    // RFC 3369 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-12.1>
    // Second item in the SignedData Sequence is digestAlgorithms
    //
    // It is mandatory by ICAO Doc 9303-10 Section 4.6.2.2
    // <https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf>
    if signed_data.digest_algorithms.is_empty() {
        error!("EF.SOD SignedData digestAlgorithms can not be empty");
        return Err(EmrtdError::InvalidFileStructure(
            "EF.SOD SignedData digestAlgorithms can not be empty",
        ));
    }

    // RFC 3369 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-12.1>
    // Third item in the SignedData Sequence is encapContentInfo
    // It contains LDSSecurityObject
    //
    // ICAO Doc 9303-10 Section 4.6.2.3 and Appendix D.2
    // <https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf>
    // LDSSecurityObjectV0 {joint-iso-itu-t (2) international(23) icao(136) mrtd(1) security(1) ldsSecurityObject(1)}
    // LDSSecurityObjectV1 {joint-iso-itu-t (2) international(23) icao(136) mrtd(1) security(1) ldsSecurityObject(1)}
    if signed_data
        .encap_content_info
        .content_type
        .ne(Oid::const_new(&[2, 23, 136, 1, 1, 1]))
    {
        error!("EF.SOD SignedData encapContentInfo OID must be id-icao-mrtd-security-ldsSecurityObject");
        return Err(EmrtdError::InvalidFileStructure("EF.SOD SignedData encapContentInfo OID must be id-icao-mrtd-security-ldsSecurityObject"));
    }

    // It is mandatory by ICAO Doc 9303-10 Section 4.6.2.2
    // <https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf>
    let Some(lds_security_object_bytes) = signed_data.encap_content_info.content else {
        error!("EF.SOD SignedData must contain eContent LDSSecurityObject");
        return Err(EmrtdError::InvalidFileStructure(
            "EF.SOD SignedData must contain eContent LDSSecurityObject",
        ));
    };

    // RFC 3369 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-12.1>
    // Fourth item in the SignedData Sequence is certificates
    //
    // It is mandatory by ICAO Doc 9303-10 Section 4.6.2.2 for LDS v1
    // <https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf>
    //
    // > States are REQUIRED to include the Document Signer Certificate (CDS) which can
    // > be used to verify the signature in the signerInfos field.
    //
    // But it is optional for LDS v0 ICAO Doc 9303-10 Appendix D.1
    let dsc = {
        let mut possible_dsc = None;
        for cert in signed_data.certificates.iter().flatten() {
            if let CertificateChoices::Certificate(c) = cert {
                let dsc_bytes = der::encode(&c).map_err(EmrtdError::RasnEncodeError)?;
                let dsc = X509::from_der(&dsc_bytes).map_err(EmrtdError::OpensslErrorStack)?;
                possible_dsc = Some(dsc);
                break;
            }
        }
        // Make sure we got a possible certificate
        match possible_dsc {
            Some(c) => {
                let chain = Stack::new().map_err(EmrtdError::OpensslErrorStack)?;
                let mut context = X509StoreContext::new().map_err(EmrtdError::OpensslErrorStack)?;
                let dsc_verification = context.init(cert_store, &c, &chain, |c| {
                    let verification = c.verify_cert()?;
                    if verification {
                        Ok((verification, ""))
                    } else {
                        Ok((verification, c.error().error_string()))
                    }
                }).map_err(EmrtdError::OpensslErrorStack)?;
                if !dsc_verification.0 {
                    error!("Error while verifying Document Signer Certificate signature: {}", dsc_verification.1);
                    return Err(EmrtdError::InvalidFileStructure("DSC certificate verification using CSCA store failed"));
                }
                info!("Document Signer Certificate signature verification result: {}", dsc_verification.0);
                c
            },
            None => unimplemented!("Documents that do not include a Document Signer Certificate are not yet supported, or the included certificate is not supported")
        }
    };

    // RFC 3369 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-12.1>
    // Fifth item in the SignedData Sequence is crls
    //
    // It is recommended **not** to use by ICAO Doc 9303-10 Section 4.6.2.2
    // <https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf>
    let crl_bytes = {
        let mut possible_crl = None;
        for crl in signed_data.crls.iter().flatten() {
            if let RevocationInfoChoice::Crl(c) = crl {
                possible_crl = Some(c);
                break;
            }
        }
        match possible_crl {
            Some(c) => {
                // Try to encode it
                match der::encode(&c).map_err(EmrtdError::RasnEncodeError) {
                    Ok(c) => Some(c),
                    Err(e) => return Err(e),
                }
            }
            None => None,
        }
    };

    if let Some(_crl) = crl_bytes {
        // We just ignore it
    }

    // RFC 3369 Section 12.1, Cryptographic Message Syntax
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-12.1>
    // Last item in the SignedData Sequence is signerInfos
    //
    // It is recommended to provide only 1 SignerInfo by
    // ICAO Doc 9303-10 Section 4.6.2.2
    // <https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf>
    if signed_data.signer_infos.is_empty() {
        error!("EF.SOD SignedData signerInfos can't be empty");
        return Err(EmrtdError::InvalidFileStructure(
            "EF.SOD SignedData signerInfos can't be empty",
        ));
    }

    // Only one signer_info is supported
    if signed_data.signer_infos.len() > 1 {
        unimplemented!("EF.SOD that include more than one SignerInfo are not supported")
    }

    let signer_info = signed_data
        .signer_infos
        .first()
        .expect("len of SignerInfos is 1");

    // RFC 3369 Section 5.3
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-5.3>
    // > version is the syntax version number.  If the SignerIdentifier is
    // > the CHOICE issuerAndSerialNumber, then the version MUST be 1.  If
    // > the SignerIdentifier is subjectKeyIdentifier, then the version
    // > MUST be 3.
    //
    // It is recommended to provide issuerandSerialNumber (v1) instead of subjectKeyIdentifier (v3)
    // by ICAO Doc 9303-10 Section 4.6.2.2
    // <https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf>
    match signer_info.sid {
        rasn_cms::SignerIdentifier::IssuerAndSerialNumber(_) => {
            if signer_info.version.ne(&rasn::types::Integer::from(1)) {
                error!("EF.SOD SignedData signerInfo IssuerAndSerialNumber is provided but version is not 1");
                return Err(EmrtdError::InvalidFileStructure("EF.SOD SignedData signerInfo IssuerAndSerialNumber is provided but version is not 1"));
            }
        }
        rasn_cms::SignerIdentifier::SubjectKeyIdentifier(_) => {
            if signer_info.version.ne(&rasn::types::Integer::from(3)) {
                error!("EF.SOD SignedData signerInfo SubjectKeyIdentifier is provided but version is not 3");
                return Err(EmrtdError::InvalidFileStructure("EF.SOD SignedData signerInfo SubjectKeyIdentifier is provided but version is not 3"));
            }
        }
    };

    // RFC 3369 Section 5.3
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-5.3>
    // > The message digest algorithm SHOULD be among those
    // > listed in the digestAlgorithms field of the associated SignerData.
    // > Implementations MAY fail to validate signatures that use a digest
    // > algorithm that is not included in the SignedData digestAlgorithms
    // > set.
    if !signed_data
        .digest_algorithms
        .contains(&signer_info.digest_algorithm)
    {
        error!("EF.SOD SignedData signerInfo DigestAlgorithm must be included in SignedData digestAlgorithms set");
        return Err(EmrtdError::InvalidFileStructure(
            "EF.SOD SignedData signerInfo DigestAlgorithm must be included in SignedData digestAlgorithms set",
        ));
    }
    // Ignore digest_algorithm parameters
    let digest_algorithm = oid2digestalg(&signer_info.digest_algorithm.algorithm)?;

    // RFC 3369 Section 5.3
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-5.3>
    //
    // > signedAttrs is a collection of attributes that are signed.  The
    // > field is optional, but it MUST be present if the content type of
    // > the EncapsulatedContentInfo value being signed is not id-data.
    //
    // EncapsulatedContentInfo
    // by ICAO Doc 9303-10 Section 4.6.2.2
    // <https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf>
    // is `(OID joint-iso-itu-t (2) international(23) icao(136) mrtd(1) security(1) ldsSecurityObject(1))`
    // So this field is mandatory
    let signed_attrs = match &signer_info.signed_attrs {
        None => {
            error!("EF.SOD SignedData signerInfo signed_attrs can't be empty");
            return Err(EmrtdError::InvalidFileStructure(
                "EF.SOD SignedData signerInfo signed_attrs can't be empty",
            ));
        }
        Some(signed_attrs) => signed_attrs,
    };

    // RFC 3369 Section 5.3
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-5.3>
    //
    // > If the field is present, it MUST
    // > contain, at a minimum, the following two attributes:
    // >
    // >   * A content-type attribute [...]
    // >   * A message-digest attribute [...]
    //
    // RFC 3369 Section 11.1
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-11.1>
    //
    // > The following object identifier identifies the content-type
    // > attribute:
    // >
    // >    id-contentType OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    // >        us(840) rsadsi(113549) pkcs(1) pkcs9(9) 3 }
    // >
    // > Content-type attribute values have ASN.1 type ContentType:
    // >
    // >    ContentType ::= OBJECT IDENTIFIER
    //
    // RFC 3369 Section 11.2
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-11.2>
    //
    // > The following object identifier identifies the message-digest
    // > attribute:
    // >
    // >    id-messageDigest OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    // >        us(840) rsadsi(113549) pkcs(1) pkcs9(9) 4 }
    // >
    // > Message-digest attribute values have ASN.1 type MessageDigest:
    // >
    // >    MessageDigest ::= OCTET STRING
    let mut content_type = None;
    let mut message_digest = None;

    for signed_attr in signed_attrs {
        if signed_attr
            .r#type
            .eq(Oid::const_new(&[1, 2, 840, 113549, 1, 9, 3]))
        {
            // ContentType
            if signed_attr.values.len() != 1 {
                error!("EF.SOD SignedData signerInfo signed_attrs contentType attribute values must have a single item");
                return Err(EmrtdError::InvalidFileStructure("EF.SOD SignedData signerInfo signed_attrs contentType attribute values must have a single item"));
            }
            let temp = signed_attr
                .values
                .first()
                .expect("There is only one item")
                .as_bytes();
            content_type = Some(
                der::decode::<rasn::types::ObjectIdentifier>(temp)
                    .map_err(EmrtdError::RasnDecodeError)?,
            );
        } else if signed_attr
            .r#type
            .eq(Oid::const_new(&[1, 2, 840, 113549, 1, 9, 4]))
        {
            // MessageDigest
            if signed_attr.values.len() != 1 {
                error!("EF.SOD SignedData signerInfo signed_attrs messageDigest attribute values must have a single item");
                return Err(EmrtdError::InvalidFileStructure("EF.SOD SignedData signerInfo signed_attrs messageDigest attribute values must have a single item"));
            }
            let temp = signed_attr
                .values
                .first()
                .expect("There is only one item")
                .as_bytes();
            message_digest = Some(
                der::decode::<rasn::types::OctetString>(temp)
                    .map_err(EmrtdError::RasnDecodeError)?,
            );
        }
    }

    let (Some(content_type), Some(message_digest)) = (content_type, message_digest) else {
        error!("EF.SOD SignedData signerInfo signed_attrs contentType or messageDigest values do not exist");
        return Err(EmrtdError::InvalidFileStructure("EF.SOD SignedData signerInfo signed_attrs contentType or messageDigest values do not exist"));
    };

    // RFC 3369 Section 5.3
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-5.3>
    //
    // > A content-type attribute having as its value the content type
    // > of the EncapsulatedContentInfo value being signed.
    //
    // contentType inside signedAttrs must be id-icao-mrtd-security-ldsSecurityObject
    if content_type.ne(Oid::const_new(&[2, 23, 136, 1, 1, 1])) {
        error!("EF.SOD SignedData signerInfo signed_attrs contentType must be id-icao-mrtd-security-ldsSecurityObject");
        return Err(EmrtdError::InvalidFileStructure("EF.SOD SignedData signerInfo signed_attrs contentType must be id-icao-mrtd-security-ldsSecurityObject",));
    }

    // RFC 3369 Section 5.4
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-5.4>
    //
    // Message Digest Calculation Process as specified in RFC 3369
    let lds_security_object_hash = hash(digest_algorithm, &lds_security_object_bytes)
        .map_err(EmrtdError::OpensslErrorStack)?;

    if lds_security_object_hash.ne(&message_digest) {
        error!("Digest of LDSSecurityObject does not match with the digest in SignedAttributes");
        return Err(EmrtdError::InvalidFileStructure(
            "Digest of LDSSecurityObject does not match with the digest in SignedAttributes",
        ));
    }
    info!("Digest of LDSSecurityObject matches with the digest in SignedAttributes");

    // Ignore unsignedAttrs
    _ = signer_info.unsigned_attrs;

    // RFC 3369 Section 5.4
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-5.4>
    //
    // > [...] A separate encoding of the signedAttrs field is performed for message digest calculation.
    // > The IMPLICIT [0] tag in the signedAttrs is not used for the DER
    // > encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
    // > encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0]
    // > tag, MUST be included in the message digest calculation along with
    // > the length and content octets of the SignedAttributes value.
    let mut signed_attrs_bytes = der::encode(&signed_attrs).map_err(EmrtdError::RasnEncodeError)?;
    signed_attrs_bytes[0] = b'\x31';

    // Signature Verification
    // Follows RFC 3369 Section 5.6 Signature Verification Process
    // <https://datatracker.ietf.org/doc/html/rfc3369#section-5.6>
    let _signature_algorithm = &signer_info.signature_algorithm;
    let signature = &signer_info.signature;
    let pub_key = dsc.public_key().map_err(EmrtdError::OpensslErrorStack)?;
    let mut verifier =
        Verifier::new(digest_algorithm, &pub_key).map_err(EmrtdError::OpensslErrorStack)?;
    verifier
        .update(&signed_attrs_bytes)
        .map_err(EmrtdError::OpensslErrorStack)?;
    let sig_verified = verifier
        .verify(signature)
        .map_err(EmrtdError::OpensslErrorStack)?;
    info!("Signature verification: {sig_verified}");

    if !sig_verified {
        error!("Signature verification failure during EF.SOD parsing");
        return Err(EmrtdError::VerifySignatureError(
            "Signature verification failure during EF.SOD parsing",
        ));
    }

    // Parse the eContent
    let lds_security_object =
        der::decode::<lds_security_object::LDSSecurityObject>(&lds_security_object_bytes)
            .map_err(EmrtdError::RasnDecodeError)?;
    // LDSSecurityObject has two versions, it is defined by ICAO Doc 9303-10
    if lds_security_object
        .version
        .eq(&rasn::types::Integer::from(0))
    {
        if lds_security_object.lds_version_info.is_some() {
            error!("EF.SOD LDSSecurityObjectVersion is V0, but ldsVersionInfo is present");
            return Err(EmrtdError::InvalidFileStructure(
                "EF.SOD LDSSecurityObjectVersion is V0, but ldsVersionInfo is present",
            ));
        }
        info!("LDSSecurityObjectVersion is V0");
    } else if lds_security_object
        .version
        .eq(&rasn::types::Integer::from(1))
    {
        if lds_security_object.lds_version_info.is_none() {
            error!("EF.SOD LDSSecurityObjectVersion is V1, but ldsVersionInfo is not present");
            return Err(EmrtdError::InvalidFileStructure(
                "EF.SOD LDSSecurityObjectVersion is V1, but ldsVersionInfo is not present",
            ));
        }
        info!("LDSSecurityObjectVersion is V1");
    }
    // Skip Algorithm parameters
    let file_digest_algorithm = oid2digestalg(&lds_security_object.hash_algorithm.algorithm)?;
    if lds_security_object.data_group_hash_values.len() < 2
        || lds_security_object.data_group_hash_values.len() > 16
    {
        error!("EF.SOD LDSSecurityObject DataGroupHash values are invalid");
        return Err(EmrtdError::InvalidFileStructure(
            "EF.SOD LDSSecurityObject DataGroupHash values are invalid",
        ));
    }
    for data_group_hash in &lds_security_object.data_group_hash_values {
        if data_group_hash
            .data_group_number
            .gt(&rasn::types::Integer::from(16))
        {
            error!("EF.SOD LDSSecurityObject invalid DataGroupHash number");
            return Err(EmrtdError::InvalidFileStructure(
                "EF.SOD LDSSecurityObject invalid DataGroupHash number",
            ));
        }
    }
    let dg_hashes = lds_security_object.data_group_hash_values;

    Ok((file_digest_algorithm, dg_hashes, dsc))
}

/// Extracts the JPEG image from the EF.DG2.
///
/// This function follows the specifications outlined in ICAO Doc 9303-10 Section 4.7.2 for the structure of EF.DG2 files.
/// For details, refer to: [ICAO Doc 9303-10 Section 4.7.2](https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf)
///
/// # Arguments
///
/// * `ef_dg2` - EF.DG2 contents.
///
/// # Returns
///
/// Extracted JPEG image data if successful, else `EmrtdError`.
///
/// # Errors
///
/// `EmrtdError` if the EF.DG2 file structure is invalid or if errors occur during parsing.
///
/// # Examples
///
/// ```
/// # use emrtd::EmrtdError;
/// #
/// # fn main() -> Result<(), EmrtdError> {
/// use emrtd::get_jpeg_from_ef_dg2;
/// use tracing::{info, error};
///
/// let ef_dg2 = &[/* EF.DG2 Data */];
///
/// let jpeg = match get_jpeg_from_ef_dg2(ef_dg2) {
///     Ok(jpeg) => {
///         info!("JPEG successfully extracted.")
///     },
///     Err(e) => error!("Error during JPEG extraction from EF.DG2: {}", e)
/// };
/// #
/// #     Ok(())
/// # }
/// ```
pub fn get_jpeg_from_ef_dg2(ef_dg2: &[u8]) -> Result<&[u8], EmrtdError> {
    // ICAO Doc 9303-10 Section 4.7.2
    // <https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf>
    // Strip EF.DG2 Tag 0x75
    validate_asn1_tag(ef_dg2, b"\x75")?;
    let (ef_dg2_rem, empty) = get_asn1_child(ef_dg2, 1)?;
    if !empty.is_empty() {
        error!("EF.DG2 file tag is wrong, must be '0x75'");
        return Err(EmrtdError::InvalidFileStructure(
            "EF.DG2 file tag is wrong, must be '0x75'",
        ));
    }
    // Strip Biometric Information Template Group Template Tag 0x7F61
    validate_asn1_tag(ef_dg2_rem, b"\x7F\x61")?;
    let (ef_dg2_rem, empty) = get_asn1_child(ef_dg2_rem, 2)?;
    if !empty.is_empty() {
        error!("EF.DG2 Biometric Information Template Group Template Tag must be '0x7F61'");
        return Err(EmrtdError::InvalidFileStructure(
            "EF.DG2 Biometric Information Template Group Template Tag must be '0x7F61'",
        ));
    }
    // Find number of biometric templates
    validate_asn1_tag(ef_dg2_rem, b"\x02")?;
    let (number_of_face_images, ef_dg2_rem) = get_asn1_child(ef_dg2_rem, 1)?;
    if number_of_face_images.len() != 1 || number_of_face_images[0] < 1 {
        error!("EF.DG2 file invalid structure, must contain at least one face image");
        return Err(EmrtdError::InvalidFileStructure(
            "EF.DG2 file invalid structure, must contain at least one face image",
        ));
    }
    // We only get the first face image
    validate_asn1_tag(ef_dg2_rem, b"\x7F\x60")?;
    let (first_instance, _other_instances) = get_asn1_child(ef_dg2_rem, 2)?;
    // Skip the Biometric Header Template (BHT) parsing
    validate_asn1_tag(first_instance, b"\xA1")?;
    let (_bht, biometric_data) = get_asn1_child(first_instance, 1)?;
    if biometric_data.is_empty() {
        error!("EF.DG2 first biometric image must not be empty");
        return Err(EmrtdError::InvalidFileStructure(
            "EF.DG2 first biometric image must not be empty",
        ));
    }
    // Strip the image tag '5F2E' or '7F2E'
    match validate_asn1_tag(biometric_data, b"\x5F\x2E") {
        Ok(()) => {}
        Err(EmrtdError::ParseAsn1TagError(_, _)) => validate_asn1_tag(biometric_data, b"\x7F\x2E")?,
        Err(e) => return Err(e),
    }
    let (biometric_data, _) = get_asn1_child(biometric_data, 2)?;
    if biometric_data.len() < 46 {
        error!("EF.DG2 invalid biometric image structure");
        return Err(EmrtdError::InvalidFileStructure(
            "EF.DG2 invalid biometric image structure",
        ));
    }
    // Face Image Data Standard for e-Governance Applications in India
    // https://egovstandards.gov.in/sites/default/files/Face_Image_Data_Standard_Ver1.0.pdf
    // Section 6.3
    // Ideally we would get these values looking at ISO 19794-5:2005
    //
    // Strip the Facial Record Header (14 bytes)
    validate_asn1_tag(biometric_data, b"\x46\x41\x43\x00\x30\x31\x30\x00")?;
    let biometric_data = &biometric_data[14..];
    // Strip Facial Information (20 bytes)
    let biometric_data = &biometric_data[20..];
    // Strip Image Information (12 bytes)
    let biometric_data = &biometric_data[12..];

    Ok(biometric_data)
}

/// Validates the integrity of a Data Group (DG) in an eMRTD.
///
/// # Arguments
///
/// * `dg` - Data Group contents.
/// * `dg_number` - The number of the Data Group to validate, ranging from 1 to 16.
/// * `message_digest` - The cryptographic hash function used to compute the hash of the Data Group in EF.SOD.
/// * `verified_hashes` - A slice of `DataGroupHash` objects representing the pre-verified hashes of Data Groups.
///
/// # Returns
///
/// * `Ok(())` if the validation succeeds, indicating that the Data Group is valid.
/// * `Err(EmrtdError)` if the validation fails, containing details about the failure.
///
/// # Errors
///
/// `EmrtdError` in case of failure during verification.
///
/// # Panics
///
/// Might panic under different circumstances.
///
/// # Examples
///
/// ```
/// # use emrtd::EmrtdError;
/// #
/// # fn main() -> Result<(), EmrtdError> {
/// use emrtd::{passive_authentication, validate_dg};
/// use openssl::x509::store::X509StoreBuilder;
/// use tracing::{info, error};
///
/// let store = X509StoreBuilder::new().map_err(EmrtdError::OpensslErrorStack)?.build();
///
/// let ef_sod_data = &[/* EF.SOD Data */];
/// let ef_dg1 = &[/* EF.DG1 Data */];
/// match passive_authentication(ef_sod_data, &store) {
///     Ok((digest_algorithm, verified_dg_hashes, dsc)) => {
///         match validate_dg(ef_dg1, 1, digest_algorithm, &verified_dg_hashes) {
///             Ok(()) => {
///                 info!("EF.DG1 successfully verified")
///             }
///             Err(err) => error!("Passive authentication failed: {:?}", err),
///         }
///     }
///     Err(err) => {
///         error!("Passive authentication failed: {:?}", err)
///     }
/// }
/// #
/// #     Ok(())
/// # }
/// ```
#[cfg(feature = "passive_auth")]
pub fn validate_dg(
    dg: &[u8],
    dg_number: i32,
    message_digest: MessageDigest,
    verified_hashes: &[lds_security_object::DataGroupHash],
) -> Result<(), EmrtdError> {
    if !(1..=16).contains(&dg_number) {
        error!("Invalid Data Group number: {}", dg_number);
        return Err(EmrtdError::InvalidArgument("Invalid Data Group number"));
    }

    let hash_bytes = hash(message_digest, dg).map_err(EmrtdError::OpensslErrorStack)?;
    let mut verified_hash = None;
    for dg_hash in verified_hashes {
        if dg_hash
            .data_group_number
            .eq(&rasn::types::Integer::from(dg_number))
        {
            verified_hash = Some(&dg_hash.data_group_hash_value);
        }
    }
    match verified_hash {
        Some(verified_hash) => {
            if !constant_time_eq(verified_hash, &hash_bytes) {
                error!("Potentially cloned document, hashes do not match");
                return Err(EmrtdError::VerifyHashError(
                    "Potentially cloned document, hashes do not match".to_owned(),
                ));
            }
        }
        None => {
            error!("Potentially cloned document, EF.DG{dg_number} file hash is not found inside verified hashes");
            return Err(EmrtdError::VerifyHashError(format!(
                "EF.DG{dg_number} file hash is not found inside verified hashes"
            )));
        }
    }

    Ok(())
}

/// An Application Protocol Data Unit (APDU) used in smart card communication.
#[derive(Debug, Clone)]
pub struct APDU {
    /// Class byte of the APDU
    cla: u8,
    /// Instruction byte of the APDU
    ins: u8,
    /// Parameter 1 byte of the APDU
    p1: u8,
    /// Parameter 2 byte of the APDU
    p2: u8,
    /// Length of the command data field (Lc) in the APDU
    lc: Option<Vec<u8>>,
    /// Command data field of the APDU
    cdata: Option<Vec<u8>>,
    /// Expected length of the response data field (Le) in the APDU
    le: Option<Vec<u8>>,
}

impl APDU {
    /// Constructs a new APDU instance with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `cla` - The class byte of the APDU.
    /// * `ins` - The instruction byte of the APDU.
    /// * `p1` - The parameter 1 byte of the APDU.
    /// * `p2` - The parameter 2 byte of the APDU.
    /// * `lc` - Optional command data field length (Lc) of the APDU.
    /// * `cdata` - Optional command data field of the APDU.
    /// * `le` - Optional expected response data field length (Le) of the APDU.
    ///
    /// # Panics
    ///
    /// Panics if the lengths of `lc` and `le` violate ISO/IEC 7816-4 specifications.
    /// See the wiki article for more details:
    /// <https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit>
    ///
    /// # Example
    ///
    /// ```
    /// # use emrtd::EmrtdError;
    /// #
    /// # fn main() -> Result<(), EmrtdError> {
    /// use emrtd::APDU;
    /// let apdu = APDU::new(b'\x00', b'\x84', b'\x00', b'\x00', None, None, Some(vec![b'\x08']));
    /// #
    /// #     Ok(())
    /// # }
    /// ```
    pub fn new(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        lc: Option<Vec<u8>>,
        cdata: Option<Vec<u8>>,
        le: Option<Vec<u8>>,
    ) -> Self {
        match (lc.as_ref().map(Vec::len), le.as_ref().map(Vec::len)) {
            (None | Some(1 | 3), None)
            | (None | Some(1), Some(1))
            | (Some(3), Some(2))
            | (None, Some(3)) => { /* Valid */ }
            (_, _) => {
                panic!("lc and le length error");
            }
        }

        Self {
            cla,
            ins,
            p1,
            p2,
            lc,
            cdata,
            le,
        }
    }

    /// Retrieves the command header of the APDU.
    ///
    /// The command header consists of the class byte, instruction byte,
    /// parameter 1 byte, and parameter 2 byte of the APDU.
    ///
    /// # Returns
    ///
    /// The command header.
    ///
    /// # Examples
    ///
    /// ```
    /// # use emrtd::EmrtdError;
    /// #
    /// # fn main() -> Result<(), EmrtdError> {
    /// use emrtd::APDU;
    /// use hex_literal::hex;
    ///
    /// let apdu = APDU::new(b'\x00', b'\x84', b'\x00', b'\x00', None, None, Some(vec![b'\x08']));
    /// assert_eq!(apdu.get_command_header(), hex!("00840000"));
    /// #
    /// #     Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn get_command_header(&self) -> Vec<u8> {
        vec![self.cla, self.ins, self.p1, self.p2]
    }
}

/// pcsc card functions used in EmrtdComms
pub trait EmrtdCard {
    fn get_attribute_owned(&self, attribute: pcsc::Attribute) -> Result<Vec<u8>, pcsc::Error>;
    fn transmit<'buf>(&self, send_buffer: &[u8], receive_buffer: &'buf mut [u8]) -> Result<&'buf [u8], pcsc::Error>;
}

impl EmrtdCard for pcsc::Card {
    fn get_attribute_owned(&self, attribute: pcsc::Attribute) -> Result<Vec<u8>, pcsc::Error> {
        self.get_attribute_owned(attribute)
    }
    fn transmit<'buf>(&self, send_buffer: &[u8], receive_buffer: &'buf mut [u8]) -> Result<&'buf [u8], pcsc::Error> {
        self.transmit(send_buffer, receive_buffer)
    }
}

pub struct EmrtdComms<C: EmrtdCard, R: RngCore + CryptoRng + Default = OsRng> {
    rng: R,
    /// The card interface used for communication with the eMRTD.
    card: C,
    /// The encryption algorithm used for securing communication with the eMRTD.
    enc_alg: Option<EncryptionAlgorithm>,
    /// The MAC (Message Authentication Code) algorithm used for data integrity verification.
    mac_alg: Option<MacAlgorithm>,
    /// The padding length used for encryption, data will be padded to multiple of `pad_len`.
    pad_len: usize,
    /// The session key used for encryption.
    ks_enc: Option<Vec<u8>>,
    /// The session key used for MAC generation.
    ks_mac: Option<Vec<u8>>,
    /// The Secure Session Counter (SSC).
    ssc: Option<Vec<u8>>,
}

impl<C: EmrtdCard, R: RngCore + CryptoRng + Default> EmrtdComms<C, R> {
    /// Constructs a new `EmrtdComms` instance with the smart card interface.
    ///
    /// # Arguments
    ///
    /// * `card` - The PC/SC smart card interface.
    ///
    /// # Returns
    ///
    /// A new `EmrtdComms` instance.
    #[must_use]
    pub fn new(card: C) -> Self {
        Self {
            rng: R::default(),
            card,
            enc_alg: None,
            mac_alg: None,
            pad_len: 0,
            ks_enc: None,
            ks_mac: None,
            ssc: None,
        }
    }

    /// Retrieves the Answer to Reset (ATR) from the smart card.
    ///
    /// # Returns
    ///
    /// ATR or an `EmrtdError`.
    ///
    /// # Errors
    ///
    /// * `EmrtdError` wrapping `PscsError` in case of failure.
    pub fn get_atr(&mut self) -> Result<Vec<u8>, EmrtdError> {
        match self.card.get_attribute_owned(AtrString) {
            Ok(atr) => Ok(atr),
            Err(err) => Err(EmrtdError::PcscError(err)),
        }
    }

    /// Sends an APDU (Application Protocol Data Unit) to the smart card and receives the response.
    /// If `secure` is `false`, the APDU is sent in plaintext.
    /// If `secure` is `true`, the function checks that the secure channel is established previously,
    /// such as using `establish_bac_session_keys` function.
    /// For more details and examples, see ICAO Doc 9303-11 Section 9.8 and Appendix D.4
    /// <https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf>
    ///
    /// # Arguments
    ///
    /// * `apdu` - The APDU to be sent.
    /// * `secure` - A flag indicating whether to send the APDU securely.
    ///
    /// # Returns
    ///
    /// The response data and status bytes if the operation succeeds else an `EmrtdError`.
    ///
    /// # Errors
    ///
    /// * `EmrtdError` in case of failure during sending or receiving an APDU.
    pub fn send(&mut self, apdu: &APDU, secure: bool) -> Result<(Vec<u8>, [u8; 2]), EmrtdError> {
        // Sending APDU in plaintext
        if !secure {
            let mut apdu_bytes = vec![];
            apdu_bytes.extend(&apdu.get_command_header());
            apdu_bytes.extend(&apdu.lc.clone().unwrap_or_default());
            apdu_bytes.extend(&apdu.cdata.clone().unwrap_or_default());
            apdu_bytes.extend(&apdu.le.clone().unwrap_or_default());

            trace!("Sending APDU: {}", bytes2hex(&apdu_bytes));
            let mut response_buffer = [0; pcsc::MAX_BUFFER_SIZE];

            return match self.card.transmit(&apdu_bytes, &mut response_buffer) {
                Ok(response) => {
                    if response.len() < 2 {
                        error!(
                            "Card response length should be greater than or equal to 2, found {}",
                            response.len()
                        );
                        return Err(EmrtdError::InvalidResponseError());
                    }

                    let status_bytes: [u8; 2] =
                        [response[response.len() - 2], response[response.len() - 1]];

                    let data = response[..response.len() - 2].to_vec();

                    trace!(
                        "APDU response ({:02X}{:02X}): {}",
                        status_bytes[0],
                        status_bytes[1],
                        bytes2hex(&data)
                    );

                    Ok((data, status_bytes))
                }
                Err(err) => Err(EmrtdError::PcscError(err)),
            };
        }

        self.increment_ssc()?;

        let Some(ref ssc) = self.ssc else {
            error!("SSC is not set but trying to send securely");
            return Err(EmrtdError::InvalidArgument(
                "SSC is not set but trying to send securely",
            ));
        };
        let Some(ref enc_alg) = self.enc_alg else {
            error!("Enc algorithm is not set but trying to send securely");
            return Err(EmrtdError::InvalidArgument(
                "Enc algorithm is not set but trying to send securely",
            ));
        };
        let Some(ref mac_alg) = self.mac_alg else {
            error!("MAC algorithm is not set but trying to send securely");
            return Err(EmrtdError::InvalidArgument(
                "MAC algorithm is not set but trying to send securely",
            ));
        };
        let Some(ref ks_enc) = self.ks_enc else {
            error!("Session key ks_enc is not set but trying to send securely");
            return Err(EmrtdError::InvalidArgument(
                "Session key ks_enc is not set but trying to send securely",
            ));
        };
        let Some(ref ks_mac) = self.ks_mac else {
            error!("Session key ks_mac is not set but trying to send securely");
            return Err(EmrtdError::InvalidArgument(
                "Session key ks_mac is not set but trying to send securely",
            ));
        };
        if self.pad_len == 0 {
            error!("Padding length is 0 but trying to send securely");
            return Err(EmrtdError::InvalidArgument(
                "Padding length is 0 but trying to send securely",
            ));
        }
        let pad_len = self.pad_len;
        let mut apdu = apdu.clone();

        apdu.cla |= 0x0C;

        let mut payload = Vec::new();
        if let Some(cdata) = &apdu.cdata {
            let data = &padding_method_2(cdata, pad_len)?;
            let encrypted_data = match enc_alg {
                EncryptionAlgorithm::DES3 => {
                    encrypt::<cbc::Encryptor<des::TdesEde3>>(ks_enc, Some(&[0; 8]), data)?
                }
                EncryptionAlgorithm::AES128 => {
                    let ssc_enc = encrypt_ecb::<ecb::Encryptor<aes::Aes128>>(ks_enc, ssc)?;
                    encrypt::<cbc::Encryptor<aes::Aes128>>(ks_enc, Some(&ssc_enc), data)?
                }
                EncryptionAlgorithm::AES192 => {
                    let ssc_enc = encrypt_ecb::<ecb::Encryptor<aes::Aes192>>(ks_enc, ssc)?;
                    encrypt::<cbc::Encryptor<aes::Aes192>>(ks_enc, Some(&ssc_enc), data)?
                }
                EncryptionAlgorithm::AES256 => {
                    let ssc_enc = encrypt_ecb::<ecb::Encryptor<aes::Aes256>>(ks_enc, ssc)?;
                    encrypt::<cbc::Encryptor<aes::Aes256>>(ks_enc, Some(&ssc_enc), data)?
                }
            };

            if apdu.ins % 2 == 0 {
                // For a command with even INS, any command data is encrypted
                // and encapsulated in a Tag 87 with padding indicator (01).
                let do87 = [
                    b"\x87",
                    (&*int2asn1len([&b"\x01"[..], &encrypted_data].concat().len())),
                    &[&b"\x01"[..], &encrypted_data].concat(),
                ]
                .concat();
                payload.extend_from_slice(&do87);
            } else {
                // For a command with odd INS, any command data is encrypted
                // and encapsulated in a Tag 85 without padding indicator.
                let do85 = [
                    b"\x85",
                    (&*int2asn1len(encrypted_data.len())),
                    &encrypted_data,
                ]
                .concat();
                payload.extend_from_slice(&do85);
            }
        }

        if let Some(le) = &apdu.le {
            // Commands with response (Le field not empty)
            // have a protected Le-field (Tag 97) in the command data.
            let do97 = [b"\x97", (&*int2asn1len(le.len())), le].concat();
            payload.extend_from_slice(&do97);
        }

        let padded_header = padding_method_2(&apdu.get_command_header(), pad_len)?;
        let n = padding_method_2(&[&ssc, (&*padded_header), &payload].concat(), pad_len)?;
        let cc = compute_mac(ks_mac, &n, mac_alg)?;

        let do8e = [b"\x8E", (&*int2asn1len(cc.len())), &cc].concat();
        payload.extend_from_slice(&do8e);

        let protected_apdu = [
            apdu.get_command_header(),
            [u8::try_from(payload.len()).map_err(EmrtdError::IntCastError)?].to_vec(),
            payload,
            b"\x00".to_vec(),
        ]
        .concat();

        trace!("Sending Protected APDU: {}", bytes2hex(&protected_apdu));
        let mut response_buffer = [0; pcsc::MAX_BUFFER_SIZE];

        match self.card.transmit(&protected_apdu, &mut response_buffer) {
            Ok(response) => {
                if response.len() < 2 {
                    error!(
                        "Card response length should be greater than or equal to 2, found {}",
                        response.len()
                    );
                    return Err(EmrtdError::InvalidResponseError());
                }

                let status_bytes: [u8; 2] =
                    [response[response.len() - 2], response[response.len() - 1]];

                let data = self.process_secure_rapdu(&response[..response.len() - 2])?;

                trace!(
                    "APDU response ({:02X}{:02X}): {}",
                    status_bytes[0],
                    status_bytes[1],
                    bytes2hex(&data)
                );

                Ok((data, status_bytes))
            }
            Err(err) => Err(EmrtdError::PcscError(err)),
        }
    }

    /// Processes a secured Application Protocol Data Unit response received from the smart card.
    ///
    /// # Arguments
    ///
    /// * `rapdu` - A slice containing the Secure `R_APDU` to be processed.
    ///
    /// # Returns
    ///
    /// Decrypted data or an `EmrtdError`.
    ///
    /// # Errors
    ///
    /// * `EmrtdError` in case of failure during processing of received APDU.
    fn process_secure_rapdu(&mut self, rapdu: &[u8]) -> Result<Vec<u8>, EmrtdError> {
        self.increment_ssc()?;

        let Some(ref ssc) = self.ssc else {
            error!("SSC is not set but trying to process R_APDU");
            return Err(EmrtdError::InvalidArgument(
                "SSC is not set but trying to process R_APDU",
            ));
        };
        let Some(ref enc_alg) = self.enc_alg else {
            error!("Enc algorithm is not set but trying to process R_APDU");
            return Err(EmrtdError::InvalidArgument(
                "Enc algorithm is not set but trying to process R_APDU",
            ));
        };
        let Some(ref mac_alg) = self.mac_alg else {
            error!("MAC algorithm is not set but trying to process R_APDU");
            return Err(EmrtdError::InvalidArgument(
                "MAC algorithm is not set but trying to process R_APDU",
            ));
        };
        let Some(ref ks_enc) = self.ks_enc else {
            error!("Session key ks_enc is not set but trying to process R_APDU");
            return Err(EmrtdError::InvalidArgument(
                "Session key ks_enc is not set but trying to process R_APDU",
            ));
        };
        let Some(ref ks_mac) = self.ks_mac else {
            error!("Session key ks_mac is not set but trying to process R_APDU");
            return Err(EmrtdError::InvalidArgument(
                "Session key ks_mac is not set but trying to process R_APDU",
            ));
        };
        if self.pad_len == 0 {
            error!("Padding length is 0 but trying to process R_APDU");
            return Err(EmrtdError::InvalidArgument(
                "Padding length is 0 but trying to process R_APDU",
            ));
        }
        let pad_len = self.pad_len;

        let mut encrypted_data = Vec::new();
        let mut decrypted_data = Vec::new();
        let mut do85: Option<&[u8]> = None;
        let mut do87: Option<&[u8]> = None;
        let mut do99: Option<&[u8]> = None;
        let mut do8e: Option<&[u8]> = None;

        trace!("R_APDU: {}", bytes2hex(rapdu));

        let mut rapdu = rapdu;
        loop {
            let (tl_len, value_len) = len2int(rapdu, 1)?;
            match rapdu[0] {
                b'\x85' => {
                    encrypted_data = rapdu[tl_len..tl_len + value_len].to_vec();
                    do85 = Some(&rapdu[..tl_len + value_len]);
                }
                b'\x87' => {
                    encrypted_data = rapdu[tl_len..tl_len + value_len].to_vec();
                    do87 = Some(&rapdu[..tl_len + value_len]);
                }
                b'\x99' => do99 = Some(&rapdu[..tl_len + value_len]),
                b'\x8e' => {
                    do8e = Some(&rapdu[tl_len..tl_len + value_len]);
                }
                _ => {
                    error!("Tag not supported in encrypted R_APDU");
                    return Err(EmrtdError::ParseDataError(format!(
                        "Tag {:02X} not supported in encrypted R_APDU",
                        rapdu[0]
                    )));
                }
            }
            rapdu = &rapdu[tl_len + value_len..];
            if rapdu.is_empty() {
                break;
            }
        }

        let k = padding_method_2(
            &[
                &ssc,
                do85.unwrap_or_default(),
                do87.unwrap_or_default(),
                do99.unwrap_or_default(),
            ]
            .concat(),
            pad_len,
        )?;
        let cc = compute_mac(ks_mac, &k, mac_alg)?;
        if !constant_time_eq(&cc, do8e.unwrap_or_default()) {
            error!("MAC verification failed");
            return Err(EmrtdError::VerifyMacError());
        }

        if !encrypted_data.is_empty() {
            // If INS is even, remove the padding indicator (01)
            if do87.is_some() {
                encrypted_data = encrypted_data[1..].to_vec();
            }
            // Decrypt
            let decrypted_padded_data = match enc_alg {
                EncryptionAlgorithm::DES3 => decrypt::<cbc::Decryptor<des::TdesEde3>>(
                    ks_enc,
                    Some(&[0; 8]),
                    &encrypted_data,
                )?,
                EncryptionAlgorithm::AES128 => {
                    let ssc_enc = encrypt_ecb::<ecb::Encryptor<aes::Aes128>>(ks_enc, ssc)?;
                    decrypt::<cbc::Decryptor<aes::Aes128>>(ks_enc, Some(&ssc_enc), &encrypted_data)?
                }
                EncryptionAlgorithm::AES192 => {
                    let ssc_enc = encrypt_ecb::<ecb::Encryptor<aes::Aes192>>(ks_enc, ssc)?;
                    decrypt::<cbc::Decryptor<aes::Aes192>>(ks_enc, Some(&ssc_enc), &encrypted_data)?
                }
                EncryptionAlgorithm::AES256 => {
                    let ssc_enc = encrypt_ecb::<ecb::Encryptor<aes::Aes256>>(ks_enc, ssc)?;
                    decrypt::<cbc::Decryptor<aes::Aes256>>(ks_enc, Some(&ssc_enc), &encrypted_data)?
                }
            };
            // Remove padding
            decrypted_data = remove_padding(&decrypted_padded_data).to_vec();
        }
        Ok(decrypted_data)
    }

    /// Selects the eMRTD application on the card.
    ///
    /// This function sends a command to select the eMRTD application using AID `A0000002471001`.
    ///
    /// # Returns
    ///
    /// Nothing if the selection is successful.
    ///
    /// # Errors
    ///
    /// `EmrtdError` in case of failure during sending the APDU.
    pub fn select_emrtd_application(&mut self) -> Result<(), EmrtdError> {
        // Select eMRTD application
        let aid = b"\xA0\x00\x00\x02\x47\x10\x01";
        info!(
            "Selecting eMRTD Application `International AID`: {}...",
            bytes2hex(aid)
        );
        let apdu = APDU::new(
            b'\x00',
            b'\xA4',
            b'\x04',
            b'\x0C',
            Some(int2asn1len(aid.len())),
            Some(aid.to_vec()),
            None,
        );
        match self.send(&apdu, false) {
            Ok((_, status)) => match status {
                [0x90, 0x00] => Ok(()),
                [sw1, sw2] => {
                    error!("Received invalid SW during Select eMRTD Application command: {sw1:02X} {sw2:02X}");
                    Err(EmrtdError::RecvApduError(sw1, sw2))
                }
            },
            Err(err) => {
                error!("Error while selecting eMRTD Application.");
                Err(err)
            }
        }
    }

    /// Selects a specific Elementary File (EF) on the smart card by sending a "Select File" APDU.
    ///
    /// # Arguments
    ///
    /// * `fid` - Array representing the File Identifier (FID) of the EF to select.
    /// * `fname` - The name of the file being selected (used for logging purposes).
    ///
    /// # Returns
    ///
    /// Nothing if successful, else an `EmrtdError`.
    ///
    /// # Errors
    ///
    /// * `EmrtdError` in case of failure during sending the APDU.
    pub fn select_ef(
        &mut self,
        fid: &[u8; 2],
        fname: &str,
        secure: bool,
    ) -> Result<(), EmrtdError> {
        // Send "Select File" APDU
        trace!("Selecting File {fname}: {}...", bytes2hex(fid));
        let apdu = APDU::new(
            b'\x00',
            b'\xA4',
            b'\x02',
            b'\x0C',
            Some(int2asn1len(fid.len())),
            Some(fid.to_vec()),
            None,
        );
        match self.send(&apdu, secure) {
            Ok((_, status)) => match status {
                [0x90, 0x00] => Ok(()),
                [sw1, sw2] => {
                    error!("Received invalid SW during Select EF command: {sw1:02X} {sw2:02X}");
                    Err(EmrtdError::RecvApduError(sw1, sw2))
                }
            },
            Err(err) => {
                error!("Error while selecting an EF.");
                Err(err)
            }
        }
    }

    /// Reads data from an EF (Elementary File) in an eMRTD (electronic Machine Readable Travel Document).
    ///
    /// This function sends APDU (Application Protocol Data Unit) commands to read the data from the EF.
    /// It starts by reading the first four bytes of the file, then determines the total length of the file.
    /// Afterward, it reads the rest of the bytes in chunks until it reaches the end of the file.
    /// `select_ef` function must be called before calling this function.
    ///
    /// # Returns
    ///
    /// The data read from the EF if successful, else an `EmrtdError`.
    ///
    /// # Errors
    ///
    /// * `EmrtdError` in case of failure.
    pub fn read_data_from_ef(&mut self, secure: bool) -> Result<Vec<u8>, EmrtdError> {
        // Read Binary of first four bytes
        let apdu = APDU::new(
            b'\x00',
            b'\xB0',
            b'\x00',
            b'\x00',
            None,
            None,
            Some(vec![b'\x04']),
        );
        // Send "Read Binary" APDU for the first 4 bytes
        trace!("Reading first 4 bytes from EF...");
        let mut data = match self.send(&apdu, secure) {
            Ok((data, status)) => match status {
                [0x90, 0x00] => data,
                [sw1, sw2] => {
                    error!("Received invalid SW during reading first 4 bytes of EF: {sw1:02X} {sw2:02X}");
                    return Err(EmrtdError::RecvApduError(sw1, sw2));
                }
            },
            Err(err) => {
                error!("Error while reading 4 bytes from EF.");
                return Err(err);
            }
        };

        if data.len() != 4 {
            error!(
                "Card response length should be equal to the requested amount 4, found {}",
                data.len()
            );
            return Err(EmrtdError::InvalidResponseError());
        }

        let data_len;
        {
            let (tl, v) = len2int(&data, 1)?;
            data_len = tl + v;
        };

        let mut offset = 4;

        // Read the rest of the bytes
        trace!("Reading {data_len} bytes from EF...");
        while offset < data_len {
            let le = if data_len - offset < 0xFA {
                [u8::try_from((data_len - offset) & 0xFF).map_err(EmrtdError::IntCastError)?]
            } else {
                [0x00]
            };

            // Send "Read Binary" APDU for the next chunk
            let offset_bytes = [
                u8::try_from(offset >> 8).map_err(EmrtdError::IntCastError)?,
                u8::try_from(offset & 0xFF).map_err(EmrtdError::IntCastError)?,
            ];
            let read_apdu = APDU::new(
                b'\x00',
                b'\xB0',
                offset_bytes[0],
                offset_bytes[1],
                None,
                None,
                Some(vec![le[0]]),
            );
            trace!("Reading next {} bytes from EF...", data_len - offset);
            let data_read = match self.send(&read_apdu, secure) {
                Ok((data, status)) => match status {
                    [0x90, 0x00] => data,
                    [sw1, sw2] => {
                        error!("Received invalid SW during reading bytes {} of EF: {sw1:02X} {sw2:02X}", data_len - offset);
                        return Err(EmrtdError::RecvApduError(sw1, sw2));
                    }
                },
                Err(err) => {
                    error!("Error while reading bytes from EF.");
                    return Err(err);
                }
            };

            if data_read.is_empty() {
                error!("Requested bytes while reading EF but received 0 bytes.");
                return Err(EmrtdError::InvalidResponseError());
            }

            // Append the new data to the result
            data.extend_from_slice(&data_read);
            offset += data_read.len();
        }

        if offset != data_len {
            error!(
                "Error while parsing EF data from the card, expected {offset}, found {data_len}."
            );
            return Err(EmrtdError::InvalidResponseError());
        }

        Ok(data)
    }

    /// Establishes session keys for Basic Access Control (BAC) protocol.
    ///
    /// For more details and examples, see ICAO Doc 9303-11 Section 4.3 and Appendix D.3
    /// <https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf>
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret key used for BAC (from MRZ, generate it using `other_mrz` function.
    ///
    /// # Returns
    ///
    /// * Nothing if successful, else an `EmrtdError`.
    ///
    /// # Errors
    ///
    /// * `EmrtdError` in case of failure during BAC session key establishment.
    pub fn establish_bac_session_keys(&mut self, secret: &[u8]) -> Result<(), EmrtdError> {
        let ba_key_seed = &generate_key_seed(secret)?[..16];

        // Calculate the basic access keys (ba_key_enc and ba_key_mac)
        trace!("Computing basic access keys...");
        let ba_key_enc = &compute_key(
            ba_key_seed,
            &KeyType::Encryption,
            &EncryptionAlgorithm::DES3,
        )?;
        let ba_key_mac = &compute_key(ba_key_seed, &KeyType::Mac, &EncryptionAlgorithm::DES3)?;

        // AUTHENTICATION AND ESTABLISHMENT OF SESSION KEYS
        trace!("Establishing session keys...");
        let apdu = APDU::new(
            b'\x00',
            b'\x84',
            b'\x00',
            b'\x00',
            None,
            None,
            Some(vec![b'\x08']),
        );
        let rnd_ic = match self.send(&apdu, false) {
            Ok((rnd_ic, status)) => match status {
                [0x90, 0x00] => rnd_ic,
                [sw1, sw2] => {
                    error!("Received invalid SW during establishing BAC session keys: {sw1:02X} {sw2:02X}");
                    return Err(EmrtdError::RecvApduError(sw1, sw2));
                }
            },
            Err(err) => {
                error!("Error while establishing BAC session keys.");
                return Err(err);
            }
        };

        let mut rnd_ifd: [u8; 8] = [0; 8];
        self.rng.fill_bytes(&mut rnd_ifd);
        let mut k_ifd: [u8; 16] = [0; 16];
        self.rng.fill_bytes(&mut k_ifd);

        let e_ifd = encrypt::<cbc::Encryptor<des::TdesEde3>>(
            ba_key_enc,
            Some(&[0; 8]),
            &[&rnd_ifd[..], (&*rnd_ic), &k_ifd[..]].concat(),
        )?;

        let m_ifd = compute_mac(
            &ba_key_mac.clone(),
            &padding_method_2(&e_ifd, 8)?,
            &MacAlgorithm::DES,
        )?;
        let cmd_data = [&e_ifd, (&*m_ifd)].concat();

        let apdu = APDU::new(
            b'\x00',
            b'\x82',
            b'\x00',
            b'\x00',
            Some(int2asn1len(cmd_data.len())),
            Some(cmd_data),
            Some(vec![b'\x28']),
        );
        let resp_data_enc = match self.send(&apdu, false) {
            Ok((resp_data_enc, status)) => match status {
                [0x90, 0x00] => resp_data_enc,
                [sw1, sw2] => {
                    error!("Received invalid SW during establishing BAC session keys: {sw1:02X} {sw2:02X}");
                    return Err(EmrtdError::RecvApduError(sw1, sw2));
                }
            },
            Err(err) => {
                error!("Error while establishing BAC session keys.");
                return Err(err);
            }
        };

        let m_ic = compute_mac(
            &ba_key_mac.clone(),
            &padding_method_2(&resp_data_enc[..resp_data_enc.len() - 8], 8)?,
            &MacAlgorithm::DES,
        )?;
        if !constant_time_eq(&m_ic, &resp_data_enc[resp_data_enc.len() - 8..]) {
            error!("MAC verification failed");
            return Err(EmrtdError::VerifyMacError());
        }

        let resp_data = decrypt::<cbc::Decryptor<des::TdesEde3>>(
            ba_key_enc,
            Some(&[0; 8]),
            &resp_data_enc[..resp_data_enc.len() - 8],
        )?;

        if !constant_time_eq(&resp_data[..8], &rnd_ic[..]) {
            error!("Error while establishing BAC session keys.");
            return Err(EmrtdError::InvalidResponseError());
        }

        if !constant_time_eq(&resp_data[8..16], &rnd_ifd[..]) {
            error!("Error while establishing BAC session keys.");
            return Err(EmrtdError::InvalidResponseError());
        }

        let k_ic: &[u8] = &resp_data[16..32];

        let ses_key_seed = xor_slices(&k_ifd, k_ic)?;

        let ks_enc = compute_key(
            &ses_key_seed,
            &KeyType::Encryption,
            &EncryptionAlgorithm::DES3,
        )?;
        let ks_mac = compute_key(&ses_key_seed, &KeyType::Mac, &EncryptionAlgorithm::DES3)?;

        let ssc = [&rnd_ic[4..], &rnd_ifd[4..]].concat();

        self.enc_alg = Some(EncryptionAlgorithm::DES3);
        self.mac_alg = Some(MacAlgorithm::DES);
        self.pad_len = 8;
        self.ks_enc = Some(ks_enc);
        self.ks_mac = Some(ks_mac);
        self.ssc = Some(ssc);

        Ok(())
    }

    /// Increment the Secure Session Counter (SSC).
    ///
    /// # Returns
    ///
    /// Nothing if successful, else an `EmrtdError` if the SSC is not set or overflows.
    ///
    /// # Errors
    ///
    /// * `EmrtdError` if SSC is invalid or overflows.
    fn increment_ssc(&mut self) -> Result<(), EmrtdError> {
        if let Some(ref mut ssc) = self.ssc {
            if ssc.len() == 8 {
                let int_val = u64::from_be_bytes(ssc.as_slice().try_into().unwrap());
                let incremented_val = int_val
                    .checked_add(1)
                    .ok_or(EmrtdError::OverflowSscError())?;
                *ssc = incremented_val.to_be_bytes().to_vec();
                Ok(())
            } else if ssc.len() == 16 {
                let int_val = u128::from_be_bytes(ssc.as_slice().try_into().unwrap());
                let incremented_val = int_val
                    .checked_add(1)
                    .ok_or(EmrtdError::OverflowSscError())?;
                *ssc = incremented_val.to_be_bytes().to_vec();
                Ok(())
            } else {
                unimplemented!("Only 8 and 16 byte SSC is supported");
            }
        } else {
            error!("SSC is not set but trying to increment");
            Err(EmrtdError::InvalidArgument(
                "SSC is not set but trying to increment",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    struct MockCard {}

    impl EmrtdCard for MockCard {
        fn get_attribute_owned(&self, attribute: pcsc::Attribute) -> Result<Vec<u8>, pcsc::Error> {
            if attribute == AtrString {
                return Ok(b"\x00\x01\x02\x03\x04\x05\x06\x07".to_vec())
            }
            return Err(pcsc::Error::InvalidAtr)
        }
        fn transmit<'buf>(&self, send_buffer: &[u8], receive_buffer: &'buf mut [u8]) -> Result<&'buf [u8], pcsc::Error> {
            // Select eMRTD application
            if send_buffer == hex!("00A4040C07A0000002471001") {
                return Ok(&hex!("9000"));
            // Request an 8 byte random number
            } else if send_buffer == hex!("0084000008") {
                return Ok(&hex!("4608F91988702212 9000"));
            // EXTERNAL AUTHENTICATE command
            } else if send_buffer == hex!("0082000028 72C29C2371CC9BDB65B779B8E8D37B29ECC154AA
                                        56A8799FAE2F498F76ED92F25F1448EEA8AD90A7 28") {
                return Ok(&hex!("46B9342A41396CD7386BF5803104D7CEDC122B91
                                32139BAF2EEDC94EE178534F2F2D235D074D7449 9000"));
            } else {
                // Return some random error
                return Err(pcsc::Error::CancelledByUser);
            }
        }
    }

    #[derive(Clone, Debug)]
    struct MockRng {
        data: Vec<u8>,
        index: usize,
    }

    impl Default for MockRng {
        fn default() -> MockRng {
            MockRng {
                data: hex!("781723860C06C226
                            0B795240CB7049B01C19B33E32804F0B").to_vec(),
                index: 0,
            }
        }
    }

    impl CryptoRng for MockRng {}

    impl RngCore for MockRng {
        fn next_u32(&mut self) -> u32 {
            unimplemented!()
        }

        fn next_u64(&mut self) -> u64 {
            unimplemented!()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest.iter_mut() {
                *byte = self.data[self.index];
                self.index = (self.index + 1) % self.data.len();
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            unimplemented!()
        }
    }

    #[test]
    fn test_calculate_check_digit_valid_data() -> Result<(), EmrtdError> {
        // Examples taken from https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf Appendix A
        let result = calculate_check_digit("520727");
        assert_eq!(result?, '3');

        let result = calculate_check_digit("AB2134<<<");
        assert_eq!(result?, '5');

        let result = calculate_check_digit("HA672242<658022549601086<<<<<<<<<<<<<<0");
        assert_eq!(result?, '8');

        let result = calculate_check_digit("D231458907<<<<<<<<<<<<<<<34071279507122<<<<<<<<<<<");
        assert_eq!(result?, '2');

        let result = calculate_check_digit("HA672242<658022549601086<<<<<<<");
        assert_eq!(result?, '8');

        let result = calculate_check_digit("");
        assert_eq!(result?, '0');

        let result = calculate_check_digit("1");
        assert_eq!(result?, '7');

        Ok(())
    }

    #[test]
    fn test_calculate_check_digit_invalid_character() -> Result<(), EmrtdError> {
        let result = calculate_check_digit("ABC*123");
        assert!(result.is_err_and(|e| matches!(e, EmrtdError::ParseMrzCharError('*'))));
        Ok(())
    }

    #[test]
    fn test_other_mrz_valid_input() -> Result<(), EmrtdError> {
        // Example taken from https://www.icao.int/publications/Documents/9303_p4_cons_en.pdf Appendix B
        let result = other_mrz("L898902C3", "740812", "120415");
        assert_eq!(result?, String::from("L898902C3674081221204159"));

        // Examples taken from https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix D.2
        let result = other_mrz("D23145890734", "340712", "950712");
        assert_eq!(result?, String::from("D23145890734934071279507122"));

        let result = other_mrz("L898902C<", "690806", "940623");
        assert_eq!(result?, String::from("L898902C<369080619406236"));

        // Example taken from https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix G
        let result = other_mrz("T22000129", "640812", "101031");
        assert_eq!(result?, String::from("T22000129364081251010318"));

        Ok(())
    }

    #[test]
    fn test_other_mrz_invalid_input() -> Result<(), EmrtdError> {
        let result = other_mrz("L898902C300000000000000", "740812", "120415");
        assert!(
            result.is_err_and(|e| matches!(e, EmrtdError::ParseMrzFieldError("Document number", _)))
        );

        let result = other_mrz("L898902C3", "7408121", "120415");
        assert!(result.is_err_and(|e| matches!(e, EmrtdError::ParseMrzFieldError("Birth date", _))));

        let result = other_mrz("L898902C3", "740812", "1204151");
        assert!(result.is_err_and(|e| matches!(e, EmrtdError::ParseMrzFieldError("Expiry date", _))));

        Ok(())
    }

    #[test]
    fn test_len2int_valid_input() -> Result<(), EmrtdError> {
        let result = len2int(&hex!("2A"), 0);
        assert_eq!(result?, (1, 42));

        let result = len2int(&hex!("302A"), 1);
        assert_eq!(result?, (2, 42));

        let result = len2int(&hex!("308207E8"), 1);
        assert_eq!(result?, (4, 2024));

        let result = len2int(&hex!("3030308207E8"), 3);
        assert_eq!(result?, (6, 2024));

        let result = len2int(&hex!("3083010000"), 1);
        assert_eq!(result?, (5, 0x0001_0000));
        Ok(())
    }

    #[test]
    fn test_len2int_invalid_input() -> Result<(), EmrtdError> {
        let result = len2int(&hex!("30"), 1);
        assert!(result.is_err_and(|e| matches!(e, EmrtdError::ParseAsn1DataError(2, 1))));

        let result = len2int(&hex!("3082"), 1);
        assert!(result.is_err_and(|e| matches!(e, EmrtdError::ParseAsn1DataError(4, 2))));
        Ok(())
    }

    #[test]
    fn test_int2asn1len() {
        let result = int2asn1len(0);
        assert_eq!(result, hex!("00").to_vec());

        let result = int2asn1len(42);
        assert_eq!(result, hex!("2A").to_vec());

        let result = int2asn1len(127);
        assert_eq!(result, hex!("7F").to_vec());

        let result = int2asn1len(2024);
        assert_eq!(result, hex!("8207E8").to_vec());

        let result = int2asn1len(0x0001_0000);
        assert_eq!(result, hex!("83010000").to_vec());

        let result = len2int(&int2asn1len(0x0001_0000), 0)
            .expect("Value should be valid")
            .1;
        assert_eq!(result, 0x0001_0000);

        let result = len2int(&int2asn1len(usize::MAX), 0)
            .expect("Value should be valid")
            .1;
        assert_eq!(result, usize::MAX);
    }

    #[test]
    fn test_generate_key_seed_valid() -> Result<(), EmrtdError> {
        // Example taken from https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix D
        let result = generate_key_seed(b"L898902C<369080619406236");
        assert_eq!(&result?[..16], &hex!("239AB9CB282DAF66231DC5A4DF6BFBAE"));

        // Example taken from https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix G
        let result = generate_key_seed(b"T22000129364081251010318");
        assert_eq!(
            &result?,
            &hex!("7E2D2A41 C74EA0B3 8CD36F86 3939BFA8 E9032AAD")
        );

        Ok(())
    }

    #[test]
    fn test_compute_key_valid_input() -> Result<(), EmrtdError> {
        // Example taken from https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix D.1
        let key_seed = hex!("239AB9CB282DAF66231DC5A4DF6BFBAE");
        let result = compute_key(
            key_seed.as_ref(),
            &KeyType::Encryption,
            &EncryptionAlgorithm::DES3,
        );
        assert_eq!(
            &result?,
            &hex!("AB94FDECF2674FDFB9B391F85D7F76F2AB94FDECF2674FDF")
        );
        let result = compute_key(key_seed.as_ref(), &KeyType::Mac, &EncryptionAlgorithm::DES3);
        assert_eq!(&result?, &hex!("7962D9ECE03D1ACD4C76089DCE131543"));

        // Example taken from https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix G.1
        let shared_secret =
            hex!("28768D20 701247DA E81804C9 E780EDE5 82A9996D B4A31502 0B273319 7DB84925");
        let result = compute_key(
            shared_secret.as_ref(),
            &KeyType::Encryption,
            &EncryptionAlgorithm::AES128,
        );
        assert_eq!(&result?, &hex!("F5F0E35C 0D7161EE 6724EE51 3A0D9A7F"));
        let result = compute_key(
            shared_secret.as_ref(),
            &KeyType::Mac,
            &EncryptionAlgorithm::AES128,
        );
        assert_eq!(&result?, &hex!("FE251C78 58B356B2 4514B3BD 5F4297D1"));

        // Example taken from https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix G.2
        let shared_secret = hex!(
            "6BABC7B3 A72BCD7E A385E4C6 2DB2625B
            D8613B24 149E146A 629311C4 CA6698E3
            8B834B6A 9E9CD718 4BA8834A FF5043D4
            36950C4C 1E783236 7C10CB8C 314D40E5
            990B0DF7 013E64B4 549E2270 923D06F0
            8CFF6BD3 E977DDE6 ABE4C31D 55C0FA2E
            465E553E 77BDF75E 3193D383 4FC26E8E
            B1EE2FA1 E4FC97C1 8C3F6CFF FE2607FD"
        );
        let result = compute_key(
            shared_secret.as_ref(),
            &KeyType::Encryption,
            &EncryptionAlgorithm::AES128,
        );
        assert_eq!(&result?, &hex!("2F7F46AD CC9E7E52 1B45D192 FAFA9126"));
        let result = compute_key(
            shared_secret.as_ref(),
            &KeyType::Mac,
            &EncryptionAlgorithm::AES128,
        );
        assert_eq!(&result?, &hex!("805A1D27 D45A5116 F73C5446 9462B7D8"));

        // Example taken from https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix H.1
        let shared_secret =
            hex!("4F150FDE 1D4F0E38 E95017B8 91BAE171 33A0DF45 B0D3E18B 60BA7BEA FDC2C713");
        let result = compute_key(
            shared_secret.as_ref(),
            &KeyType::Encryption,
            &EncryptionAlgorithm::AES128,
        );
        assert_eq!(&result?, &hex!("0D3FEB33 251A6370 893D62AE 8DAAF51B"));
        let result = compute_key(
            shared_secret.as_ref(),
            &KeyType::Mac,
            &EncryptionAlgorithm::AES128,
        );
        assert_eq!(&result?, &hex!("B01E89E3 D9E8719E 586B50B4 A7506E0B"));

        // Example taken from https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix H.2
        let shared_secret = hex!(
            "419410D6 C0A17A4C 07C54872 CE1CBCEB
            0A2705C1 A434C8A8 9A4CFE41 F1D78124
            CA7EC52B DE7615E5 345E48AB 1ABB6E7D
            1D59A57F 3174084D 3CA45703 97C1F622
            28BDFDB2 DA191EA2 239E2C06 0DBE3BBC
            23C2FCD0 AF12E0F9 E0B99FCF 91FF1959
            011D5798 B2FCBC1F 14FCC24E 441F4C8F
            9B08D977 E9498560 E63E7FFA B3134EA7"
        );
        let result = compute_key(
            shared_secret.as_ref(),
            &KeyType::Encryption,
            &EncryptionAlgorithm::AES128,
        );
        assert_eq!(&result?, &hex!("01AFC10C F87BE36D 8179E873 70171F07"));
        let result = compute_key(
            shared_secret.as_ref(),
            &KeyType::Mac,
            &EncryptionAlgorithm::AES128,
        );
        assert_eq!(&result?, &hex!("23F0FBD0 5FD6C7B8 B88F4C83 09669061"));

        // Examples taken from https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix I.1
        let shared_secret =
            hex!("67950559 D0C06B4D 4B86972D 14460837 461087F8 419FDBC3 6AAF6CEA AC462832");
        let result = compute_key(
            shared_secret.as_ref(),
            &KeyType::Encryption,
            &EncryptionAlgorithm::AES128,
        );
        assert_eq!(&result?, &hex!("0A9DA4DB 03BDDE39 FC5202BC 44B2E89E"));
        let result = compute_key(
            shared_secret.as_ref(),
            &KeyType::Mac,
            &EncryptionAlgorithm::AES128,
        );
        assert_eq!(&result?, &hex!("4B1C0649 1ED5140C A2B537D3 44C6C0B1"));

        Ok(())
    }

    #[test]
    fn test_compute_mac() -> Result<(), EmrtdError> {
        // Examples taken from https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix D.3
        let data = hex!("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2");
        let result = compute_mac(
            &hex!("7962D9ECE03D1ACD4C76089DCE131543"),
            &padding_method_2(data.as_ref(), 8)?,
            &MacAlgorithm::DES,
        );
        assert_eq!(&result?, &hex!("5F1448EEA8AD90A7"));

        let data = hex!("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F");
        let result = compute_mac(
            &hex!("7962D9ECE03D1ACD4C76089DCE131543"),
            &padding_method_2(data.as_ref(), 8)?,
            &MacAlgorithm::DES,
        );
        assert_eq!(&result?, &hex!("2F2D235D074D7449"));

        // Examples taken from https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf Appendix D.4
        let data = hex!("887022120C06C2270CA4020C800000008709016375432908C044F6");
        let result = compute_mac(
            &hex!("F1CB1F1FB5ADF208806B89DC579DC1F8"),
            &padding_method_2(data.as_ref(), 8)?,
            &MacAlgorithm::DES,
        );
        assert_eq!(&result?, &hex!("BF8B92D635FF24F8"));

        let data = hex!("887022120C06C22899029000");
        let result = compute_mac(
            &hex!("F1CB1F1FB5ADF208806B89DC579DC1F8"),
            &padding_method_2(data.as_ref(), 8)?,
            &MacAlgorithm::DES,
        );
        assert_eq!(&result?, &hex!("FA855A5D4C50A8ED"));

        let data = hex!("887022120C06C2290CB0000080000000970104");
        let result = compute_mac(
            &hex!("F1CB1F1FB5ADF208806B89DC579DC1F8"),
            &padding_method_2(data.as_ref(), 8)?,
            &MacAlgorithm::DES,
        );
        assert_eq!(&result?, &hex!("ED6705417E96BA55"));

        let data = hex!("887022120C06C22A8709019FF0EC34F992265199029000");
        let result = compute_mac(
            &hex!("F1CB1F1FB5ADF208806B89DC579DC1F8"),
            &padding_method_2(data.as_ref(), 8)?,
            &MacAlgorithm::DES,
        );
        assert_eq!(&result?, &hex!("AD55CC17140B2DED"));

        let data = hex!("887022120C06C22B0CB0000480000000970112");
        let result = compute_mac(
            &hex!("F1CB1F1FB5ADF208806B89DC579DC1F8"),
            &padding_method_2(data.as_ref(), 8)?,
            &MacAlgorithm::DES,
        );
        assert_eq!(&result?, &hex!("2EA28A70F3C7B535"));

        let data =
            hex!("887022120C06C22C871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A99029000");
        let result = compute_mac(
            &hex!("F1CB1F1FB5ADF208806B89DC579DC1F8"),
            &padding_method_2(data.as_ref(), 8)?,
            &MacAlgorithm::DES,
        );
        assert_eq!(&result?, &hex!("C8B2787EAEA07D74"));

        Ok(())
    }

    #[cfg(feature = "passive_auth")]
    #[test]
    fn test_oid2digestalg_known_oid() -> Result<(), EmrtdError> {
        let result = oid2digestalg(
            &rasn::types::ObjectIdentifier::new(vec![2, 16, 840, 1, 101, 3, 4, 2, 1]).unwrap(),
        )?;
        assert!(result.eq(&MessageDigest::sha256()));

        Ok(())
    }

    #[cfg(feature = "passive_auth")]
    #[test]
    fn test_oid2digestalg_unknown_oid() -> Result<(), EmrtdError> {
        // ripemd256
        let result =
            oid2digestalg(&rasn::types::ObjectIdentifier::new(vec![1, 3, 36, 3, 2, 3]).unwrap());

        assert!(result.is_err_and(|e| matches!(e, EmrtdError::InvalidOidError())));
        Ok(())
    }

    #[test]
    fn test_send() -> Result<(), EmrtdError> {
        use hex_literal::hex;

        let mock_card = MockCard {};
        let mut sm_object = EmrtdComms::<MockCard, MockRng>::new(mock_card);
        let result = sm_object.get_atr()?;
        assert_eq!(&result, &hex!("0001020304050607"));

        Ok(())
    }

    #[test]
    fn test_establish_bac_session_keys() -> Result<(), EmrtdError> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .init();

        use hex_literal::hex;

        let mock_card = MockCard {};
        let mut sm_object = EmrtdComms::<MockCard, MockRng>::new(mock_card);
        let result = sm_object.get_atr()?;
        assert_eq!(&result, &hex!("0001020304050607"));

        sm_object.select_emrtd_application()?;

        sm_object.establish_bac_session_keys(b"L898902C<369080619406236")?;

        Ok(())
    }
}
