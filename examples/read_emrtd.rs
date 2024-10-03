use std::env;

use emrtd::{bytes2hex, get_jpeg_from_ef_dg2, other_mrz, EmrtdComms, EmrtdError};
use tracing::{error, info};

#[cfg(feature = "passive_auth")]
use emrtd::{parse_master_list, passive_authentication, validate_dg};

fn main() -> Result<(), EmrtdError> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();

    // Establish a PC/SC context.
    let ctx = match pcsc::Context::establish(pcsc::Scope::User) {
        Ok(ctx) => ctx,
        Err(err) => {
            error!("Failed to establish context: {err}");
            std::process::exit(1);
        }
    };

    // List available readers.
    let mut readers_buf = [0; 2048];
    let mut readers = match ctx.list_readers(&mut readers_buf) {
        Ok(readers) => readers,
        Err(err) => {
            error!("Failed to list readers: {err}");
            std::process::exit(1);
        }
    };

    // Use the first reader.
    let reader = match readers.next() {
        Some(reader) => reader,
        None => {
            error!("No readers are connected.");
            std::process::exit(1);
        }
    };
    info!("Using reader: {reader:?}");

    // Connect to the card.
    let card = match ctx.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY) {
        Ok(card) => card,
        Err(pcsc::Error::NoSmartcard) => {
            error!("A smartcard is not present in the reader.");
            std::process::exit(1);
        }
        Err(err) => {
            error!("Failed to connect to card: {err}");
            std::process::exit(1);
        }
    };

    let mut sm_object = EmrtdComms::<pcsc::Card>::new(card);

    // Get the card's ATR.
    info!("ATR from attribute: {}", bytes2hex(&sm_object.get_atr()?));

    // Read EF.CardAccess
    // sm_object.select_ef(b"\x01\x1C", "EF.CardAccess", false)?;
    // let ef_cardacess = sm_object.read_data_from_ef(false)?;
    // info!("Data from the EF.CardAccess: {}", bytes2hex(&ef_cardacess));

    // Read EF.DIR
    // sm_object.select_ef(b"\x2F\x00", "EF.DIR", false)?;
    // let ef_dir = sm_object.read_data_from_ef(false)?;
    // info!("Data from the EF.DIR: {}", bytes2hex(&ef_dir));

    // Select eMRTD application
    sm_object.select_emrtd_application()?;

    let doc_no = env::var("DOCNO").expect("Please set DOCNO environment variable");
    let birthdate = env::var("BIRTHDATE").expect("Please set BIRTHDATE environment variable");
    let expirydate = env::var("EXPIRYDATE").expect("Please set EXPIRYDATE environment variable");

    let secret = other_mrz(&doc_no, &birthdate, &expirydate)?;

    sm_object.establish_bac_session_keys(secret.as_bytes())?;

    // Read EF.COM
    sm_object.select_ef(b"\x01\x1E", "EF.COM", true)?;
    let ef_com = sm_object.read_data_from_ef(true)?;
    info!("Data from the EF.COM: {}", bytes2hex(&ef_com));

    // Read EF.SOD
    sm_object.select_ef(b"\x01\x1D", "EF.SOD", true)?;
    let ef_sod = sm_object.read_data_from_ef(true)?;
    info!("Data from the EF.SOD: {}", bytes2hex(&ef_sod));

    let result;
    #[cfg(feature = "passive_auth")]
    {
        let master_list = include_bytes!("../data/DE_ML_2024-04-10-10-54-13.ml");
        let csca_cert_store = parse_master_list(master_list)?;
        info!(
            "Number of certificates parse from the Master List in the store {}",
            csca_cert_store.all_certificates().len()
        );
        result = passive_authentication(&ef_sod, &csca_cert_store).unwrap();
        info!("{:?} {:?} {:?}", result.0.type_(), result.1, result.2);
    }

    // Read EF.DG1
    sm_object.select_ef(b"\x01\x01", "EF.DG1", true)?;
    let ef_dg1 = sm_object.read_data_from_ef(true)?;
    info!("Data from the EF.DG1: {}", bytes2hex(&ef_dg1));
    #[cfg(feature = "passive_auth")]
    validate_dg(&ef_dg1, 1, result.0, &result.1)?;

    // Read EF.DG2
    sm_object.select_ef(b"\x01\x02", "EF.DG2", true)?;
    let ef_dg2 = sm_object.read_data_from_ef(true)?;
    info!("Data from the EF.DG2: {}", bytes2hex(&ef_dg2));
    #[cfg(feature = "passive_auth")]
    validate_dg(&ef_dg2, 2, result.0, &result.1)?;

    let jpeg = get_jpeg_from_ef_dg2(&ef_dg2)?;
    std::fs::write("face.jpg", jpeg).expect("Error writing file");

    return Ok(());
}
