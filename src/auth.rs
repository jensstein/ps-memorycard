use std::path::Path;

use crate::errors::{CryptographyError,Error};
use crate::memorycard::{MemoryCard, PS2MemoryCard};
use crate::{calculate_edc, validate_response_success};

use cbc::cipher::KeyIvInit;
use cbc::cipher::BlockEncryptMut;
use cbc::cipher::BlockDecryptMut;
use cbc::cipher::block_padding::NoPadding;

// Eight random bytes
const M_NONCE: [u8; 8] = [0x8c, 0x1, 0xc7, 0x6e, 0x39, 0x69, 0x96, 0xfe];

struct Challenges {
    c1: Vec<u8>,
    c2: Vec<u8>,
    c3: Vec<u8>,
}

impl PS2MemoryCard {
    fn auth_cmd(&self, cmd: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        let _write_result = self.write_to_device(&cmd);
        let response = self.read_from_device(length)?;
        if !validate_response_success(&response) {
            return Err(Error::new(format!("Invalid response for command: {:?}", cmd)))
        }
        Ok(response)
    }

    fn auth_cmd_without_response(&self, b1: u8, b2: u8) -> Result<(), Error> {
        let cmd = get_auth_cmd(b1, b2);
        self.auth_cmd(&cmd, 9)?;
        Ok(())
    }

    fn auth_cmd_with_response(&self, b1: u8, b2: u8) -> Result<Vec<u8>, Error> {
        let cmd = get_auth_cmd(b1, b2);
        let cmd = [cmd.as_ref(), &[0, 0, 0, 0, 0, 0, 0, 0, 0]].concat();
        self.auth_cmd(&cmd, 18)
    }

    fn write_auth_data(&self, b1: u8, b2: u8, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut cmd = vec![0x81, b1, b2];
        // This is a checksum of the data to send
        let ecd = calculate_edc(data);
        let mut data = data.to_owned();
        data.reverse();
        cmd.append(&mut data);
        // Two trailing zeros like the other auth commands
        cmd.append(&mut vec![ecd, 0, 0]);
        self.auth_cmd(&cmd, 18)
    }

    pub fn auth_reset(&self) -> Result<(), Error> {
        self.auth_cmd_without_response(0xf3, 0x00)
    }

    // The python program performs these steps with an external authentication mechanism:
    // https://github.com/vpelletier/ps3-memorycard-adapter/blob/a925dd392f4af6c4273c04f8743e8a46f12c2260/nbd/memory_card_reader.py#L382
    // In ps3mca-tool these steps are performed in `Card_Authentificate`.
    pub fn authenticate(&self, card_keys: &CardKeys) -> Result<Vec<u8>, Error> {
        self.auth_reset()?;
        self.auth_cmd_without_response(0xf7, 0x01)?;
        // The following steps go from 0x00 to 0x14
        self.auth_cmd_without_response(0xf0, 0x00)?;
        let card_iv: [u8; 8] = parse_auth_response(
            &mut self.auth_cmd_with_response(0xf0, 0x01)?)
            .try_into()?;
        let card_material = parse_auth_response(&mut self.auth_cmd_with_response(0xf0, 0x02)?);
        let unique_key: [u8; 16] = calculate_unique_key(card_keys, card_iv, card_material.try_into()?)?.try_into()?;
        self.auth_cmd_without_response(0xf0, 0x03)?;
        // This value is different on each invocation
        // https://en.wikipedia.org/wiki/Cryptographic_nonce
        let nonce = parse_auth_response(&mut self.auth_cmd_with_response(0xf0, 0x04)?).try_into()?;
        self.auth_cmd_without_response(0xf0, 0x05)?;
        let challenges = generate_challenges(nonce, card_iv, unique_key)?;
        self.write_auth_data(0xf0, 0x06, &challenges.c3)?;
        self.write_auth_data(0xf0, 0x07, &challenges.c2)?;
        self.auth_cmd_without_response(0xf0, 0x08)?;
        self.auth_cmd_without_response(0xf0, 0x09)?;
        self.auth_cmd_without_response(0xf0, 0x0a)?;
        self.write_auth_data(0xf0, 0x0b, &challenges.c1)?;
        self.auth_cmd_without_response(0xf0, 0x0c)?;
        self.auth_cmd_without_response(0xf0, 0x0d)?;
        self.auth_cmd_without_response(0xf0, 0x0e)?;
        let card_response_1 = parse_auth_response(&mut self.auth_cmd_with_response(0xf0, 0x0f)?);
        self.auth_cmd_without_response(0xf0, 0x10)?;
        let card_response_2 = parse_auth_response(&mut self.auth_cmd_with_response(0xf0, 0x11)?);
        self.auth_cmd_without_response(0xf0, 0x12)?;
        let card_response_3 = parse_auth_response(&mut self.auth_cmd_with_response(0xf0, 0x13)?);
        self.auth_cmd_without_response(0xf0, 0x14)?;
        // The IV here is just random bytes. In ps3mca-tool the value used here is `MC_CHALLENGE_MATERIAL`.
        let _decrypted_key_1 = decrypt(unique_key, [0x47, 0x73, 0xb8, 0x50, 0x88, 0xc5, 0x16, 0xea], &card_response_1)?;
        let _decrypted_key_2 = decrypt(unique_key, card_response_1[..].try_into()?, &card_response_2)?;
        let decrypted_key_3 = decrypt(unique_key, card_response_2[..].try_into()?, &card_response_3)?;
        // TODO: `decrypted_key_1` is supposed to match `nonce` and `decrypted_key_2` is supposed to
        // match `M_NONCE`. But they don't seem to with this implementation so maybe I'm missing
        // something.
        // It might only matter when trying to read or write the content key of the card.
        // https://patents.google.com/patent/EP1505595A2/en
        Ok(decrypted_key_3)
    }

    pub fn validate(&self) -> Result<Vec<u8>, Error> {
        let cmd = get_auth_cmd(0x28, 0x00);
        self.auth_cmd(&cmd, 9)
    }

    // You seem to need to set the termination code to avoid having to authenticate on every
    // request.
    pub fn set_termination_code(&self) -> Result<Vec<u8>, Error> {
        let cmd = get_auth_cmd(0x27, 0x5a);
        self.auth_cmd(&cmd, 9)
    }
}

// Auth commands that don't write data to the device are all 0x81 + two bytes with either two or nine trailing zeros
fn get_auth_cmd(b1: u8, b2: u8) -> [u8; 5] {
    [0x81, b1, b2, 0, 0]
}

fn xor(a1: [u8; 8], a2: [u8; 8]) -> Vec<u8> {
    a1.iter().zip(a2).map(|(x1, x2)| x1 ^ x2).collect()
}

fn parse_auth_response(input: &mut Vec<u8>) -> Vec<u8> {
    input.reverse();
    input[2..10].into()
}

#[derive(Debug)]
pub struct CardKeys {
    // This value is called `MC_CARDKEY_HASHKEY_1` in ps3mca-tool
    k1: [u8; 16],
    // This value is called `MC_CARDKEY_HASHKEY_2` in ps3mca-tool
    k2: [u8; 16],
    // This value is called `MC_CARDKEY_MATERIAL_1` in ps3mca-tool
    iv1: [u8; 8],
    // This value is called `MC_CARDKEY_MATERIAL_2` in ps3mca-tool
    iv2: [u8; 8],
}

pub fn read_card_keys(directory: &Path) -> Result<CardKeys, Error> {
    let k1 = std::fs::read(directory.join("k1.bin"))?;
    let k2 = std::fs::read(directory.join("k2.bin"))?;
    let iv1 = std::fs::read(directory.join("iv1.bin"))?;
    let iv2 = std::fs::read(directory.join("iv2.bin"))?;
    Ok(CardKeys {
        k1: k1.try_into()?,
        k2: k2.try_into()?,
        iv1: iv1.try_into()?,
        iv2: iv2.try_into()?,
    })
}

// This function is a port of the `meCardCalcUniqueKey` function in ps3mca-tool
fn calculate_unique_key(keys: &CardKeys, m1: [u8; 8], m2: [u8; 8]) -> Result<Vec<u8>, Error> {
    let input = xor(m1, m2);
    let mut part1 = encrypt(keys.k1, keys.iv1, &input)?;
    let mut part2 = encrypt(keys.k2, keys.iv2, &input)?;
    part1.append(&mut part2);
    Ok(part1)
}

// This function is a port of the `meCardGenerateChallenge` function in ps3mca-tool
fn generate_challenges(nonce: [u8; 8], iv: [u8; 8], unique_key: [u8; 16]) -> Result<Challenges, Error> {
    // The IV and input here are just random bytes generated with python `[hex(random.randint(0, 255)) for _ in range(8)]`
    // In ps3mca-tool the corresponding values are also hardcoded in the variables MC_CHALLENGE_MATERIAL and MechaNonce.
    let c1 = encrypt(unique_key, [0xfc, 0xfa, 0x11, 0x4e, 0xfe, 0xd7, 0x69, 0x2],
        &M_NONCE)?;
    let c2 = encrypt(unique_key, c1.clone().try_into()?, &nonce)?;
    let c3 = encrypt(unique_key, c2.clone().try_into()?, &iv)?;
    Ok(Challenges {
        c1, c2, c3
    })
}

fn encrypt(key: [u8; 16], iv: [u8; 8], input: &[u8]) -> Result<Vec<u8>, CryptographyError> {
    let mut buf = [0; 8];
    // The encryptor instance is consumed when encrypting, so it needs to be instantiated every
    // time.
    // https://github.com/RustCrypto/block-ciphers/issues/285
    // TdesEde2: Triple DES with keying option 2 where k3 == k1 in encryption-decryption-encryption mode.
    // https://csrc.nist.gov/csrc/media/publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf
    Ok(cbc::Encryptor::<des::TdesEde2>::new(&key.into(), &iv.into())
        .encrypt_padded_b2b_mut::<NoPadding>(input, &mut buf)?
        .into())
}

fn decrypt(key: [u8; 16], iv: [u8; 8], input: &[u8]) -> Result<Vec<u8>, CryptographyError> {
    let mut buf = [0; 8];
    Ok(cbc::Decryptor::<des::TdesEde2>::new(&key.into(), &iv.into())
        .decrypt_padded_b2b_mut::<NoPadding>(input, &mut buf)?
        .into())
}
