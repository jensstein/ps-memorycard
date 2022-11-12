pub mod auth;
pub mod errors;
pub mod memorycard;

use std::time::Duration;

use crate::memorycard::{MemoryCard, PS2MemoryCard};
use crate::errors::Error;

#[derive(Debug,Clone,PartialEq)]
pub enum CardType {
    PS1,
    PS2,
    Unknown,
    NotPresent,
}

// This enum is used to indicate which memory card implementation you get from reading the device.
// By returning an enum like this instead of returning a boxed trait, I avoid being forced to
// handle references and implement casting to Any.
// https://bennett.dev/dont-use-boxed-trait-objects-for-struct-internals/
pub enum CardResult {
    PS1,
    PS2(PS2MemoryCard),
}

pub struct CardInfo {
    pub page_size: u16,
    block_size: u16,
    // This value doesn't seem to be reliable. I have a 64MB card which reports itself as 8MB.
    pub card_size: u32,
}

impl CardInfo {
    fn new(page_size: u16, block_size: u16, pages: u32) -> Self {
        Self {page_size, block_size, card_size: pages * page_size as u32}
    }
}

// When this module is compiled for tests a MockUSBDevice trait is added
#[cfg_attr(test, mockall::automock)]
pub trait USBDevice {
    fn write_bulk(&self, endpoint: u8, buf: &[u8], timeout: Duration) -> Result<usize, rusb::Error>;
    fn read_bulk(&self, endpoint: u8, buf: &mut [u8], timeout: Duration) -> Result<usize, rusb::Error>;
}

impl USBDevice for rusb::DeviceHandle<rusb::GlobalContext> {
    fn write_bulk(&self, endpoint: u8, buf: &[u8], timeout: Duration) -> Result<usize, rusb::Error>{
        self.write_bulk(endpoint, buf, timeout)
    }
    fn read_bulk(&self, endpoint: u8, buf: &mut [u8], timeout: Duration) -> Result<usize, rusb::Error>{
        self.read_bulk(endpoint, buf, timeout)
    }
}

pub fn write_bytes_to_device(device: &dyn USBDevice, cmd: &[u8]) -> Result<usize, Error> {
    let result = device.write_bulk(0x02, cmd, Duration::from_millis(500))?;
    if result <= 0 {
        eprintln!("WARN: write to device was successful but no bytes were written");
    }
    Ok(result)
}

pub fn read_bytes_from_device(device: &dyn USBDevice, response_len: usize) -> Result<Vec<u8>, Error> {
    // The response buffer must be initialized with zeros. Initializing with the vec! macro is
    // more efficient than Vec::with_capacity + Vec::resize: https://doc.rust-lang.org/std/vec/struct.Vec.html
    let mut response_buffer = vec![0; response_len];
    let response = device.read_bulk(0x81, &mut response_buffer, Duration::new(5, 0))?;
    if response <= 0 {
        return Err(Error::new("Read from device was successful but not bytes were read".into()));
    }
    Ok(response_buffer)
}

pub fn get_card_type(device: &dyn USBDevice) -> Result<CardType, Error> {
    // Short command for getting the type of the memory card. 1 indicates PS1 and 2 indicates
    // PS2.
    // https://github.com/vpelletier/ps3-memorycard-adapter/blob/a925dd392f4af6c4273c04f8743e8a46f12c2260/nbd/memory_card_reader.py#L96
    // This command should not be sent as a long command so it doesn't need 0x42 or the length
    // bytes.
    let buf = [0xaa, 0x40];
    let _write_result = write_bytes_to_device(device, &buf)?;
    match read_bytes_from_device(device, 2) {
        Ok(response) => {
            let card_type = match response[1] {
                0x00 => CardType::NotPresent,
                0x01 => CardType::PS1,
                0x02 => CardType::PS2,
                _ => {
                    eprintln!("Unknown response for card type: {:#04x}", response[1]);
                    CardType::Unknown
                }
            };
            Ok(card_type)
        },
        Err(error) => Err(Error::new(format!("Invalid response from device when querying for type: {}", error)))
    }
}

fn read_u16_byte(buf: &[u8], pos: usize) -> Result<u16, Error> {
    // Converts two 8bit little endian bytes into one 16bit byte
    let a: [u8; 2] = buf[pos..pos+2].try_into()?;
    Ok(u16::from_le_bytes(a))
}

fn read_u32_byte(buf: &[u8], pos: usize) -> Result<u32, Error> {
    // Converts four 8bit little endian bytes into one 32bit byte
    let a: [u8; 4] = buf[pos..pos+4].try_into()?;
    Ok(u32::from_le_bytes(a))
}

fn length_in_bytes(len: u16) -> [u8; 2] {
    // Converts a length representation given as a 16bit byte into two 8bit little endian bytes.
    // That way a length of 4 is represented as [0x04, 0x00]
    u16::to_le_bytes(len)
}

// This function is only used for debugging
#[allow(dead_code)]
fn print_bytes(bytes: &[u8]) {
    for b in bytes.iter() {
        print!("{:#04x} ", b);
    }
    println!();
}

pub fn get_memory_card(vendor: u16, product: u16) -> Result<Option<CardResult>, Error> {
    for device in rusb::devices()?.iter() {
        let device_desc = device.device_descriptor()?;
        if device_desc.vendor_id() == vendor && device_desc.product_id() == product {
            let mut handle = device.open()?;
            let _ = &mut handle.claim_interface(0)?;
            match get_card_type(&handle)? {
                CardType::PS2 => {
                    let mc = PS2MemoryCard::new(handle)?;
                    return Ok(Some(CardResult::PS2(mc)));
                },
                _ => {}
            }
        }
    }
    Ok(None)
}

pub fn print_specs(card: &dyn MemoryCard) -> Result<(), Error> {
    let card_info = card.get_card_specs()?;
    println!("page size: {} bytes", card_info.page_size);
    println!("block size: {} pages", card_info.block_size);
    println!("card size: {} MB", f64::from(card_info.card_size) / 1024.0 / 1024.0);
    Ok(())
}

pub fn validate_response_success(response: &[u8]) -> bool {
    response[0] == 0x55 && response[1] == 0x5a
}

// https://csrc.nist.gov/glossary/term/error_detection_code
// This function is a port of the `calcEDC` function in ps3mca-tool
fn calculate_edc(buf: &[u8]) -> u8 {
    let mut checksum = 0;
    for b in buf {
        checksum ^= b;
    }
    checksum
}


#[cfg(test)]
mod test {
    use mockall::predicate::{eq, function, always};
    use crate::MockUSBDevice;
    use super::*;

    #[test]
    fn test_write_to_device() {
        let mut device = MockUSBDevice::new();
        device.expect_write_bulk().times(1).return_const(Ok(2));
        let result = write_bytes_to_device(&device, &[0, 0]).expect("Unable to write to device");
        assert_eq!(2, result);
    }

    #[test]
    fn test_read_from_device() {
        let mut device = MockUSBDevice::new();
        device.expect_read_bulk().times(1).return_once(move |_endpoint, response_buffer, _timeout| {
            response_buffer.iter_mut().for_each(|item| *item = 1);
            Ok(3)
        });
        let result = read_bytes_from_device(&device, 3).expect("Unable to read from device");
        assert_eq!(vec![1, 1, 1], result);
    }

    #[test]
    fn test_get_card_type() {
        let mut device = MockUSBDevice::new();
        device.expect_write_bulk()
            .times(1)
            .with(eq(0x02), function(|v| v == &[0xaa, 0x40]), always())
            .return_const(Ok(2));
        device.expect_read_bulk().times(1).return_once(move |_endpoint, response_buffer, _timeout| {
            reassign_mut_array(&[0x55, 0x02], response_buffer);
            Ok(2)
        });
        let result = get_card_type(&device).expect("Unable to get card type");
        assert_eq!(CardType::PS2, result);
    }

    #[test]
    fn test_calculate_edc() {
        let result = calculate_edc(&[0x00, 0x01, 0xff, 0xc0]);
        assert_eq!(0x3e, result);
    }

    fn reassign_mut_array(source: &[u8], destination: &mut [u8]) {
        destination.iter_mut().for_each(|item| *item = 0xff);
        source.iter().enumerate().for_each(|(i, item)| {
            destination[i] = *item;
        });
    }
}
