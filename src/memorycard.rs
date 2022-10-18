use crate::{errors::Error, CardInfo, length_in_bytes, read_u16_byte,
    read_u32_byte, write_bytes_to_device, read_bytes_from_device, CardType};

pub trait MemoryCard {
    fn new(device: rusb::DeviceHandle<rusb::GlobalContext>) -> Result<Self, Error> where Self: Sized;
    fn write_to_device(&self, cmd: &[u8]) -> Result<usize, Error>;
    fn read_from_device(&self, response_len: usize) -> Result<Vec<u8>, Error>;
    fn get_card_specs(&self) -> Result<CardInfo, Error>;
    fn get_card_type(&self) -> CardType;
}

pub struct PS2MemoryCard {
    pub device: rusb::DeviceHandle<rusb::GlobalContext>
}

impl MemoryCard for PS2MemoryCard {
    fn new(device: rusb::DeviceHandle<rusb::GlobalContext>) -> Result<Self, Error> {
        Ok(Self {device})
    }

    fn write_to_device(&self, cmd: &[u8]) -> Result<usize, Error> {
        let cmd_len = match cmd.len().try_into() {
            Ok(len) => len,
            Err(error) => return Err(Error::new(format!("Invalid length of command {:?}: {}", cmd, error)))
        };
        let cmd_start = assemble_long_command_buffer_start(cmd_len);
        // https://stackoverflow.com/a/66607637
        let buf = [cmd_start.as_ref(), cmd.as_ref()].concat();
        write_bytes_to_device(&self.device, &buf)
    }

    fn read_from_device(&self, response_len: usize) -> Result<Vec<u8>, Error> {
        let response = read_bytes_from_device(&self.device, response_len)?;
        if response[0] != 0x55 {
            return Err(Error::new(format!("Received invalid response: {:?}", response)));
        }
        Ok(response.into())
    }

    fn get_card_specs(&self) -> Result<CardInfo, Error> {
        let cmd = [0x81, 0x26, 0x5a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let _write_result = self.write_to_device(&cmd)?;
        // 17 = 13 (length of command) + 4 (2 ACK bytes + 2 length bytes)
        let response = self.read_from_device(17)?;
        Ok(CardInfo::new(
            read_u16_byte(&response, 7)?,
            read_u16_byte(&response, 9)?,
            read_u32_byte(&response, 11)?))
    }

    fn get_card_type(&self) -> CardType {
        CardType::PS2
    }
}

impl PS2MemoryCard {
    // This check is called `Card_Changed` in ps3mca-tool
    pub fn is_authenticated(&self) -> Result<bool, Error> {
        // https://github.com/vpelletier/ps3-memorycard-adapter/blob/a925dd392f4af6c4273c04f8743e8a46f12c2260/nbd/memory_card_reader.py#L101
        let cmd = [0x81, 0x11, 0, 0];
        let _write_result = self.write_to_device(&cmd)?;
        match self.read_from_device(8) {
            Ok(response) => {
                if response[1] == 0xaf {
                    Ok(false)
                } else if response[1] == 0x5a && response[6..8] == [0x2b, 0x5a] {
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            Err(error) => Err(Error::new(format!("Invalid response from device when getting authentication status: {}", error)))
        }
    }
}

fn assemble_long_command_buffer_start(cmd_len: u16) -> [u8; 4] {
    let len = length_in_bytes(cmd_len);
    // 0xaa seems to be the first byte of the ps3mca protocol, 0x42 indicates that this is a
    // long command. The 3rd and 4th bytes are a 16bit representation of the length of the
    // command.
    [0xaa, 0x42, len[0], len[1]]
}
