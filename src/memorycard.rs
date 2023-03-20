use std::collections::{HashMap, VecDeque};
use std::path::Path;

use crate::{auth::{CardKeys,read_card_keys}, errors::Error, CardInfo, calculate_edc, length_in_bytes, read_u16_byte,
    read_u32_byte, write_bytes_to_device, read_bytes_from_device, CardType};

// The commands here are mostly ported from ps3mca-tool and some are documented on
// https://psi-rockin.github.io/ps2tek/#sio2ps2memcards

pub trait MemoryCard {
    fn write_to_device(&self, cmd: &[u8]) -> Result<usize, Error>;
    fn read_from_device(&self, response_len: usize) -> Result<Vec<u8>, Error>;
    fn get_card_specs(&self) -> Result<CardInfo, Error>;
    fn get_card_type(&self) -> CardType;
    fn read_page(&self, page_number: u32, page_size: u16) -> Result<Vec<u8>, Error>; // This function reads frames from a PS1 card and pages from a PS2 card
}

struct ClusterCache {
    cache: HashMap<u32, Vec<u8>>,
    clusters_in_cache: VecDeque<u32>,
}

impl ClusterCache {
    fn new() -> Self {
        let cache_size = 64;
        Self {
            cache: HashMap::with_capacity(cache_size),
            clusters_in_cache: VecDeque::with_capacity(cache_size),
        }
    }

    fn contains_key(&self, key: &u32) -> bool {
        self.cache.contains_key(key)
    }

    fn get(&self, key: &u32) -> Option<&Vec<u8>> {
        self.cache.get(key)
    }

    fn insert(&mut self, key: u32, value: Vec<u8>) {
        if self.clusters_in_cache.len() >= self.clusters_in_cache.capacity() {
            if let Some(removed_key) = self.clusters_in_cache.pop_front() {
                self.cache.remove(&removed_key);
            }
        }
        self.clusters_in_cache.push_back(key);
        self.cache.insert(key, value);
    }
}

// The names for the fields in this struct are taken from the documentation here:
// https://web.archive.org/web/20221014060234/www.csclub.uwaterloo.ca:11068/mymc/ps2mcfs.html
#[derive(Debug)]
pub struct SuperBlock {
    magic: String,
    version: String,
    page_len: u16,
    pages_per_cluster: u16,
    pages_per_block: u16,
    clusters_per_card: u32,
    alloc_offset: u32,
    alloc_end: u32,
    rootdir_cluster: u32,
    backup_block1: u32,
    backup_block2: u32,
    ifc_list: Vec<u32>,
    bad_block_list: Vec<u32>,
    card_type: u8,
    card_flags: u8,
}

pub struct PS2MemoryCard {
    cluster_cache: ClusterCache,
    superblock: SuperBlock,
    partial_device: PS2MemoryCardPartial,
}

// This struct is used to authenticate the ps2 memory card so that the PS2MemoryCard struct can
// read its superblock when it is instantiated.
pub struct PS2MemoryCardPartial {
    device: rusb::DeviceHandle<rusb::GlobalContext>,
}
impl PS2MemoryCardPartial {
    fn new(device: rusb::DeviceHandle<rusb::GlobalContext>) -> Result<Self, Error> {
        Ok(Self {
            device,
        })
    }

    pub fn write_to_device(&self, cmd: &[u8]) -> Result<usize, Error> {
        let cmd_len = match cmd.len().try_into() {
            Ok(len) => len,
            Err(error) => return Err(Error::new(format!("Invalid length of command {:?}: {}", cmd, error)))
        };
        let cmd_start = assemble_long_command_buffer_start(cmd_len);
        // https://stackoverflow.com/a/66607637
        let buf = [cmd_start.as_ref(), cmd.as_ref()].concat();
        write_bytes_to_device(&self.device, &buf)
    }

    pub fn read_from_device(&self, response_len: usize) -> Result<Vec<u8>, Error> {
        // If you read too few bytes you will get seemingly unintelligent errors. ps3mca-tool takes
        // the approach of always reading 1024 bytes.
        let response = read_bytes_from_device(&self.device, response_len)?;
        if response[0] != 0x55 {
            return Err(Error::new(format!("Received invalid response: {:?}", response)));
        }
        Ok(response.into())
    }


    pub fn get_card_type(&self) -> CardType {
        CardType::PS2
    }

    pub fn read_page(&self, page_number: u32, page_size: u16) -> Result<Vec<u8>, Error> {
        let page_number_in_bytes = u32::to_le_bytes(page_number);
        let page_number_edc = calculate_edc(&page_number_in_bytes);
        // 23h is the command to start reading
        let cmd = [&[0x81, 0x23], page_number_in_bytes.as_ref(), &[page_number_edc], &[0, 0]].concat();
        self.write_to_device(&cmd)?;
        // Only read to verify response
        self.read_from_device(1024)?;
        let count = page_size >> 7;
        let mut page_contents = vec![];
        for i in 0..count {
            // 43h reads data from the address which is set by the 23h command.
            // That means that we don't specify the address to read from here.
            let subcmd = [[0x81, 0x43, 128].as_ref(), [0; 131].as_ref()].concat();
            self.write_to_device(&subcmd)?;
            let subresult = self.read_from_device(138)?;
            if subresult.len() == 138 {
                let data = &subresult[8..136];
                let edc = calculate_edc(&data);
                if subresult[136] != edc {
                    return Err(Error::new(format!(
                        "Checksum for page {}/{} did not match received data",
                        page_number, i)))
                }
                page_contents.extend(data);
            } else {
                return Err(Error::new(
                    format!("Page data read from device returned invalid response length: {}",
                    subresult.len())));
            }
        };
        // 81h means read end
        self.write_to_device(&[0x81, 0x81, 0, 0])?;
        // We don't need the response other than for validation
        self.read_from_device(1024)?;
        Ok(page_contents)
    }

    pub fn read_superblock(&self) -> Result<SuperBlock, Error> {
        let cmd = [0x81, 0x26, 0x5a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let _write_result = self.write_to_device(&cmd)?;
        // 17 = 13 (length of command) + 4 (2 ACK bytes + 2 length bytes)
        let response = self.read_from_device(17)?;
        let page_size = read_u16_byte(&response, 7)?;
        // This value you can read from the 26h command doesn't seem reliable.
        // I have a 64MB card which reports itself as 8MB. But you can read the
        // total number of clusters in the card from the superblock and multiple
        // that with the number of pages per cluster times the page size. For my
        // 64MB card this procedure gives the correct size.
        // https://psi-rockin.github.io/ps2tek/#sio2ps2memcardfilesystem
        let superblock_bytes = self.read_page(0, page_size)?;
        let u8_slice_to_u32_vec = |slice: &[u8]| -> Result<Vec<u32>, Error> {
            let mut b = Vec::<u32>::with_capacity(slice.len() / 4);
            for i in (0..slice.len()).step_by(4) {
                b.push(read_u32_byte(slice, i)?);
            }
            Ok(b)
        };

        // https://web.archive.org/web/20221014060234/www.csclub.uwaterloo.ca:11068/mymc/ps2mcfs.html
        Ok(SuperBlock {
            magic: String::from_utf8(superblock_bytes[0..28].to_vec()).expect("UPUP"),
            version: String::from_utf8(superblock_bytes[28..40].to_vec()).expect("YREW"),
            page_len: read_u16_byte(&superblock_bytes, 40)?,
            pages_per_cluster: read_u16_byte(&superblock_bytes, 42)?,
            pages_per_block: read_u16_byte(&superblock_bytes, 44)?,
            clusters_per_card: read_u32_byte(&superblock_bytes, 48)?,
            alloc_offset: read_u32_byte(&superblock_bytes, 52)?,
            alloc_end: read_u32_byte(&superblock_bytes, 56)?,
            rootdir_cluster: read_u32_byte(&superblock_bytes, 60)?,
            backup_block1: read_u32_byte(&superblock_bytes, 64)?,
            backup_block2: read_u32_byte(&superblock_bytes, 68)?,
            ifc_list: u8_slice_to_u32_vec(&superblock_bytes[80..208])?,
            bad_block_list: u8_slice_to_u32_vec(&superblock_bytes[200..336])?,
            card_type: superblock_bytes[336],
            card_flags: superblock_bytes[337],
        })
    }
}

impl MemoryCard for PS2MemoryCard {
    fn read_from_device(&self, response_len: usize) -> Result<Vec<u8>, Error> {
        self.partial_device.read_from_device(response_len)
    }

    fn write_to_device(&self, cmd: &[u8]) -> Result<usize, Error> {
        self.partial_device.write_to_device(cmd)
    }

    fn get_card_type(&self) -> CardType {
        self.partial_device.get_card_type()
    }

    fn read_page(&self, page_number: u32, page_size: u16) -> Result<Vec<u8>, Error> {
        self.partial_device.read_page(page_number, page_size)
    }

    fn get_card_specs(&self) -> Result<CardInfo, Error> {
        let card_size = self.superblock.clusters_per_card *
            self.superblock.pages_per_cluster as u32 *
            self.superblock.page_len as u32;
        Ok(CardInfo::new(
            self.superblock.page_len,
            self.superblock.pages_per_block,
            self.superblock.pages_per_cluster,
            card_size))
    }
}

impl PS2MemoryCard {
    pub fn new(device: rusb::DeviceHandle<rusb::GlobalContext>, keys_directory: &str) -> Result<Self, Error> {
        let partial_device = PS2MemoryCardPartial::new(device)?;
        let card_keys = read_card_keys(Path::new(keys_directory))?;
        partial_device.authenticate(&card_keys)?;
        partial_device.validate()?;
        partial_device.set_termination_code()?;
        let superblock = partial_device.read_superblock()?;
        Ok(Self {
            cluster_cache: ClusterCache::new(),
            superblock,
            partial_device: partial_device,
        })
    }

    // This check is called `Card_Changed` in ps3mca-tool
    pub fn is_authenticated(&self) -> Result<bool, Error> {
        // https://github.com/vpelletier/ps3-memorycard-adapter/blob/a925dd392f4af6c4273c04f8743e8a46f12c2260/nbd/memory_card_reader.py#L101
        let cmd = [0x81, 0x11, 0, 0];
        let _write_result = self.partial_device.write_to_device(&cmd)?;
        match self.partial_device.read_from_device(8) {
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

    pub fn read_cluster(&mut self, cluster: u32) -> Result<Vec<u8>, Error> {
        // TODO: handling of backup_block1 and backup_block2
        // https://web.archive.org/web/20221014060234/www.csclub.uwaterloo.ca:11068/mymc/ps2mcfs.html

        if self.cluster_cache.contains_key(&cluster) {
            if let Some(contents) = self.cluster_cache.get(&cluster) {
                return Ok(contents.to_owned());
            }
        }
        let mut contents = Vec::with_capacity((self.superblock.pages_per_cluster *
            self.superblock.page_len) as usize);
        for i in 0..self.superblock.pages_per_cluster {
            let page = self.partial_device.read_page(cluster *
                self.superblock.pages_per_cluster as u32 + i as u32, self.superblock.page_len)?;
            contents.extend_from_slice(&page);
        }
        self.cluster_cache.insert(cluster, contents.clone());
        Ok(contents)
    }

    pub fn auth_reset(&self) -> Result<(), Error> {
        self.partial_device.auth_reset()
    }

    pub fn authenticate(&self, card_keys: &CardKeys) -> Result<Vec<u8>, Error> {
        self.partial_device.authenticate(card_keys)
    }

    pub fn set_termination_code(&self) -> Result<Vec<u8>, Error> {
        self.partial_device.set_termination_code()
    }
}

fn assemble_long_command_buffer_start(cmd_len: u16) -> [u8; 4] {
    let len = length_in_bytes(cmd_len);
    // 0xaa seems to be the first byte of the ps3mca protocol, 0x42 indicates that this is a
    // long command. The 3rd and 4th bytes are a 16bit representation of the length of the
    // command.
    [0xaa, 0x42, len[0], len[1]]
}
