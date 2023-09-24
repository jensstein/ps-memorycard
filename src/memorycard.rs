//! Memory card specific operations
//!
//! Documentation for the file system of ps2 memory cards come from Ross Ridge, creator of `mymc`:
//! http://www.csclub.uwaterloo.ca:11068/mymc/ps2mcfs.html
//! https://web.archive.org/web/20221014060234/www.csclub.uwaterloo.ca:11068/mymc/ps2mcfs.html
//! I'll refer to it as "RR ps2mc-fs" in the documentation here.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::path::{Component, Path};

use chrono::TimeZone;

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

/*
 * This struct is used to authenticate the ps2 memory card so that the PS2MemoryCard struct can
 * read its superblock when it is instantiated.
 * It is private to the current crate so that only the struct representing the complete memory card
 * is accesible to outside crates.
 */
pub(crate) struct PS2MemoryCardPartial {
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
        // If you read too few bytes you will get seemingly unintelligible errors. ps3mca-tool takes
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

        let magic = match String::from_utf8(superblock_bytes[0..28].to_vec()) {
            Ok(magic) => magic,
            Err(error) => return Err(Error::new(format!("Unable to parse the superblock header: {error}"))),
        };
        let version = match String::from_utf8(superblock_bytes[28..40].to_vec()) {
            Ok(version) => version,
            Err(error) => return Err(Error::new(format!("Unable to parse version information from the superblock: {error}"))),
        };
        // Refer to RR ps2mc-fs under "The Superblock" for an overview of the superblock layout.
        Ok(SuperBlock {
            magic,
            version,
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

#[derive(Debug, PartialEq)]
pub enum DirectoryEntryType {
    File,
    Directory,
    Unknown,
}

impl fmt::Display for DirectoryEntryType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Self::File => "<file>",
            Self::Directory => "<dir>",
            Self::Unknown => "<???>",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug)]
pub struct DirectoryEntry {
    mode: u16,
    pub length: u32,
    created: Time,
    cluster: u32,
    dir_entry: u32,
    pub modified: Time,
    attr: u32,
    pub name: String,
    pub entry_type: DirectoryEntryType,
}

impl TryFrom<Vec<u8>> for DirectoryEntry {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Error> {
        let mode = u16::from_le_bytes([bytes[0], bytes[1]]);
        let length = u32::from_le_bytes(bytes[4..8].try_into()?);
        let created = time_from_bytes(bytes[8..16].try_into()?);
        let cluster = u32::from_le_bytes(bytes[16..20].try_into()?);
        let dir_entry = u32::from_le_bytes(bytes[20..24].try_into()?);
        let modified = time_from_bytes(bytes[24..32].try_into()?);
        let attr = u32::from_le_bytes(bytes[32..36].try_into()?);
        // The filenames are zero-terminated so this line finds first zero or sets `string_end` to
        // 32 which is the max if there are no zeros.
        let string_end = &bytes[64..96].iter().position(|i| *i == 0u8).unwrap_or(32);
        let name = if *string_end > 0 {
            match String::from_utf8(bytes[64..(64+string_end)].to_vec()) {
                Ok(name) => name,
                Err(_err) => {
                    "<no-name>".into()
                },
            }
        } else {
            "<no-name>".into()
        };
        let entry_type = if mode & 0x0010 == 0x0010 {
            DirectoryEntryType::File
        } else if mode & 0x0020 == 0x0020 {
            DirectoryEntryType::Directory
        } else {
            DirectoryEntryType::Unknown
        };
        Ok(Self {
            mode,
            length,
            created,
            cluster,
            dir_entry,
            modified,
            attr,
            name,
            entry_type,
        })
    }
}

impl fmt::Display for DirectoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let time = match self.modified {
            Some(time) => time.to_string(),
            None => "<missing date>".into()
        };
        write!(f, "{}\t{}\t{}", self.entry_type, time, self.name)
    }
}

type Time = Option<chrono::DateTime<chrono::offset::FixedOffset>>;

/// Parse 8 bytes as a Japanese date given the format found in RR ps2mc-fs
fn time_from_bytes(bytes: &[u8; 8]) -> Time {
    // The times are always in the Japanese timezone: UTC+9
    let timezone = chrono::offset::FixedOffset::east_opt(9 * 3600)?;
    let year = u16::from_le_bytes([bytes[6], bytes[7]]) as i32;
    let month = bytes[5] as u32;
    let day = bytes[4] as u32;
    let hour = bytes[3] as u32;
    let minutes = bytes[2] as u32;
    let seconds = bytes[1] as u32;
    let t = timezone.with_ymd_and_hms(
        year, month, day, hour, minutes, seconds
    );
    t.single()
}

#[derive(Copy, Clone)]
struct FatCluster {
    has_next_cluster: bool,
    cluster: u32,
}

/// Parse an array of u8 as cluster entries (u32 with a special most
/// significant bit, refer to RR ps2mc-fs under "File Allocation Table".)
fn read_cluster_list(cluster_list: &[u8]) -> Result<Vec<FatCluster>, Error> {
    if cluster_list.len() % 4 != 0 {
        return Err(Error::new("Cluster list must be parsable as 32bit integers".into()));
    }
    let mut fat_clusters = Vec::with_capacity(cluster_list.len() / 4);
    for i in (0..cluster_list.len()).step_by(4) {
        let entry = u32::from_le_bytes(cluster_list[i..i+4].try_into()?);
        // Get the most significant bit. If it is set, then the lower 31 bits
        // point to the next cluster in the list. Otherwise it will be clear and the corresponding
        // entry will be free.
        // Refer to RR ps2mc-fs under "File Allocation Table".
        let has_next_cluster = (entry >> 31) & 1;
        // Bitwise and to get the lower 31 bits of the u32. These contain the value of the next
        // cluster in the list.
        let fc = FatCluster{has_next_cluster: has_next_cluster == 1, cluster: entry & 0xffff};
        fat_clusters.push(fc);
    }
    Ok(fat_clusters)
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
            partial_device,
        })
    }

    /// This function corresponds to `ps2mc.read_fat_cluster` in ps2mc.py from mymc.
    /// The implementation follows how RR ps2mc-fs gives the algorithm which is slightly different
    /// from how it's implemented in mymc.
    fn get_fat_entry(&mut self, fat_index: usize) -> Result<FatCluster, Error> {
        // The part where we divide by 4 is taken from mymc. RR ps2mc-fs
        // documents each entry being 32 bits thereby corresponding to four 8-bit bytes.
        let entries_per_cluster: usize = (self.superblock.page_len * self.superblock.pages_per_cluster / 4).into();
        let fat_offset = fat_index % entries_per_cluster;
        let indirect_index = fat_index / entries_per_cluster;
        let indirect_offset = indirect_index % entries_per_cluster;
        let double_indirect_index = indirect_index / entries_per_cluster;
        let indirect_cluster_n = self.superblock.ifc_list[double_indirect_index];
        let indirect_cluster = self.read_cluster(indirect_cluster_n)?;
        let indirect_cluster = read_cluster_list(&indirect_cluster)?;
        let fat_cluster_n = &indirect_cluster[indirect_offset];
        let fat_cluster = self.read_cluster(fat_cluster_n.cluster)?;
        let fat_cluster = read_cluster_list(&fat_cluster)?;
        let entry = fat_cluster[fat_offset];
        Ok(entry)
    }

    /// Get a [`DirectoryEntry`](crate::memorycard::DirectoryEntry) from a file system path.
    pub fn get_directory_entry_by_path(&mut self, path: &Path) -> Result<Option<DirectoryEntry>, Error> {
        let mut components = Vec::with_capacity(16);
        for c in path.components() {
            match c {
                Component::Normal(component) => {
                    let component_str = match component.to_str() {
                        Some(s) => s,
                        None => return Err(Error::new(format!(
                            "Unable to parse path component {component:?} as unicode."))),
                    };
                    components.push(component_str);
                },
                Component::RootDir => components.push("/"),
                Component::CurDir | Component::ParentDir => return Err(
                    Error::new(". and .. is not allowed in paths for memory card files".into())),
                Component::Prefix(_) => return Err(Error::new(
                    "Windows path prefix doesn't make sense for PS2 memory cards. Start the path with '/'.".into())),
            }
        }
        if components[0] != "/" {
            return Err(Error::new("Only absolute paths are supported. Start the path with '/'.".into()));
        }

        // Start iterating from the root directory
        let root = self.read_cluster(self.superblock.alloc_offset + self.superblock.rootdir_cluster)?;
        // Only read the first directory entry here because the second one is just the .. entry.
        let d = DirectoryEntry::try_from(root[0..512].to_vec())?;
        // If there is only one path component and the path must start with / then we know that the
        // root is the relevant directory entry.
        if components.len() == 1 {
            return Ok(Some(d));
        }
        // Iterate though the directory entries with a lifo queue (stack). Any time a matching filename is
        // found the stack is cleared.
        let mut queue = VecDeque::from(self.directory_entries(&d)?);
        let last_component_index = components.len() - 1;
        for (i, p) in components[1..].iter().enumerate() {
            while let Some(entry) = queue.pop_back() {
                if *p == entry.name {
                    // Clear the queue to avoid iterating through the irrelevant directories
                    queue.clear();
                    if entry.entry_type == DirectoryEntryType::Directory {
                        // If this is the last component of the path, end the iteration here
                        if i + 1 == last_component_index {
                            return Ok(Some(entry));
                        } else {
                            // If this is not the last component of the path, iterate through the
                            // directory.
                            for e in self.directory_entries(&entry)? {
                                queue.push_back(e);
                            }
                        }
                    } else {
                        return Ok(Some(entry));
                    }
                    // Jump to the next path component when a matching filename is found
                    break;
                }
            }
        }
        Ok(None)
    }

    /// Get a list of [`DirectoryEntry`](crate::memorycard::DirectoryEntry) from the current
    /// DirectoryEntry. This raises an error if the current DirectoryEntry is not a directory.
    pub fn directory_entries(&mut self, directory: &DirectoryEntry) -> Result<Vec<DirectoryEntry>, Error> {
        if directory.entry_type != DirectoryEntryType::Directory {
            return Err(Error::new(format!("{} is not a directory so it has no contents to list", directory.name)));
        }
        let mut entries = Vec::with_capacity(directory.length as usize);
        // Use `fat_entry` to follow the linked list of clusters
        let mut fat_entry = directory.cluster;
        // A directory entry is 512 bytes, so depending on the size of the cluster there are either
        // one or two. If there are two per cluster the iteration should be half as long as if
        // there is only one.
        for _ in 0..(directory.length / (self.superblock.page_len * self.superblock.pages_per_cluster / 512) as u32) {
            let fat_cluster = self.get_fat_entry(fat_entry as usize)?;
            if !fat_cluster.has_next_cluster {
                break;
            }
            fat_entry = fat_cluster.cluster;

            let cluster = self.read_cluster(self.superblock.alloc_offset + fat_entry)?;
            entries.push(DirectoryEntry::try_from(cluster[0..512].to_vec())?);
            if cluster.len() == 1024 {
                entries.push(DirectoryEntry::try_from(cluster[512..1024].to_vec())?);
            }
        }
        Ok(entries)
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

    fn read_bytes_for_entry<F>(&mut self, fat_entry: u32, total_read: usize,
            directory_entry_length: usize, callback: &mut F) -> Result<usize, Error>
            where F: FnMut(Vec<u8>) {
        let data = self.read_cluster(self.superblock.alloc_offset + fat_entry)?;
        let read = total_read + data.len();
        if read > directory_entry_length {
            let surplus = read - directory_entry_length;
            let left_to_read = data.len() - surplus;
            callback(data[0..left_to_read].to_vec());
            Ok(left_to_read)
        } else {
            let data_len = data.len();
            callback(data);
            Ok(data_len)
        }
    }

    pub fn read_file<F>(&mut self, path: &Path, mut callback: F) -> Result<(), Error>
            where F: FnMut(Vec<u8>) {
        if let Some(directory_entry) = self.get_directory_entry_by_path(path)? {
            if directory_entry.entry_type != DirectoryEntryType::File {
                return Err(Error::new(format!("{} is not a regular file.", path.display())));
            }

            let directory_entry_length = directory_entry.length as usize;
            let mut fat_entry = directory_entry.cluster;
            let mut read = self.read_bytes_for_entry(fat_entry, 0, directory_entry_length, &mut callback)?;
            while read < directory_entry_length  {
                let fat_cluster = self.get_fat_entry(fat_entry as usize)?;
                if !fat_cluster.has_next_cluster {
                    break;
                }
                fat_entry = fat_cluster.cluster;
                read += self.read_bytes_for_entry(fat_entry, read, directory_entry_length, &mut callback)?;
            }
            Ok(())
        } else {
            return Err(Error::new(format!("Cannot access {}: No such file or directory", path.display())));
        }
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
