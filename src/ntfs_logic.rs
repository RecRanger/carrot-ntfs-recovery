use serde::Serialize;
use chrono::{DateTime, TimeZone, Utc};

const MFT_MAGIC: &[u8; 4] = b"FILE";

const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_OBJECT_ID: u32 = 0x40;
const ATTR_DATA: u32 = 0x80;
const ATTR_REPARSE_POINT: u32 = 0xC0;
const ATTR_EA_INFORMATION: u32 = 0xD0;
const ATTR_END: u32 = 0xFFFFFFFF;

// File attribute flags
const FILE_ATTR_READONLY: u32 = 0x01;
const FILE_ATTR_HIDDEN: u32 = 0x02;
const FILE_ATTR_SYSTEM: u32 = 0x04;
const FILE_ATTR_DIRECTORY: u32 = 0x10;
const FILE_ATTR_ARCHIVE: u32 = 0x20;
const FILE_ATTR_DEVICE: u32 = 0x40;
const FILE_ATTR_NORMAL: u32 = 0x80;
const FILE_ATTR_TEMPORARY: u32 = 0x100;
const FILE_ATTR_SPARSE_FILE: u32 = 0x200;
const FILE_ATTR_REPARSE_POINT: u32 = 0x400;
const FILE_ATTR_COMPRESSED: u32 = 0x800;
const FILE_ATTR_OFFLINE: u32 = 0x1000;
const FILE_ATTR_NOT_CONTENT_INDEXED: u32 = 0x2000;
const FILE_ATTR_ENCRYPTED: u32 = 0x4000;

#[derive(Debug, Serialize, Clone)]
pub struct FileAttributes {
    pub readonly: bool,
    pub hidden: bool,
    pub system: bool,
    pub directory: bool,
    pub archive: bool,
    pub device: bool,
    pub normal: bool,
    pub temporary: bool,
    pub sparse_file: bool,
    pub reparse_point: bool,
    pub compressed: bool,
    pub offline: bool,
    pub not_content_indexed: bool,
    pub encrypted: bool,
}

impl FileAttributes {
    fn from_flags(flags: u32) -> Self {
        Self {
            readonly: flags & FILE_ATTR_READONLY != 0,
            hidden: flags & FILE_ATTR_HIDDEN != 0,
            system: flags & FILE_ATTR_SYSTEM != 0,
            directory: flags & FILE_ATTR_DIRECTORY != 0,
            archive: flags & FILE_ATTR_ARCHIVE != 0,
            device: flags & FILE_ATTR_DEVICE != 0,
            normal: flags & FILE_ATTR_NORMAL != 0,
            temporary: flags & FILE_ATTR_TEMPORARY != 0,
            sparse_file: flags & FILE_ATTR_SPARSE_FILE != 0,
            reparse_point: flags & FILE_ATTR_REPARSE_POINT != 0,
            compressed: flags & FILE_ATTR_COMPRESSED != 0,
            offline: flags & FILE_ATTR_OFFLINE != 0,
            not_content_indexed: flags & FILE_ATTR_NOT_CONTENT_INDEXED != 0,
            encrypted: flags & FILE_ATTR_ENCRYPTED != 0,
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct AlternateFilename {
    pub name: String,
    pub namespace: u8,
}

#[derive(Debug, Serialize, Clone)]
pub struct DataRun {
    pub cluster_offset: i64,
    pub cluster_count: u64,
}

#[derive(Debug, Serialize, Clone)]
pub struct DataStream {
    pub name: Option<String>,
    pub resident: bool,
    pub size: u64,
    pub allocated_size: u64,
    pub resident_data: Option<String>,
    pub data_runs: Option<Vec<DataRun>>, // For non-resident data
}

#[derive(Debug, Serialize)]
pub struct NtfsEntry {
    pub mft_offset: u64,
    pub mft_record_number: u64,
    pub sequence_number: u16,
    pub hardlink_count: u16,
    pub is_in_use: bool,
    pub is_directory: bool,
    
    // Main filename (Win32/POSIX)
    pub filename: String,
    pub parent_mft_record: u64,  // MFT record number of parent directory
    pub parent_sequence: u16,     // Sequence number of parent
    pub allocated_size: u64,
    pub real_size: u64,

    // Standard Information timestamps
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub mft_modified: Option<DateTime<Utc>>,
    pub accessed: Option<DateTime<Utc>>,
    
    // File attributes
    pub file_attributes: Option<FileAttributes>,
    
    // Security and ownership
    pub owner_id: Option<u32>,
    pub security_id: Option<u32>,
    pub usn: Option<u64>,

    // Object ID (GUID)
    pub object_id: Option<String>,
    
    // Alternate filenames (DOS names, other namespaces)
    pub alternate_filenames: Vec<AlternateFilename>,
    
    // Data streams (unnamed + named)
    pub data_streams: Vec<DataStream>,
    
    // Reparse point
    pub reparse_tag: Option<u32>,
    pub reparse_target: Option<String>,
    
    // Extended attributes
    pub has_extended_attributes: bool,
}

fn parse_attr_header(buf: &[u8], offset: usize) -> Option<(u32, usize, bool, Option<String>)> {
    if offset + 16 > buf.len() {
        return None;
    }

    let attr_type = u32::from_le_bytes(buf[offset..offset + 4].try_into().ok()?);
    if attr_type == ATTR_END {
        return None;
    }

    let length = u32::from_le_bytes(buf[offset + 4..offset + 8].try_into().ok()?) as usize;
    if length == 0 || offset + length > buf.len() {
        return None;
    }

    let non_resident = buf[offset + 8] != 0;
    let name_length = buf[offset + 9] as usize;
    let name_offset = u16::from_le_bytes(buf[offset + 10..offset + 12].try_into().ok()?) as usize;
    
    let attr_name = if name_length > 0 && offset + name_offset + name_length * 2 <= buf.len() {
        let name_bytes = &buf[offset + name_offset..offset + name_offset + name_length * 2];
        let utf16: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&utf16).ok()
    } else {
        None
    };

    Some((attr_type, length, non_resident, attr_name))
}

#[derive(Debug)]
struct FileNameAttr {
    name: String,
    parent_reference: u64,
    namespace: u8,
    allocated_size: u64,
    real_size: u64,
}

fn parse_filename(attr: &[u8]) -> Option<FileNameAttr> {
    if attr.len() < 66 {
        return None;
    }

    let content_offset = u16::from_le_bytes(attr[20..22].try_into().ok()?) as usize;

    if content_offset + 66 > attr.len() {
        return None;
    }

    let content = &attr[content_offset..];

    let parent_reference = u64::from_le_bytes(content[0..8].try_into().ok()?);
    let allocated_size = u64::from_le_bytes(content[40..48].try_into().ok()?);
    let real_size = u64::from_le_bytes(content[48..56].try_into().ok()?);
    let namespace = content[65];
    let name_len = content[64] as usize;
    let name_off = 66;

    let byte_len = name_len * 2;
    if name_off + byte_len > content.len() {
        return None;
    }

    let raw = &content[name_off..name_off + byte_len];
    let utf16: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    let name = String::from_utf16(&utf16).ok()?;

    Some(FileNameAttr {
        name,
        parent_reference,
        namespace,
        allocated_size,
        real_size,
    })
}

fn parse_resident_data(attr: &[u8]) -> Option<Vec<u8>> {
    if attr.len() < 24 {
        return None;
    }

    let content_len = u32::from_le_bytes(attr[16..20].try_into().ok()?) as usize;
    let content_offset = u16::from_le_bytes(attr[20..22].try_into().ok()?) as usize;

    if content_offset + content_len > attr.len() {
        return None;
    }

    Some(attr[content_offset..content_offset + content_len].to_vec())
}

fn parse_data_runs(attr: &[u8]) -> Option<Vec<DataRun>> {
    if attr.len() < 64 {
        return None;
    }
    
    let data_run_offset = u16::from_le_bytes(attr[32..34].try_into().ok()?) as usize;
    
    if data_run_offset >= attr.len() {
        return None;
    }
    
    let mut runs = Vec::new();
    let mut offset = data_run_offset;
    let mut current_lcn: i64 = 0; // Logical Cluster Number (cumulative)
    
    while offset < attr.len() {
        let header = attr[offset];
        if header == 0 {
            break; // End of data runs
        }
        
        let length_bytes = (header & 0x0F) as usize;
        let offset_bytes = ((header & 0xF0) >> 4) as usize;
        
        if length_bytes == 0 || length_bytes > 8 || offset_bytes > 8 {
            break;
        }
        
        offset += 1;
        
        if offset + length_bytes + offset_bytes > attr.len() {
            break;
        }
        
        // Read cluster count (unsigned)
        let mut cluster_count: u64 = 0;
        for i in 0..length_bytes {
            cluster_count |= (attr[offset + i] as u64) << (i * 8);
        }
        offset += length_bytes;
        
        // Read cluster offset (signed, relative to previous LCN)
        let mut cluster_offset: i64 = 0;
        for i in 0..offset_bytes {
            cluster_offset |= (attr[offset + i] as i64) << (i * 8);
        }
        // Sign extend if necessary
        if offset_bytes > 0 && (attr[offset + offset_bytes - 1] & 0x80) != 0 {
            for i in offset_bytes..8 {
                cluster_offset |= 0xFF << (i * 8);
            }
        }
        offset += offset_bytes;
        
        current_lcn += cluster_offset;
        
        runs.push(DataRun {
            cluster_offset: current_lcn,
            cluster_count,
        });
    }
    
    if runs.is_empty() {
        None
    } else {
        Some(runs)
    }
}

fn parse_data_attribute(attr: &[u8], attr_name: Option<String>, non_resident: bool) -> Option<DataStream> {
    if non_resident {
        if attr.len() < 64 {
            return None;
        }
        let real_size = u64::from_le_bytes(attr[48..56].try_into().ok()?);
        let allocated_size = u64::from_le_bytes(attr[56..64].try_into().ok()?);
        let data_runs = parse_data_runs(attr);
        
        Some(DataStream {
            name: attr_name,
            resident: false,
            size: real_size,
            allocated_size,
            resident_data: None,
            data_runs,
        })
    } else {
        let data = parse_resident_data(attr)?;
        let size = data.len() as u64;
        let resident_str = String::from_utf8(data).ok();
        
        Some(DataStream {
            name: attr_name,
            resident: true,
            size,
            allocated_size: size,
            resident_data: resident_str,
            data_runs: None,
        })
    }
}

fn filetime_to_utc(ft: u64) -> Option<DateTime<Utc>> {
    if ft == 0 {
        return None;
    }

    const WINDOWS_TICK: i64 = 10_000_000;
    const SEC_TO_UNIX_EPOCH: i64 = 11_644_473_600;

    let seconds = (ft as i64 / WINDOWS_TICK) - SEC_TO_UNIX_EPOCH;
    let nanos = ((ft % WINDOWS_TICK as u64) * 100) as u32;

    Utc.timestamp_opt(seconds, nanos).single()
}

fn parse_standard_information(attr: &[u8]) -> Option<(DateTime<Utc>, DateTime<Utc>, DateTime<Utc>, DateTime<Utc>, FileAttributes, Option<u32>, Option<u32>, Option<u64>)> {
    let content_offset = u16::from_le_bytes(attr[20..22].try_into().ok()?) as usize;

    if content_offset + 48 > attr.len() {
        return None;
    }

    let c = &attr[content_offset..];

    let created = filetime_to_utc(u64::from_le_bytes(c[0..8].try_into().ok()?))?;
    let modified = filetime_to_utc(u64::from_le_bytes(c[8..16].try_into().ok()?))?;
    let mft_modified = filetime_to_utc(u64::from_le_bytes(c[16..24].try_into().ok()?))?;
    let accessed = filetime_to_utc(u64::from_le_bytes(c[24..32].try_into().ok()?))?;
    
    let flags = u32::from_le_bytes(c[32..36].try_into().ok()?);
    let file_attrs = FileAttributes::from_flags(flags);
    
    // Extended fields (NTFS 3.0+)
    let owner_id = if c.len() >= 56 {
        Some(u32::from_le_bytes(c[48..52].try_into().ok()?))
    } else {
        None
    };
    
    let security_id = if c.len() >= 56 {
        Some(u32::from_le_bytes(c[52..56].try_into().ok()?))
    } else {
        None
    };
    
    let usn = if c.len() >= 72 {
        Some(u64::from_le_bytes(c[64..72].try_into().ok()?))
    } else {
        None
    };

    Some((created, modified, mft_modified, accessed, file_attrs, owner_id, security_id, usn))
}

fn parse_object_id(attr: &[u8]) -> Option<String> {
    let content_offset = u16::from_le_bytes(attr[20..22].try_into().ok()?) as usize;
    
    if content_offset + 16 > attr.len() {
        return None;
    }
    
    let guid_bytes = &attr[content_offset..content_offset + 16];
    
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid_bytes[3], guid_bytes[2], guid_bytes[1], guid_bytes[0],
        guid_bytes[5], guid_bytes[4],
        guid_bytes[7], guid_bytes[6],
        guid_bytes[8], guid_bytes[9],
        guid_bytes[10], guid_bytes[11], guid_bytes[12], guid_bytes[13], guid_bytes[14], guid_bytes[15]
    ))
}

fn parse_reparse_point(attr: &[u8]) -> Option<(u32, Option<String>)> {
    let content_offset = u16::from_le_bytes(attr[20..22].try_into().ok()?) as usize;
    
    if content_offset + 8 > attr.len() {
        return None;
    }
    
    let content = &attr[content_offset..];
    let tag = u32::from_le_bytes(content[0..4].try_into().ok()?);
    
    // Parse symlink/junction target for common reparse points
    let target = if tag == 0xA000000C || tag == 0xA0000003 {
        if content.len() >= 20 {
            let substitute_name_offset = u16::from_le_bytes(content[8..10].try_into().ok()?) as usize;
            let substitute_name_length = u16::from_le_bytes(content[10..12].try_into().ok()?) as usize;
            
            let path_buffer_offset = 20;
            let start = path_buffer_offset + substitute_name_offset;
            let end = start + substitute_name_length;
            
            if end <= content.len() {
                let utf16: Vec<u16> = content[start..end]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16(&utf16).ok()
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    
    Some((tag, target))
}

fn parse_ntfs_record(disk_image_buffer: &[u8], current_idx: usize, record_size: usize) -> Option<NtfsEntry> {
    if &disk_image_buffer[current_idx..current_idx + 4] != MFT_MAGIC {
        return None;
    }

    if current_idx + record_size > disk_image_buffer.len() {
        return None;
    }

    let record = &disk_image_buffer[current_idx..current_idx + record_size];

    // Parse MFT record header
    let sequence_number = u16::from_le_bytes(record[16..18].try_into().unwrap());
    let hardlink_count = u16::from_le_bytes(record[18..20].try_into().unwrap());
    let first_attr_offset = u16::from_le_bytes(record[20..22].try_into().unwrap()) as usize;
    let flags = u16::from_le_bytes(record[22..24].try_into().unwrap());
    let mft_record_number = u32::from_le_bytes(record[44..48].try_into().unwrap()) as u64;
    
    let is_in_use = flags & 0x01 != 0;
    let is_directory = flags & 0x02 != 0;

    let mut offset = first_attr_offset;
    let mut all_filenames = Vec::new();
    let mut data_streams = Vec::new();
    
    let mut created = None;
    let mut modified = None;
    let mut mft_modified = None;
    let mut accessed = None;
    let mut file_attributes = None;
    let mut owner_id = None;
    let mut security_id = None;
    let mut usn = None;
    let mut object_id = None;
    let mut reparse_tag = None;
    let mut reparse_target = None;
    let mut has_ea = false;

    while let Some((attr_type, len, non_resident, attr_name)) = parse_attr_header(record, offset) {
        let attr = &record[offset..offset + len];

        match attr_type {
            ATTR_FILE_NAME => {
                if let Some(fname) = parse_filename(attr) {
                    all_filenames.push(fname);
                }
            }
            ATTR_DATA => {
                if let Some(stream) = parse_data_attribute(attr, attr_name, non_resident) {
                    data_streams.push(stream);
                }
            }
            ATTR_STANDARD_INFORMATION => {
                if created.is_none() {
                    if let Some((c, m, mm, a, attrs, oid, sid, u)) = parse_standard_information(attr) {
                        created = Some(c);
                        modified = Some(m);
                        mft_modified = Some(mm);
                        accessed = Some(a);
                        file_attributes = Some(attrs);
                        owner_id = oid;
                        security_id = sid;
                        usn = u;
                    }
                }
            }
            ATTR_OBJECT_ID => {
                if object_id.is_none() {
                    object_id = parse_object_id(attr);
                }
            }
            ATTR_REPARSE_POINT => {
                if reparse_tag.is_none() {
                    if let Some((tag, target)) = parse_reparse_point(attr) {
                        reparse_tag = Some(tag);
                        reparse_target = target;
                    }
                }
            }
            ATTR_EA_INFORMATION => {
                has_ea = true;
            }
            _ => {}
        }

        offset += len;
    }

    if all_filenames.is_empty() {
        return None;
    }

    // Find main filename (prefer Win32/POSIX, not DOS)
    let main_idx = all_filenames.iter().position(|f| f.namespace == 1 || f.namespace == 3)
        .or_else(|| all_filenames.iter().position(|f| f.namespace == 0))
        .unwrap_or(0);

    let main = all_filenames.remove(main_idx);
    
    // Extract parent MFT record and sequence from the 48-bit reference
    let parent_mft_record = main.parent_reference & 0x0000_FFFF_FFFF_FFFF;
    let parent_sequence = ((main.parent_reference >> 48) & 0xFFFF) as u16;
    
    // Convert remaining to alternate filenames
    let alternate_filenames = all_filenames.into_iter()
        .map(|f| AlternateFilename {
            name: f.name,
            namespace: f.namespace,
        })
        .collect();

    Some(NtfsEntry {
        mft_offset: current_idx as u64,
        mft_record_number,
        sequence_number,
        hardlink_count,
        is_in_use,
        is_directory,
        filename: main.name,
        parent_mft_record,
        parent_sequence,
        allocated_size: main.allocated_size,
        real_size: main.real_size,
        created,
        modified,
        mft_modified,
        accessed,
        file_attributes,
        owner_id,
        security_id,
        usn,
        object_id,
        alternate_filenames,
        data_streams,
        reparse_tag,
        reparse_target,
        has_extended_attributes: has_ea,
    })
}

pub fn scan_ntfs_image(disk_image_buffer: &[u8]) -> impl Iterator<Item = NtfsEntry> + '_ {
    let record_size = 1024;

    (0..disk_image_buffer.len().saturating_sub(4))
        .step_by(8)
        .filter_map(move |i| parse_ntfs_record(disk_image_buffer, i, record_size))
}
