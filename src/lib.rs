pub mod smbios {
    use std::fs::{File, read_dir};
    use std::io::{Read, Seek, SeekFrom};

    fn read_raw_mem(address: u64, bytes_count: usize) -> Result<Vec<u8>, u8> {
        let mut mem_handle = File::open("/dev/mem").unwrap();
        mem_handle.metadata().unwrap().permissions().set_readonly(true);
        mem_handle.seek(SeekFrom::Start(address)).unwrap();

        let mut memory_data: Vec<u8> = vec![0; bytes_count];

        let read_bytes = mem_handle.read(&mut memory_data).unwrap();
        if read_bytes != bytes_count {
            Err(0)
        }
        else {
            Ok(memory_data)
        }
    }

    const ANCHOR_REV_3_LENGHT: usize = 24;
    const ANCHOR_REV_2_LENGHT: usize = 32;
    const SMBIOS_ANCHOR_AREA_START: u64 = 0x000F0000;
    const SMBIOS_ANCHOR_AREA_END: u64 = 0x000FFFFF;
    const SMBIOS_ANCHOR_UTIL_SIZE: usize = 4;

    enum AnchorVer {
        Rev2,
        Rev3,
    }

    struct Anchor {
        entry_point_checksum: u8,
        entry_point_lenght: u8,
        major_version: u8,
        minor_version: u8,
        doc_rev: u8,
        entry_point_rev: u8,
        structure_table_max_size: u32,
        structure_table_address: u64,
    }

    impl Anchor {
        pub fn new(address: u64, rev: AnchorVer) -> Anchor {

            let parsed_anchor = match rev {
                AnchorVer::Rev2 => {
                    Anchor::create_anchor_rev_2(read_raw_mem(address, ANCHOR_REV_2_LENGHT).unwrap())
                },
                AnchorVer::Rev3 => {
                    Anchor::create_anchor_rev_3(read_raw_mem(address, ANCHOR_REV_3_LENGHT).unwrap())
                },
            };

            parsed_anchor
        }

        fn create_anchor_rev_2 (anchor_raw_data: Vec<u8>) -> Anchor {
            let mut raw_struct_max_size: [u8; 2] = [0; 2];
            raw_struct_max_size.copy_from_slice(&anchor_raw_data[22..24]);

            let mut raw_table_address: [u8; 4] = [0; 4];
            raw_table_address.copy_from_slice(&anchor_raw_data[24..28]);

            Anchor {
                entry_point_checksum: anchor_raw_data[4],
                entry_point_lenght: anchor_raw_data[5],
                major_version: anchor_raw_data[6],
                minor_version: anchor_raw_data[7],
                doc_rev: 0,
                entry_point_rev: anchor_raw_data[10],
                structure_table_max_size: u16::from_le_bytes(raw_struct_max_size) as u32,
                structure_table_address: u32::from_le_bytes(raw_table_address) as u64,
            }
        }

        fn create_anchor_rev_3 (anchor_raw_data: Vec<u8>) -> Anchor {
            let mut raw_struct_max_size: [u8; 4] = [0; 4];
            raw_struct_max_size.copy_from_slice(&anchor_raw_data[12..16]);

            let mut raw_table_address: [u8; 8] = [0; 8];
            raw_table_address.copy_from_slice(&anchor_raw_data[16..24]);

            Anchor {
                entry_point_checksum: anchor_raw_data[5],
                entry_point_lenght: anchor_raw_data[6],
                major_version: anchor_raw_data[7],
                minor_version: anchor_raw_data[8],
                doc_rev: anchor_raw_data[9],
                entry_point_rev: anchor_raw_data[10],
                structure_table_max_size: u32::from_le_bytes(raw_struct_max_size),
                structure_table_address: u64::from_le_bytes(raw_table_address),
            }
        }
    }

    fn get_smbios_anchor() -> Result<Anchor, u8> {
        for address in SMBIOS_ANCHOR_AREA_START..SMBIOS_ANCHOR_AREA_END - 4 {
            let data = read_raw_mem(address, SMBIOS_ANCHOR_UTIL_SIZE).unwrap();
            let ascii_data = String::from_utf8(data);

            if let Ok(ascii) = ascii_data {
                if ascii.to_ascii_uppercase() == "_SM_".to_ascii_uppercase() {
                    return Ok(Anchor::new(address, AnchorVer::Rev2));
                }
                else if ascii.to_ascii_uppercase() == "_SM3".to_ascii_uppercase() {
                    return Ok(Anchor::new(address, AnchorVer::Rev3));
                }
            }
        }
        Err(0)
    }

    #[cfg(test)]
    mod tests{
        use super::*;

        #[test]
        fn read_test() {
            let read_data = read_raw_mem(SMBIOS_ANCHOR_AREA_END, 1);
            assert!(read_data.is_ok());
        }

        #[test]
        fn get_anchor_test () {
            let anchor = get_smbios_anchor();
            assert!(anchor.is_ok());
            let good_anchor = anchor.unwrap();
            assert_eq!(good_anchor.doc_rev, 0x00);
        }
    }

}
