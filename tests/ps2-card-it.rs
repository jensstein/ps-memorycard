// This module is not compiled when the `test-ps2-card` feature isn't enabled
#[cfg(test)]
#[cfg(feature = "test-ps2-card")]
mod test {
    use ps_memorycard::{auth::read_card_keys, get_memory_card, CardResult};

    use std::path::Path;

    #[test]
    fn test_authentication() {
        let mc = get_memory_card(0x054c, 0x02ea, Some("card-keys")).expect("Unable to get memory card").expect("No memory card present");
        match mc {
            CardResult::PS1 => {
                assert!(false, "Cannot test authentication for PS1 type memory card");
            },
            CardResult::PS2(mc) => {
                mc.auth_reset().expect("Unable to reset authentication status");
                assert_eq!(false, mc.is_authenticated().expect("Unable to get authentication status"));
                let ck = read_card_keys(Path::new("card-keys")).expect("Unable to read card keys");
                mc.authenticate(&ck).expect("Unable to authenticate card");
                mc.set_termination_code().expect("Unable to set termination code");
                assert_eq!(true, mc.is_authenticated().expect("Unable to get authentication status"));
            }
        }
    }
}
