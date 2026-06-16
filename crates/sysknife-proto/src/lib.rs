pub mod sysknife {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/sysknife.v1.rs"));
    }
}
