mod storage {
    #[cfg(feature = "sqlite")]
    mod adapter;
    mod record_manager;
    mod remote_changes;
    #[cfg(feature = "sqlite")]
    mod sqlite;
}
