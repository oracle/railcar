use log::{Log, LogRecord, LogLevel, LogMetadata};
use std::fs::OpenOptions;
use std::io::Write;

pub struct SimpleLogger;

impl Log for SimpleLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevel::Debug
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());

            if let Ok(mut f) = OpenOptions::new().append(true).open(
                "/home/vishvananda/railcar/log",
            )
            {
                f.write_all(
                    format!{"{} = {}\n", record.level(), record.args()}
                        .as_bytes(),
                ).unwrap();
            };
        }
    }
}
