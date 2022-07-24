use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

use serde::{de::DeserializeOwned, Serialize};

pub fn read_value_from_stream<T: DeserializeOwned>(stream: &mut TcpStream) -> io::Result<T> {
    // Each value is prefixed by 4 bytes specifying the length.
    let mut buf = [0; 4];
    stream.read_exact(&mut buf)?;
    let length = u32::from_be_bytes(buf);

    let mut data = vec![0; length as usize];
    stream.read_exact(&mut data)?;
    let s = String::from_utf8(data).map_err(|r| io::Error::new(io::ErrorKind::InvalidData, r))?;

    let val: T = serde_json::from_str(&s)?;
    Ok(val)
}

pub fn write_value_to_stream<T: Serialize>(stream: &mut TcpStream, value: &T) -> io::Result<()> {
    let s = serde_json::to_string(value)?;
    let data = s.as_bytes();
    let length = data.len() as u32;

    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(data)?;
    Ok(())
}
