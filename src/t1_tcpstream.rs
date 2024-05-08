use std::io::{Read, Write};
use std::net::TcpStream;

fn main() {
    // 建立与 example.com 网站的 TCP 连接
    let mut stream = TcpStream::connect("example.com:80").expect("Failed to connect to server");

    // 构造 HTTP GET 请求
    let request = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";

    // 发送 HTTP GET 请求
    stream
        .write_all(request.as_bytes())
        .expect("Failed to send request");

    // 读取响应
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("Failed to read response");

    // 打印响应内容
    println!("{}", response);
}
