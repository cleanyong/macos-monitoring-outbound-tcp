use std::collections::HashMap;
use std::io::{self, Write};
use std::net::IpAddr;
use std::process::Command;
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
struct Connection {
    command: String,
    pid: String,
    user: String,
    remote_ip: String,
    remote_port: String,
}

fn main() {
    let mut dns_cache: HashMap<String, String> = HashMap::new();

    loop {
        match collect_connections() {
            Ok(conns) => {
                // 像 top 一樣回到左上角，避免整個螢幕閃爍
                print!("\x1b[H");
                println!("Outbound TCP connections (updated every second)");
                println!("(hostname is reverse-DNS of remote IP, cached)");
                println!();
                println!(
                    "{:<8} {:<16} {:<16} {:<40} {:<18} {:<6}",
                    "PID", "USER", "CMD", "REMOTE HOST", "REMOTE IP", "PORT"
                );
                println!("{}", "-".repeat(120));

                for c in conns {
                    let hostname = resolve_hostname(&c.remote_ip, &mut dns_cache);
                    println!(
                        "{:<8} {:<16} {:<16} {:<40} {:<18} {:<6}",
                        c.pid,
                        c.user,
                        c.command,
                        hostname,
                        c.remote_ip,
                        c.remote_port
                    );
                }

                // 確保立刻刷新畫面
                let _ = io::stdout().flush();
            }
            Err(e) => {
                eprintln!("Failed to collect connections: {e}");
            }
        }

        // 每秒更新一次
        thread::sleep(Duration::from_secs(1));
    }
}

fn collect_connections() -> Result<Vec<Connection>, String> {
    // 使用 macOS 上常見的 lsof 來列出已建立的 TCP 連線
    let output = Command::new("lsof")
        .args(["-iTCP", "-sTCP:ESTABLISHED", "-n", "-P"])
        .output()
        .map_err(|e| format!("failed to run lsof: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "lsof exited with status {status}",
            status = output.status
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();

    // 跳過 header
    let _header = lines.next();

    let mut conns = Vec::new();

    for line in lines {
        // lsof 輸出大致如下:
        // COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
        // Safari  1234 user   40u  IPv4 0x...      0t0  TCP 192.168.1.10:53123->93.184.216.34:443 (ESTABLISHED)
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 {
            continue;
        }

        let command = parts[0].to_string();
        let pid = parts[1].to_string();
        let user = parts[2].to_string();

        // NAME 欄位通常在最後, 我們找包含 "->" 的部分
        let mut name_field = None;
        for &p in &parts {
            if p.contains("->") {
                name_field = Some(p);
                break;
            }
        }
        let name_field = match name_field {
            Some(n) => n,
            None => continue,
        };

        // 解析 remote 端: local->remote
        let mut lr = name_field.split("->");
        let _local = lr.next();
        let remote = match lr.next() {
            Some(r) => r,
            None => continue,
        };

        // remote 格式: ip:port 或 [ip]:port
        let remote = remote.trim_matches(|c| c == '(' || c == ')' );
        let (ip_str, port_str) = match remote.rsplit_once(':') {
            Some((ip, port)) => (ip.to_string(), port.to_string()),
            None => continue,
        };

        conns.push(Connection {
            command,
            pid,
            user,
            remote_ip: ip_str,
            remote_port: port_str,
        });
    }

    Ok(conns)
}

fn resolve_hostname(ip: &str, cache: &mut HashMap<String, String>) -> String {
    if let Some(name) = cache.get(ip) {
        return name.clone();
    }

    let ip_addr: IpAddr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return String::from("-"),
    };

    match dns_lookup::lookup_addr(&ip_addr) {
        Ok(host) => {
            cache.insert(ip.to_string(), host.clone());
            host
        }
        Err(_) => String::from("-"),
    }
}
