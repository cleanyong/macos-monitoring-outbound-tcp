use std::collections::{HashMap, HashSet};
use std::io::{self, Write, BufRead, BufReader};
use std::net::IpAddr;
use std::fs::{File, OpenOptions};
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
    // 如果命令行包含 "udp" (不區分大小寫)，則只監控 UDP；否則監控 TCP
    let args: Vec<String> = std::env::args().skip(1).collect();
    let monitor_udp = args.iter().any(|a| a.to_lowercase().contains("udp"));
    let protocol_label = if monitor_udp { "UDP" } else { "TCP" };

    let log_filename = if monitor_udp {
        "mac-monitoring-stats-UDP.log"
    } else {
        "mac-monitoring-stats.log"
    };

    let mut dns_cache: HashMap<String, String> = HashMap::new();
    // 從已存在的統計檔中載入已經記錄過的行，避免跨次啟動重複寫入
    let mut seen_lines: HashSet<String> = load_seen_lines(log_filename);

    loop {
        match collect_connections(monitor_udp) {
            Ok(conns) => {
                // 像 top 一樣回到左上角，避免整個螢幕閃爍
                print!("\x1b[H");
                println!("Outbound {protocol} connections (updated every second)", protocol = protocol_label);
                println!("(hostname is reverse-DNS of remote IP, cached)");
                println!();
                println!(
                    "{:<8} {:<16} {:<16} {:<40} {:<18} {:<6}",
                    "PID", "USER", "CMD", "REMOTE HOST", "REMOTE IP", "PORT"
                );
                println!("{}", "-".repeat(120));

                for c in conns {
                    let hostname = resolve_hostname(&c.remote_ip, &mut dns_cache);

                    // 這一行是螢幕上顯示的格式
                    let line = format!(
                        "{:<8} {:<16} {:<16} {:<40} {:<18} {:<6}",
                        c.pid,
                        c.user,
                        c.command,
                        hostname,
                        c.remote_ip,
                        c.remote_port
                    );
                    println!("{line}");

                    // 以整行顯示內容作為 key, 只在第一次出現時寫入統計檔 (跨啟動也不重複)
                    if !seen_lines.contains(&line) {
                        if let Err(e) = append_stats_line(&line, log_filename) {
                            eprintln!("Failed to write stats file: {e}");
                        } else {
                            seen_lines.insert(line.clone());
                        }
                    }
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

fn append_stats_line(line: &str, filename: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)
        .map_err(|e| format!("open stats file error: {e}"))?;

    writeln!(file, "{line}").map_err(|e| format!("write stats file error: {e}"))
}

fn collect_connections(monitor_udp: bool) -> Result<Vec<Connection>, String> {
    // 使用 macOS 上常見的 lsof 來列出連線
    let mut cmd = Command::new("lsof");
    if monitor_udp {
        cmd.args(["-iUDP", "-n", "-P"]);
    } else {
        cmd.args(["-iTCP", "-sTCP:ESTABLISHED", "-n", "-P"]);
    }

    let output = cmd
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

fn load_seen_lines(filename: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(file) = File::open(filename) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(l) = line {
                if !l.trim().is_empty() {
                    set.insert(l);
                }
            }
        }
    }
    set
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
