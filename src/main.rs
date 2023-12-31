use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use prettytable::{Table, Row, Cell, Attr, color};
use prettytable::row;
use prettytable::format;
use std::fs;
use std::collections::HashMap;
use clap::{App, Arg};

fn get_process_names(pids: &[u32]) -> HashMap<u32, String> {
    let mut process_names = HashMap::new();
    for &pid in pids {
        let comm_path = format!("/proc/{}/comm", pid);
        if let Ok(name) = fs::read_to_string(comm_path) {
            process_names.insert(pid, name.trim().to_string());
        }
    }
    process_names
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = App::new("nrs")
        .version("1.0")
        .author("@adamkadaban")
        .about("Netstat with sensible defaults")
        .arg(Arg::with_name("tcp")
            .short("t")
            .long("tcp")
            .help("Display TCP sockets.")
            .takes_value(false))
        .arg(Arg::with_name("udp")
            .short("u")
            .long("udp")
            .help("Display UDP sockets.")
            .takes_value(false))
        .arg(Arg::with_name("listening")
            .short("l")
            .long("listening")
            .help("Display  only  listening sockets (these are omitted by default).")
            .takes_value(false))
        .arg(Arg::with_name("inet6")
            .short("6")
            .long("inet6")
            .help("Display only IP version 6 sockets")
            .takes_value(false))
        .arg(Arg::with_name("inet4")
            .short("4")
            .long("inet4")
            .help("Display only IP version 4 sockets")
            .takes_value(false))
        .arg(Arg::with_name("numbers")
            .short("N")
            .long("numbers")
            .help("Show row number alongside socket entries")
            .takes_value(false))
        .arg(Arg::with_name("colors")
            .short("c")
            .long("colors")
            .help("Show colors in output")
            .takes_value(false))
        .arg(Arg::with_name("compact")
            .short("C")
            .long("compact")
            .help("Output in compact table")
            .takes_value(false))
        .arg(Arg::with_name("ascii")
            .short("s")
            .long("ascii")
            .help("Use ascii instead of unicode for table output")
            .takes_value(false))
        .get_matches();


    let listening_sockets = matches.is_present("listening");
    let ipv4_sockets = matches.is_present("inet4");
    let ipv6_sockets = matches.is_present("inet6");
    let udp_sockets = matches.is_present("udp");
    let tcp_sockets = matches.is_present("tcp");
    let show_numbers = matches.is_present("numbers");
    let show_colors = matches.is_present("colors");
    let be_compact = matches.is_present("compact");
    let use_ascii = matches.is_present("ascii");


    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets_info = get_sockets_info(af_flags, proto_flags)?;

    let mut table = Table::new();
    table.set_format(*format::consts::FORMAT_NO_LINESEP_WITH_TITLE);
    if be_compact{
        table.set_format(*format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR);
    }
    else if !use_ascii{
        table.set_format(*format::consts::FORMAT_BOX_CHARS);
    }
    table.set_titles(row![
        Fr->"No.",
        Fc->"Protocol",
        Fc->"Local Address:Port",
        //Fc->"Local Address",
        //Fc->"Local Port",
        Fc->"Remote Address",
        Fc->"Remote Port",
        Fc->"PID/Program Name",
        Fc->"State"
    ]);

    let pids: Vec<u32> = sockets_info
        .iter()
        .flat_map(|si| si.associated_pids.iter().copied())
        .collect();

    let process_names = get_process_names(&pids);

    let mut index = 0;

    for si in sockets_info.iter() {
        let state_cell = if let ProtocolSocketInfo::Tcp(tcp_si) = &si.protocol_socket_info {
            if tcp_si.state == netstat2::TcpState::Established {
                Cell::new(&tcp_si.state.to_string()).with_style(Attr::ForegroundColor(color::GREEN))
            } 
            else {
                Cell::new(&tcp_si.state.to_string())
            }
        } else {
            Cell::new("")
        };

        let protocol_type = if let ProtocolSocketInfo::Tcp(_) = &si.protocol_socket_info {
            if si.local_addr().is_ipv6() {
                "TCP6"
            } else {
                "TCP"
            }
        } else if let ProtocolSocketInfo::Udp(_) = &si.protocol_socket_info{
            if si.local_addr().is_ipv6() {
                "UDP6"
            } else {
                "UDP"
            }
        } else {
            ""
        };



        let row_number = Cell::new((index + 1).to_string().as_str());
        let pid = si.associated_pids.first().cloned().unwrap_or(0);
        let program_name = process_names.get(&pid).cloned().unwrap_or_else(String::new);
        let pid_program_name = if program_name.is_empty() {
            String::new()
        } else {
            format!("{}/{}", pid, program_name)
        };


        let row = match (&si.protocol_socket_info, &si.local_addr().is_ipv6()) {
            (ProtocolSocketInfo::Tcp(tcp_si), false) => {
                Row::new(vec![
                    row_number,
                    Cell::new(protocol_type),
                    Cell::new(format!("{}:{}",&tcp_si.local_addr,&tcp_si.local_port).as_str()),
                    // Cell::new(&tcp_si.local_addr.to_string()),
                    // Cell::new(&tcp_si.local_port.to_string()),
                    Cell::new(&tcp_si.remote_addr.to_string()),
                    Cell::new(&tcp_si.remote_port.to_string()),
                    Cell::new(&pid_program_name),
                    state_cell,
                ])
            }
            (ProtocolSocketInfo::Tcp(tcp_si), true) => {
                // Handle IPv6 TCP connection
                Row::new(vec![
                    row_number,
                    Cell::new(protocol_type),
                    Cell::new(format!("[{}]:{}",&tcp_si.local_addr,&tcp_si.local_port).as_str()),
                    // Cell::new(&tcp_si.local_addr.to_string()),
                    // Cell::new(&tcp_si.local_port.to_string()),
                    Cell::new(&tcp_si.remote_addr.to_string()),
                    Cell::new(&tcp_si.remote_port.to_string()),
                    Cell::new(&pid_program_name),
                    state_cell,
                ])
            }
            (ProtocolSocketInfo::Udp(udp_si), false) => {
                Row::new(vec![
                    row_number,
                    Cell::new(protocol_type),
                    Cell::new(format!("{}:{}",&udp_si.local_addr,&udp_si.local_port).as_str()),
                    // Cell::new(&udp_si.local_addr.to_string()),
                    // Cell::new(&udp_si.local_port.to_string()),
                    Cell::new("*"),
                    Cell::new("*"),
                    Cell::new(&pid_program_name),
                    Cell::new(""),
                ])
            }
            (ProtocolSocketInfo::Udp(udp_si), true) => {
                // Handle IPv6 UDP connection
                Row::new(vec![
                    row_number,
                    Cell::new(protocol_type),
                    Cell::new(format!("{}:{}",&udp_si.local_addr,&udp_si.local_port).as_str()),
                    // Cell::new(&udp_si.local_addr.to_string()),
                    // Cell::new(&udp_si.local_port.to_string()),
                    Cell::new("*"),
                    Cell::new("*"),
                    Cell::new(&pid_program_name),
                    Cell::new(""),
                ])
            }
        };


        // Adding TCP sockets to the table
        if (&protocol_type[0..3] == "TCP") && (tcp_sockets == true || (tcp_sockets == false && udp_sockets == false)){
            if (si.local_addr().is_ipv6()) && (ipv6_sockets == true || (ipv4_sockets == false && ipv6_sockets == false)){
                table.add_row(row);
                index += 1;
            } else if (!si.local_addr().is_ipv6()) && (ipv4_sockets == true || (ipv4_sockets == false && ipv6_sockets == false)){
                table.add_row(row);
                index += 1;
            }
        // Adding UDP sockets to the table
        } else if (&protocol_type[0..3] == "UDP") && (udp_sockets == true || (tcp_sockets == false && udp_sockets == false)){
            if (si.local_addr().is_ipv6()) && (ipv6_sockets == true || (ipv4_sockets == false && ipv6_sockets == false)){
                table.add_row(row);
                index += 1;
            } else if (!si.local_addr().is_ipv6()) && (ipv4_sockets == true || (ipv4_sockets == false && ipv6_sockets == false)){
                table.add_row(row);
                index += 1;
            }
        }

    }

    table.printstd();

 
    Ok(())
}