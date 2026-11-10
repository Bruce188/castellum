#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Native window onto a Castellum server. The server stays the single source of truth
//! (and the browser a first-class client); this shell only replaces the browser tab.
//! The remote page gets no Tauri IPC: there are no capabilities granted to it.

use std::{net::TcpStream, thread, time::Duration};
use tauri::{Url, WebviewUrl, WebviewWindowBuilder};

const DEFAULT_URL: &str = "http://localhost:8080";

fn server_url() -> Url {
    let raw = std::env::var("CASTELLUM_URL").unwrap_or_else(|_| DEFAULT_URL.into());
    match Url::parse(&raw) {
        Ok(u) if matches!(u.scheme(), "http" | "https") => u,
        _ => {
            eprintln!("CASTELLUM_URL must be an http(s) URL, got {raw:?}; using {DEFAULT_URL}");
            Url::parse(DEFAULT_URL).unwrap()
        }
    }
}

fn reachable(url: &Url) -> bool {
    url.socket_addrs(|| None)
        .map(|addrs| {
            addrs
                .iter()
                .any(|a| TcpStream::connect_timeout(a, Duration::from_secs(1)).is_ok())
        })
        .unwrap_or(false)
}

fn main() {
    let url = server_url();
    tauri::Builder::default()
        .setup(move |app| {
            // Local waiting page first; switch to the server once its port accepts connections.
            let window = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title(format!("Castellum ({url})"))
                .inner_size(1440.0, 900.0)
                .min_inner_size(900.0, 600.0)
                .build()?;
            thread::spawn(move || {
                // ponytail: polls until the server is up, no timeout; the waiting page stays meanwhile.
                while !reachable(&url) {
                    thread::sleep(Duration::from_secs(1));
                }
                if let Err(e) = window.navigate(url) {
                    eprintln!("failed to open Castellum: {e}");
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Castellum desktop");
}
