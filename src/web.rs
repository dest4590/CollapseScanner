#[cfg(feature = "web-ui")]
use actix_multipart::Multipart;
#[cfg(feature = "web-ui")]
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
#[cfg(feature = "web-ui")]
use futures_util::StreamExt;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use crate::scanner::scan::CollapseScanner;
use crate::types::ScannerOptions;

#[cfg(not(feature = "web-ui"))]
compile_error!("web.rs compiled without feature `web-ui`. Enable the feature or remove the file.");

async fn index() -> impl Responder {
    let bytes: &'static [u8] = include_bytes!("../web/index.html");
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(bytes.to_vec())
}

async fn save_file(
    mut payload: Multipart,
    scanner: web::Data<Arc<CollapseScanner>>,
    opts: web::Data<Arc<ScannerOptions>>,
) -> impl Responder {
    let mut saved_paths: Vec<String> = Vec::new();

    while let Some(item) = payload.next().await {
        if let Ok(mut field) = item {
            let content_disposition = field.content_disposition();
            let filename = content_disposition
                .and_then(|cd| cd.get_filename().map(|s| s.to_string()))
                .unwrap_or_else(|| "upload.bin".to_string());

            let mut filepath = std::env::temp_dir();
            filepath.push(format!("collapsescanner_upload_{}", filename));

            let mut f = match File::create(&filepath) {
                Ok(x) => x,
                Err(e) => {
                    return HttpResponse::InternalServerError()
                        .body(format!("failed to create file: {}", e))
                }
            };

            while let Some(chunk) = field.next().await {
                let data = match chunk {
                    Ok(d) => d,
                    Err(e) => {
                        return HttpResponse::InternalServerError()
                            .body(format!("error reading chunk: {}", e))
                    }
                };
                if let Err(e) = f.write_all(&data) {
                    return HttpResponse::InternalServerError()
                        .body(format!("error writing file: {}", e));
                }
            }

            saved_paths.push(filepath.display().to_string());
        }
    }

    use serde_json::json;
    let mut reports: Vec<serde_json::Value> = Vec::new();

    for p in &saved_paths {
        let pbuf = PathBuf::from(p);
        let scan_result = std::thread::spawn({
            let sc = Arc::clone(&scanner);
            let pbuf_clone = pbuf.clone();
            move || sc.scan_path(&pbuf_clone)
        })
        .join();

        match scan_result {
            Ok(Ok(results)) => {
                let significant: Vec<&crate::types::ScanResult> = results
                    .iter()
                    .filter(|r| !r.matches.is_empty() || opts.verbose)
                    .collect();

                let total_findings: usize = significant.iter().map(|r| r.matches.len()).sum();

                let mut files: Vec<serde_json::Value> = Vec::new();
                for r in &significant {
                    let findings: Vec<serde_json::Value> = r
                        .matches
                        .iter()
                        .map(|(ft, v)| json!({"type": format!("{:?}", ft), "value": v}))
                        .collect();

                    files.push(json!({
                        "file_path": r.file_path,
                        "danger_score": r.danger_score,
                        "findings": findings
                    }));
                }

                reports.push(json!({
                    "uploaded_path": p,
                    "total_findings": total_findings,
                    "files": files
                }));
            }
            Ok(Err(e)) => {
                reports.push(json!({"uploaded_path": p, "error": e.to_string()}));
            }
            Err(e) => {
                reports
                    .push(json!({"uploaded_path": p, "error": format!("scan panicked: {:?}", e)}));
            }
        }
    }

    HttpResponse::Ok().json(reports)
}

pub fn run_web_ui(
    scanner: CollapseScanner,
    _opts: ScannerOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Arc::new(scanner);
    let opts = Arc::new(_opts);

    let data_scanner = web::Data::new(Arc::clone(&scanner));
    let data_opts = web::Data::new(Arc::clone(&opts));

    let sys = actix_rt::System::new();
    sys.block_on(async move {
        HttpServer::new(move || {
            App::new()
                .app_data(data_scanner.clone())
                .app_data(data_opts.clone())
                .route("/", web::get().to(index))
                .route("/upload", web::post().to(save_file))
        })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
    })?;

    Ok(())
}
