use crate::cli;
use crate::error::PassmanError;
use crate::storage::PassmanStorage;
use eframe::egui;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEFAULT_M_COST: u32 = 65536;
const DEFAULT_T_COST: u32 = 10;
const DEFAULT_P_COST: u32 = 2;

pub struct PassmanGui {
    master_password: String,
    services: Vec<String>,
    status: Arc<Mutex<String>>,

    // Popups
    show_new_file_popup: bool,
    new_service_name: String,
    confirm_master_password: String,

    show_get_popup: bool,
    get_service_name: String,
    get_master_input: String,

    // Refresh trigger
    needs_refresh: Arc<Mutex<bool>>,
}

impl Default for PassmanGui {
    fn default() -> Self {
        let mut gui = PassmanGui {
            master_password: String::new(),
            services: Vec::new(),
            status: Arc::new(Mutex::new("Ready".to_string())),

            show_new_file_popup: false,
            new_service_name: String::new(),
            confirm_master_password: String::new(),

            show_get_popup: false,
            get_service_name: String::new(),
            get_master_input: String::new(),

            needs_refresh: Arc::new(Mutex::new(false)),
        };
        gui.refresh_services();
        gui
    }
}

impl PassmanGui {
    fn refresh_services(&mut self) {
        match cli::list_all_services() {
            Ok(list) => {
                self.services = list;
                *self.status.lock().unwrap() =
                    format!("Loaded {} services.", self.services.len());
            }
            Err(e) => {
                *self.status.lock().unwrap() =
                    format!("Error listing services: {}", e);
            }
        }
    }

    fn copy_password(&self, service: &str, master: &str) {
        let service = service.to_string();
        let master = master.to_string();
        let status = self.status.clone();

        std::thread::spawn(move || {
            if master.is_empty() {
                *status.lock().unwrap() =
                    "Please enter master password first.".to_string();
                return;
            }

            *status.lock().unwrap() = "Decrypting...".to_string();

            let storage = PassmanStorage::new(master.clone());

            match storage.retrieve(&service) {
                Ok(password) => {
                    if let Err(e) = cli::copy_to_clipboard(&password) {
                        *status.lock().unwrap() = format!("Failed to copy: {}", e);
                    } else {
                        *status.lock().unwrap() =
                            format!("Password for '{}' copied!", service);
                    }
                }
                Err(e) => {
                    *status.lock().unwrap() =
                        format!("Failed to decrypt '{}': {}", service, e);
                }
            }
        });
    }

    fn open_folder(&self) {
        if let path = PassmanStorage::get_default_path() {
            let path_str = path.to_string_lossy().to_string();
            *self.status.lock().unwrap() = format!("Opening folder: {}", path_str);

            #[cfg(target_os = "windows")]
            let _ = Command::new("explorer").arg(path_str).spawn();
            #[cfg(target_os = "linux")]
            let _ = Command::new("xdg-open").arg(path_str).spawn();
            #[cfg(target_os = "macos")]
            let _ = Command::new("open").arg(path_str).spawn();
        } else {
            *self.status.lock().unwrap() =
                "Failed to locate storage folder.".to_string();
        }
    }

    fn create_new_file(&mut self) {
        let master = self.master_password.clone();
        let service = self.new_service_name.trim().to_string();
        let status = self.status.clone();
        let refresh_flag = self.needs_refresh.clone();

        if master.is_empty() {
            *status.lock().unwrap() = "Enter master password first.".to_string();
            return;
        }

        if service.is_empty() {
            *status.lock().unwrap() = "Service name cannot be empty.".to_string();
            return;
        }

        *status.lock().unwrap() = "Creating new file...".to_string();
        let password_final = cli::generate_random_password(20);

        std::thread::spawn(move || {
            let storage = PassmanStorage::new(master.clone());

            match storage.store(&service, &password_final, DEFAULT_M_COST, DEFAULT_T_COST, DEFAULT_P_COST) {
                Ok(_) => {
                    *status.lock().unwrap() =
                        format!("Created new entry '{}'.", service);
                    *refresh_flag.lock().unwrap() = true; // mark for refresh
                }
                Err(e) => {
                    *status.lock().unwrap() =
                        format!("Failed to create '{}': {}", service, e);
                }
            }
        });
    }
}

impl eframe::App for PassmanGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Automatically refresh when flagged by background thread
        if *self.needs_refresh.lock().unwrap() {
            *self.needs_refresh.lock().unwrap() = false;
            self.refresh_services();
        }

        //
        // Top bar
        //
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("PassMan");

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("📂 Open Folder").clicked() {
                        self.open_folder();
                    }
                    if ui.button("➕ New File").clicked() {
                        self.show_new_file_popup = true;
                    }
                });
            });
        });

        //
        // Central content
        //
        egui::CentralPanel::default().show(ctx, |ui| {
            if ui.button("🔄 Refresh services").clicked() {
                self.refresh_services();
            }
            ui.label(format!("{} stored services", self.services.len()));

            ui.separator();

            if self.services.is_empty() {
                ui.label("No services found.");
            } else {
                ui.vertical(|ui| {
                    for service in &self.services {
                        ui.horizontal(|ui| {
                            if ui.button("🔑 Get").clicked() {
                                self.get_service_name = service.clone();
                                self.get_master_input.clear();
                                self.show_get_popup = true;
                            }
                            ui.label(service);
                        });
                    }
                });
            }

            ui.separator();
            ui.label(format!("Status: {}", self.status.lock().unwrap()));
        });

        //
        // New file popup
        //
        if self.show_new_file_popup {
            egui::Window::new("Create New Service")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Enter service name:");
                    ui.text_edit_singleline(&mut self.new_service_name);

                    ui.separator();

                    ui.label("Enter master password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.master_password)
                            .password(true)
                            .hint_text("Master password"),
                    );

                    ui.label("Confirm master password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.confirm_master_password)
                            .password(true)
                            .hint_text("Confirm master password"),
                    );

                    ui.separator();

                    ui.horizontal(|ui| {
                        if ui.button("Create").clicked() {
                            if self.master_password != self.confirm_master_password {
                                *self.status.lock().unwrap() = 
                                    "Master passwords do not match.".to_string();
                            } else {
                                self.create_new_file();
                                self.refresh_services();
                                self.new_service_name.clear();
                                self.master_password.clear();
                                self.confirm_master_password.clear();
                                self.show_new_file_popup = false;
                            }
                        }

                        if ui.button("Cancel").clicked() {
                            self.new_service_name.clear();
                            self.master_password.clear();
                            self.confirm_master_password.clear();
                            self.show_new_file_popup = false;
                        }
                    });
                });
        }


        //
        // Popup for getting a password
        //
        if self.show_get_popup {
            egui::Window::new(format!("Get password for '{}'", self.get_service_name))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Enter master password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.get_master_input)
                            .password(true)
                            .hint_text("Master password"),
                    );

                    ui.horizontal(|ui| {
                        if ui.button("Decrypt").clicked() {
                            self.copy_password(
                                &self.get_service_name,
                                &self.get_master_input,
                            );
                            self.show_get_popup = false;
                            self.get_master_input.clear();
                        }

                        if ui.button("Cancel").clicked() {
                            self.show_get_popup = false;
                            self.get_master_input.clear();
                        }
                    });
                });
        }

        ctx.request_repaint_after(Duration::from_millis(200));
    }
}
