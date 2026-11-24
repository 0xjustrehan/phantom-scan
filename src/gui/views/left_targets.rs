use eframe::egui::{self, FontId, RichText, Ui, Vec2};
use crate::gui::state::AppState;
use crate::gui::theme::Theme;

pub struct LeftTargetsView;

impl LeftTargetsView {
    pub fn render(ui: &mut Ui, state: &mut AppState) {
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing = Vec2::new(0.0, 3.0);

            // Targets label & multiline editor
            ui.label("Targets");
            let target_w = ui.available_width();
            ui.add(
                egui::TextEdit::multiline(&mut state.config.target)
                    .font(egui::TextStyle::Monospace)
                    .desired_rows(7)
                    .desired_width(target_w),
            );

            // [Load] [Save] [Clear] (No unexplained buttons on primary surface)
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing = Vec2::new(3.0, 0.0);
                ui.spacing_mut().button_padding = Vec2::new(6.0, 2.0);

                if ui.button("Load").clicked() {
                    if let Some(path) = rfd::FileDialog::new().set_title("Open Targets File").pick_file() {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            state.config.target = content;
                            state.config.targets_file = path.display().to_string();
                        }
                    }
                }

                if ui.button("Save").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Save Targets")
                        .set_file_name("targets.txt")
                        .save_file()
                    {
                        let _ = std::fs::write(&path, &state.config.target);
                    }
                }

                if ui.button("Clear").clicked() {
                    state.config.target.clear();
                    state.config.targets_file.clear();
                }
            });

            ui.add_space(4.0);

            // 1. PORTS ROW: Label "Ports" then a proper text field with clear left margin (8 px)
            ui.horizontal(|ui| {
                ui.label("Ports");
                ui.add_space(8.0);
                let ports_w = ui.available_width();
                ui.add(
                    egui::TextEdit::singleline(&mut state.config.ports)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(ports_w),
                );
            });

            // Preset buttons on NEXT line, full text, no truncation: [3389] [22] [80,443] [445] [common]
            // Same height (19px), same padding, plain/monospace, not cut off
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing = Vec2::new(2.0, 0.0);
                ui.spacing_mut().button_padding = Vec2::new(3.0, 1.5);
                let font = FontId::proportional(11.0);

                let presets = [
                    ("3389", "3389"),
                    ("22", "22"),
                    ("80,443", "80,443"),
                    ("445", "445"),
                    ("common", "common"),
                ];

                for (label, val) in presets {
                    let btn = egui::Button::new(RichText::new(label).font(font.clone()))
                        .min_size(Vec2::new(0.0, 19.0));
                    if ui.add(btn).clicked() {
                        state.config.ports = val.to_string();
                    }
                }

                let quick_nla_btn = egui::Button::new(RichText::new("Quick NLA").font(font.clone()))
                    .min_size(Vec2::new(0.0, 19.0));
                if ui.add(quick_nla_btn).clicked() {
                    state.config.ports = "3389".to_string();
                    state.config.banner = true;
                    state.config.nla_only = true;
                    state.config.bare = true;
                    state.config.output_file = "NLA.txt".to_string();
                }

                let quick_ssh_btn = egui::Button::new(RichText::new("Quick SSH").font(font.clone()))
                    .min_size(Vec2::new(0.0, 19.0));
                if ui.add(quick_ssh_btn).clicked() {
                    state.config.ports = "22".to_string();
                    state.config.banner = false;
                    state.config.nla_only = false;
                    state.config.bare = true;
                    state.config.output_file = "SSH.txt".to_string();
                }
            });

            ui.add_space(4.0);

            // Checkboxes
            ui.horizontal(|ui| {
                ui.checkbox(&mut state.config.scan_private, "Private ranges");
                ui.checkbox(&mut state.config.banner, "Grab banners");
            });
            ui.horizontal(|ui| {
                if ui.checkbox(&mut state.config.nla_only, "NLA only").changed() && state.config.nla_only {
                    state.config.banner = true;
                }
                ui.checkbox(&mut state.config.bare, "Bare IP:PORT");
            });

            ui.add_space(4.0);

            // Output [_______________] [...]
            ui.label("Output");
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing = Vec2::new(2.0, 0.0);
                let out_w = (ui.available_width() - 26.0).max(60.0);

                ui.add(
                    egui::TextEdit::singleline(&mut state.config.output_file)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(out_w),
                );

                let browse_btn = egui::Button::new("...")
                    .min_size(Vec2::new(22.0, 19.0));
                if ui.add(browse_btn).clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .set_title("Select Output File")
                        .set_file_name("open_targets.txt")
                        .save_file()
                    {
                        state.config.output_file = path.display().to_string();
                    }
                }
            });
        });
    }
}
