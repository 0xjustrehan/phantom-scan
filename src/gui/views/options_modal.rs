use eframe::egui::{self, Context, Grid, Ui, Vec2};
use crate::gui::state::AppState;

pub struct OptionsModalView;

impl OptionsModalView {
    pub fn render(ctx: &Context, state: &mut AppState) {
        if !state.show_options_modal {
            return;
        }

        let mut is_open = state.show_options_modal;

        egui::Window::new("Options")
            .open(&mut is_open)
            .collapsible(false)
            .resizable(false)
            .default_width(380.0)
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing = Vec2::new(4.0, 4.0);

                Grid::new("options_grid")
                    .num_columns(2)
                    .spacing([8.0, 4.0])
                    .show(ui, |ui| {
                        // Cooldown
                        ui.label("Subnet cooldown (ms)");
                        ui.add(egui::DragValue::new(&mut state.config.cooldown_ms).range(0..=60_000).speed(50.0));
                        ui.end_row();

                        // Compact cooldown
                        ui.label("Cooldown table");
                        ui.checkbox(&mut state.config.compact_cooldown, "Compact 4MB (hash) table");
                        ui.end_row();

                        // Randomize stack
                        ui.label("Stack randomization");
                        ui.checkbox(&mut state.config.randomize_stack, "Randomize TCP options & jitter TTL");
                        ui.end_row();

                        // Retries
                        ui.label("Retransmission passes");
                        ui.add(egui::DragValue::new(&mut state.config.retries).range(0..=5).speed(1.0));
                        ui.end_row();

                        // Source port range
                        ui.label("Source port range");
                        ui.add(egui::TextEdit::singleline(&mut state.config.source_port_range).font(egui::TextStyle::Monospace).desired_width(120.0));
                        ui.end_row();

                        // Source IP
                        ui.label("Source IPv4");
                        ui.add(egui::TextEdit::singleline(&mut state.config.source_ip).font(egui::TextStyle::Monospace).desired_width(140.0));
                        ui.end_row();

                        // Source IPv6
                        ui.label("Source IPv6");
                        ui.add(egui::TextEdit::singleline(&mut state.config.source_ip_v6).font(egui::TextStyle::Monospace).desired_width(180.0));
                        ui.end_row();

                        // Interface
                        ui.label("Interface (-I)");
                        ui.add(egui::TextEdit::singleline(&mut state.config.interface).font(egui::TextStyle::Monospace).desired_width(100.0));
                        ui.end_row();

                        // Gateway MAC
                        ui.label("Gateway MAC");
                        ui.add(egui::TextEdit::singleline(&mut state.config.gateway_mac).font(egui::TextStyle::Monospace).desired_width(140.0));
                        ui.end_row();

                        // Source MAC
                        ui.label("Source MAC");
                        ui.add(egui::TextEdit::singleline(&mut state.config.source_mac).font(egui::TextStyle::Monospace).desired_width(140.0));
                        ui.end_row();

                        // Fanout mode
                        ui.label("AF_PACKET fanout");
                        egui::ComboBox::from_id_salt("modal_fanout")
                            .selected_text(&state.config.fanout_mode)
                            .width(80.0)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut state.config.fanout_mode, "lb".to_string(), "lb");
                                ui.selectable_value(&mut state.config.fanout_mode, "hash".to_string(), "hash");
                                ui.selectable_value(&mut state.config.fanout_mode, "cpu".to_string(), "cpu");
                                ui.selectable_value(&mut state.config.fanout_mode, "rollover".to_string(), "rollover");
                            });
                        ui.end_row();

                        // IPv6 samples
                        ui.label("IPv6 prefix samples");
                        ui.add(egui::DragValue::new(&mut state.config.v6_samples).range(1..=65536).speed(10.0));
                        ui.end_row();

                        // Exclude CIDRs
                        ui.label("Exclude CIDRs");
                        ui.add(egui::TextEdit::singleline(&mut state.config.exclude).font(egui::TextStyle::Monospace).desired_width(180.0));
                        ui.end_row();

                        // Exclude file
                        ui.label("Exclude file");
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut state.config.exclude_file).font(egui::TextStyle::Monospace).desired_width(140.0));
                            if ui.button("...").clicked() {
                                if let Some(path) = rfd::FileDialog::new().set_title("Open Exclude File").pick_file() {
                                    state.config.exclude_file = path.display().to_string();
                                }
                            }
                        });
                        ui.end_row();

                        // Auto threat feeds
                        ui.label("Auto threat feeds");
                        ui.checkbox(&mut state.config.auto_feeds, "Refresh feeds on startup");
                        ui.end_row();

                        // JSONL output
                        ui.label("Format");
                        ui.checkbox(&mut state.config.jsonl, "JSON Lines output (--json)");
                        ui.end_row();
                    });

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    if ui.button("BGP Geo-IP Routing...").clicked() {
                        state.show_geo_modal = true;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Close").clicked() {
                            state.show_options_modal = false;
                        }
                    });
                });
            });

        state.show_options_modal = is_open;
    }
}
