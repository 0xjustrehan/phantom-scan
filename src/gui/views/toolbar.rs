use eframe::egui::{self, Color32, Margin, RichText, Stroke, Ui, Vec2};
use crate::gui::state::{AppState, ScanStatus};
use crate::gui::theme::Theme;

pub struct ToolbarView;

impl ToolbarView {
    pub fn render(ui: &mut Ui, state: &mut AppState) {
        ui.horizontal_centered(|ui| {
            ui.spacing_mut().item_spacing = Vec2::new(4.0, 0.0);

            // [Start]
            let can_start = state.status == ScanStatus::Idle
                || state.status == ScanStatus::Done
                || state.status == ScanStatus::Error;

            let start_btn = ui.add_enabled(
                can_start,
                egui::Button::new(RichText::new("Start").color(Color32::WHITE))
                    .fill(Theme::BTN_START_FILL)
                    .min_size(Vec2::new(48.0, 20.0)),
            );
            if start_btn.clicked() {
                state.start_scan();
            }

            // [Stop]
            let can_stop = state.status == ScanStatus::Scanning
                || state.status == ScanStatus::Paused
                || state.status == ScanStatus::Draining;

            let stop_btn = ui.add_enabled(
                can_stop,
                egui::Button::new(RichText::new("Stop").color(Color32::WHITE))
                    .fill(Theme::BTN_STOP_FILL)
                    .min_size(Vec2::new(48.0, 20.0)),
            );
            if stop_btn.clicked() {
                state.stop_scan();
            }

            ui.add_space(3.0);
            ui.separator();
            ui.add_space(3.0);

            // [Engine ▼]
            ui.label("Engine");
            egui::ComboBox::from_id_salt("toolbar_engine")
                .selected_text(&state.config.mode)
                .width(105.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut state.config.mode, "stealth-async".to_string(), "stealth-async");
                    ui.selectable_value(&mut state.config.mode, "raw-syn".to_string(), "raw-syn");
                    #[cfg(target_os = "linux")]
                    ui.selectable_value(&mut state.config.mode, "af-packet".to_string(), "af-packet");
                });

            ui.add_space(3.0);

            // [Rate] [____] pps
            ui.label("Rate");
            egui::Frame::none()
                .fill(Theme::BG_LIST)
                .stroke(Stroke::new(1.0_f32, Theme::BORDER))
                .inner_margin(Margin::symmetric(4.0, 1.0))
                .show(ui, |ui| {
                    ui.add(
                        egui::DragValue::new(&mut state.config.rate)
                            .range(1..=10_000_000)
                            .speed(100.0),
                    );
                });
            ui.label("pps");

            ui.add_space(3.0);

            // [Threads] [__]
            ui.label("Threads");
            egui::Frame::none()
                .fill(Theme::BG_LIST)
                .stroke(Stroke::new(1.0_f32, Theme::BORDER))
                .inner_margin(Margin::symmetric(4.0, 1.0))
                .show(ui, |ui| {
                    ui.add(
                        egui::DragValue::new(&mut state.config.tx_threads)
                            .range(1..=512)
                            .speed(1.0),
                    );
                });

            ui.add_space(3.0);

            // Profile [Random ▼]
            ui.label("Profile");
            egui::ComboBox::from_id_salt("toolbar_profile")
                .selected_text(&state.config.profile)
                .width(80.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut state.config.profile, "Random".to_string(), "Random");
                    ui.selectable_value(&mut state.config.profile, "Windows".to_string(), "Windows");
                    ui.selectable_value(&mut state.config.profile, "Linux".to_string(), "Linux");
                    ui.selectable_value(&mut state.config.profile, "macOS".to_string(), "macOS");
                    ui.selectable_value(&mut state.config.profile, "FreeBSD".to_string(), "FreeBSD");
                    ui.selectable_value(&mut state.config.profile, "Android".to_string(), "Android");
                });

            // Options... button on right
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let opt_btn = ui.add(
                    egui::Button::new("Options…")
                        .min_size(Vec2::new(0.0, 20.0)),
                );
                if opt_btn.clicked() {
                    state.show_options_modal = !state.show_options_modal;
                }
            });
        });
    }
}
