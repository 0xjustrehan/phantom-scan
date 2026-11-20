use eframe::egui::{self, Context, Grid, Ui, Vec2};
use crate::gui::state::AppState;

pub struct GeoModalView;

impl GeoModalView {
    pub fn render(ctx: &Context, state: &mut AppState) {
        if !state.show_geo_modal {
            return;
        }

        let mut is_open = state.show_geo_modal;

        egui::Window::new("BGP Geo-IP Routing Downloader")
            .open(&mut is_open)
            .collapsible(false)
            .resizable(false)
            .default_width(360.0)
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing = Vec2::new(4.0, 4.0);

                ui.label("Decompose live BGP country/regional prefixes into optimal CIDRs.");
                ui.add_space(2.0);

                // Quick Presets
                ui.label("Presets:");
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = Vec2::new(3.0, 3.0);
                    if ui.small_button("Slavic").clicked() {
                        state.geo_region_input = "slavic".to_string();
                    }
                    if ui.small_button("Europe").clicked() {
                        state.geo_region_input = "europe".to_string();
                    }
                    if ui.small_button("Asia").clicked() {
                        state.geo_region_input = "asia".to_string();
                    }
                    if ui.small_button("North America").clicked() {
                        state.geo_region_input = "north_america".to_string();
                    }
                    if ui.small_button("South America").clicked() {
                        state.geo_region_input = "south_america".to_string();
                    }
                    if ui.small_button("Africa").clicked() {
                        state.geo_region_input = "africa".to_string();
                    }
                    if ui.small_button("Oceania").clicked() {
                        state.geo_region_input = "oceania".to_string();
                    }
                });

                ui.add_space(4.0);

                Grid::new("geo_grid")
                    .num_columns(2)
                    .spacing([8.0, 4.0])
                    .show(ui, |ui| {
                        ui.label("Target Region / ISO:");
                        ui.add(
                            egui::TextEdit::singleline(&mut state.geo_region_input)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(180.0),
                        );
                        ui.end_row();

                        ui.label("Exclude Countries:");
                        ui.add(
                            egui::TextEdit::singleline(&mut state.geo_exclude_input)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(180.0)
                                .hint_text("e.g. RU,BY"),
                        );
                        ui.end_row();
                    });

                if !state.geo_status_msg.is_empty() {
                    ui.add_space(2.0);
                    ui.colored_label(
                        if state.geo_status_msg.starts_with("Error") {
                            crate::gui::theme::Theme::STATUS_STOP
                        } else {
                            crate::gui::theme::Theme::HIT_TEXT
                        },
                        &state.geo_status_msg,
                    );
                }

                ui.add_space(6.0);

                ui.horizontal(|ui| {
                    if state.geo_loading {
                        ui.add(egui::Spinner::new());
                        ui.label("Fetching BGP table & compiling CIDRs...");
                    } else {
                        if ui.button("Fetch & Load Targets").clicked() {
                            state.trigger_geo_fetch();
                        }
                        if ui.button("Close").clicked() {
                            state.show_geo_modal = false;
                        }
                    }
                });
            });

        state.show_geo_modal = is_open;
    }
}
