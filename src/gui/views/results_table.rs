use eframe::egui::{self, Color32, FontId, Layout, RichText, Sense, Stroke, Ui, Vec2};
use egui_extras::{Column, TableBuilder};
use crate::gui::state::AppState;
use crate::gui::theme::Theme;

pub struct ResultsTableView;

impl ResultsTableView {
    pub fn render(ui: &mut Ui, state: &mut AppState) {
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing = Vec2::new(0.0, 3.0);

            // Filter box sits directly above the table, matching table width
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing = Vec2::new(4.0, 0.0);
                ui.label(RichText::new("Filter:").size(11.0).color(Theme::TEXT_MUTED));

                let has_clear = !state.filter_query.is_empty();
                let clear_space = if has_clear { 44.0 } else { 0.0 };
                let filter_w = (ui.available_width() - clear_space).max(60.0);

                let edit = ui.add(
                    egui::TextEdit::singleline(&mut state.filter_query)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(filter_w),
                );
                if edit.changed() {
                    state.update_filter();
                }

                if has_clear && ui.small_button("Clear").clicked() {
                    state.filter_query.clear();
                    state.update_filter();
                }
            });

            // Results Table
            let total_rows = state.filtered_indices.len();

            let mut action_copy_ip: Option<String> = None;
            let mut action_copy_ipport: Option<String> = None;
            let mut action_open_url: Option<String> = None;
            let mut action_clear = false;

            TableBuilder::new(ui)
                .striped(true)
                .cell_layout(Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(130.0).at_least(110.0).resizable(true)) // IP
                .column(Column::initial(52.0).at_least(45.0).resizable(true))   // Port
                .column(Column::remainder().at_least(120.0))                     // Banner
                .column(Column::exact(65.0))                                     // Time
                .header(19.0, |mut header| {
                    header.col(|ui| {
                        ui.label(RichText::new("IP").monospace().size(11.0).strong().color(Theme::TEXT_MAIN));
                        ui.painter().hline(ui.max_rect().x_range(), ui.max_rect().bottom(), Stroke::new(1.0_f32, Theme::BORDER));
                    });
                    header.col(|ui| {
                        ui.label(RichText::new("Port").monospace().size(11.0).strong().color(Theme::TEXT_MAIN));
                        ui.painter().hline(ui.max_rect().x_range(), ui.max_rect().bottom(), Stroke::new(1.0_f32, Theme::BORDER));
                    });
                    header.col(|ui| {
                        ui.label(RichText::new("Banner").monospace().size(11.0).strong().color(Theme::TEXT_MAIN));
                        ui.painter().hline(ui.max_rect().x_range(), ui.max_rect().bottom(), Stroke::new(1.0_f32, Theme::BORDER));
                    });
                    header.col(|ui| {
                        ui.label(RichText::new("Time").monospace().size(11.0).strong().color(Theme::TEXT_MAIN));
                        ui.painter().hline(ui.max_rect().x_range(), ui.max_rect().bottom(), Stroke::new(1.0_f32, Theme::BORDER));
                    });
                })
                .body(|body| {
                    if total_rows == 0 {
                        body.rows(24.0, 1, |mut row| {
                            row.col(|ui| {
                                ui.label(RichText::new("No results").size(11.0).color(Theme::TEXT_MUTED));
                            });
                            row.col(|_| {});
                            row.col(|_| {});
                            row.col(|_| {});
                        });
                    } else {
                        body.rows(19.0, total_rows, |mut row| {
                            let row_idx = row.index();
                            if row_idx >= state.filtered_indices.len() {
                                return;
                            }
                            let hit_idx = state.filtered_indices[row_idx];
                            let hit = &state.results[hit_idx];

                            let ip_str = hit.ip.to_string();
                            let port_num = hit.port;
                            let banner_str = hit.banner.as_deref().unwrap_or("").to_string();
                            let time_str = hit.timestamp.format("%H:%M:%S").to_string();

                            // Subtle light horizontal line for row
                            let row_border = Stroke::new(1.0_f32, Color32::from_rgb(38, 38, 38));

                            // Col 1: IP (with context menu & double-click)
                            row.col(|ui| {
                                ui.painter().hline(ui.max_rect().x_range(), ui.max_rect().bottom(), row_border);

                                let resp = ui.add(
                                    egui::Label::new(
                                        RichText::new(&ip_str)
                                            .font(FontId::monospace(11.0))
                                            .color(Theme::HIT_TEXT),
                                    )
                                    .sense(Sense::click()),
                                );

                                if resp.double_clicked() {
                                    action_copy_ipport = Some(format!("{}:{}", ip_str, port_num));
                                }

                                resp.context_menu(|ui| {
                                    if ui.button("Copy").clicked() {
                                        action_copy_ip = Some(ip_str.clone());
                                        ui.close_menu();
                                    }
                                    if ui.button("Copy IP:port").clicked() {
                                        action_copy_ipport = Some(format!("{}:{}", ip_str, port_num));
                                        ui.close_menu();
                                    }
                                    if ui.button("Open").clicked() {
                                        let proto = if port_num == 443 || port_num == 8443 { "https" } else { "http" };
                                        action_open_url = Some(format!("{}://{}:{}/", proto, ip_str, port_num));
                                        ui.close_menu();
                                    }
                                    ui.separator();
                                    if ui.button("Clear").clicked() {
                                        action_clear = true;
                                        ui.close_menu();
                                    }
                                });
                            });

                            // Col 2: Port
                            row.col(|ui| {
                                ui.painter().hline(ui.max_rect().x_range(), ui.max_rect().bottom(), row_border);
                                ui.label(
                                    RichText::new(port_num.to_string())
                                        .font(FontId::monospace(11.0))
                                        .color(Theme::TEXT_MAIN),
                                );
                            });

                            // Col 3: Banner
                            row.col(|ui| {
                                ui.painter().hline(ui.max_rect().x_range(), ui.max_rect().bottom(), row_border);
                                ui.label(
                                    RichText::new(&banner_str)
                                        .font(FontId::monospace(11.0))
                                        .color(Theme::TEXT_MUTED),
                                );
                            });

                            // Col 4: Time
                            row.col(|ui| {
                                ui.painter().hline(ui.max_rect().x_range(), ui.max_rect().bottom(), row_border);
                                ui.label(
                                    RichText::new(&time_str)
                                        .font(FontId::monospace(11.0))
                                        .color(Theme::TEXT_MUTED),
                                );
                            });
                        });
                    }
                });

            // Handle actions from context menu or double clicks
            if let Some(text) = action_copy_ip {
                if let Ok(mut cb) = arboard::Clipboard::new() {
                    let _ = cb.set_text(&text);
                }
                state.append_log("INFO", format!("Copied IP '{}' to clipboard", text));
            }
            if let Some(text) = action_copy_ipport {
                if let Ok(mut cb) = arboard::Clipboard::new() {
                    let _ = cb.set_text(&text);
                }
                state.append_log("INFO", format!("Copied target '{}' to clipboard", text));
            }
            if let Some(url) = action_open_url {
                let _ = webbrowser::open(&url);
            }
            if action_clear {
                state.clear_results();
            }
        });
    }
}
