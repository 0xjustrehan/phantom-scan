use eframe::egui::{self, FontId, RichText, Ui};
use crate::gui::state::AppState;
use crate::gui::theme::Theme;

pub struct StatusBarView;

impl StatusBarView {
    pub fn render(ui: &mut Ui, state: &AppState) {
        ui.horizontal_centered(|ui| {
            let m = &state.metrics;

            let sent_str = format!("{}/{}", m.probes_sent, m.total_targets);
            let hits_str = m.hits_count.to_string();
            let kpps = (m.current_pps as f64) / 1000.0;
            let kpps_str = format!("{:.2}-kpps", kpps);

            let rtt_str = if m.average_rtt_ms > 0.0 {
                format!("{:.0}ms", m.average_rtt_ms)
            } else {
                "—".to_string()
            };

            let skip_str = (m.blacklist_skips + m.cooldown_skips).to_string();

            let eta_str = if let Some(secs) = m.eta_secs {
                let h = secs / 3600;
                let m = (secs % 3600) / 60;
                let s = secs % 60;
                if h > 0 {
                    format!("{:02}:{:02}:{:02}", h, m, s)
                } else {
                    format!("{:02}:{:02}", m, s)
                }
            } else {
                "—".to_string()
            };

            let status_line = format!(
                "SENT {}   HITS {}   {}   RTT {}   SKIP {}   ETA {}",
                sent_str, hits_str, kpps_str, rtt_str, skip_str, eta_str
            );

            ui.label(
                RichText::new(status_line)
                    .font(FontId::monospace(11.0))
                    .color(Theme::TEXT_MUTED),
            );
        });
    }
}
