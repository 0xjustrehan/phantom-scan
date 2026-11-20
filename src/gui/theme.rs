use eframe::egui::{self, Color32, Margin, Rounding, Stroke, Vec2, Visuals};

/// Native tool theme: flat dark gray, 0px rounding, 1px borders.
/// Modeled after classic utilities (KPort, NLBrute, Angry IP Scanner).
pub struct Theme;

impl Theme {
    // Window & background colors
    pub const BG_WINDOW: Color32 = Color32::from_rgb(43, 43, 43);       // #2b2b2b Main window & toolbar
    pub const BG_PANEL: Color32 = Color32::from_rgb(38, 38, 38);        // #262626 Left panel & options
    pub const BG_LIST: Color32 = Color32::from_rgb(30, 30, 30);         // #1e1e1e Results list & inputs
    pub const BG_ROW_ALT: Color32 = Color32::from_rgb(34, 34, 34);      // #222222 Alternating list row
    pub const BG_CONTROL: Color32 = Color32::from_rgb(60, 60, 60);      // #3c3c3c Standard controls / buttons

    // Borders & strokes
    pub const BORDER: Color32 = Color32::from_rgb(68, 68, 68);          // #444444 1px border
    pub const BORDER_FOCUS: Color32 = Color32::from_rgb(90, 90, 90);    // #5a5a5a Focused border
    pub const SEPARATOR: Color32 = Color32::from_rgb(55, 55, 55);       // #373737 Separator line

    // Text colors
    pub const TEXT_MAIN: Color32 = Color32::from_rgb(220, 220, 220);    // #dcdcdc Primary light gray text
    pub const TEXT_MUTED: Color32 = Color32::from_rgb(140, 140, 140);   // #8c8c8c Muted secondary labels
    pub const TEXT_DISABLED: Color32 = Color32::from_rgb(95, 95, 95);   // #5f5f5f Disabled text

    // Hits in list
    pub const HIT_TEXT: Color32 = Color32::from_rgb(112, 204, 112);     // #70cc70 Slight green for open ports
    pub const HIT_ROW_BG: Color32 = Color32::from_rgba_premultiplied(30, 50, 30, 30); // Very subtle tint

    // Functional status indicators & action buttons
    pub const STATUS_STOP: Color32 = Color32::from_rgb(200, 70, 70);
    pub const STATUS_WARN: Color32 = Color32::from_rgb(210, 180, 50);

    // High-contrast filled action buttons for Start / Stop
    pub const BTN_START_FILL: Color32 = Color32::from_rgb(32, 78, 40);
    pub const BTN_STOP_FILL: Color32 = Color32::from_rgb(110, 36, 36);

    pub fn apply(ctx: &egui::Context) {
        let mut visuals = Visuals::dark();
        visuals.dark_mode = true;
        visuals.override_text_color = Some(Self::TEXT_MAIN);

        visuals.panel_fill = Self::BG_WINDOW;
        visuals.window_fill = Self::BG_PANEL;
        visuals.window_stroke = Stroke::new(1.0_f32, Self::BORDER);
        visuals.window_rounding = Rounding::ZERO;

        visuals.extreme_bg_color = Self::BG_LIST;
        visuals.faint_bg_color = Self::BG_ROW_ALT;

        // Non-interactive widgets
        visuals.widgets.noninteractive.bg_fill = Self::BG_WINDOW;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, Self::BORDER);
        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, Self::TEXT_MUTED);
        visuals.widgets.noninteractive.rounding = Rounding::ZERO;

        // Inactive controls
        visuals.widgets.inactive.bg_fill = Self::BG_CONTROL;
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, Self::BORDER);
        visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, Self::TEXT_MAIN);
        visuals.widgets.inactive.rounding = Rounding::ZERO;

        // Hovered controls
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(72, 72, 72);
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, Self::BORDER_FOCUS);
        visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
        visuals.widgets.hovered.rounding = Rounding::ZERO;

        // Active/clicked controls
        visuals.widgets.active.bg_fill = Color32::from_rgb(50, 50, 50);
        visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, Self::BORDER_FOCUS);
        visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, Color32::WHITE);
        visuals.widgets.active.rounding = Rounding::ZERO;

        // Open popups/comboboxes
        visuals.widgets.open.bg_fill = Self::BG_PANEL;
        visuals.widgets.open.bg_stroke = Stroke::new(1.0_f32, Self::BORDER_FOCUS);

        // Selection
        visuals.selection.bg_fill = Color32::from_rgba_premultiplied(70, 90, 120, 100);
        visuals.selection.stroke = Stroke::new(1.0_f32, Color32::from_rgb(90, 120, 170));

        ctx.set_visuals(visuals);

        // Compact native layout metrics
        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = Vec2::new(4.0, 3.0);
        style.spacing.window_margin = Margin::same(4.0);
        style.spacing.button_padding = Vec2::new(5.0, 2.0);
        style.spacing.indent = 8.0;

        // Thin standard scrollbars
        style.spacing.scroll.bar_width = 8.0;
        style.spacing.scroll.handle_min_length = 16.0;
        style.spacing.scroll.bar_inner_margin = 0.0;
        style.spacing.scroll.bar_outer_margin = 0.0;

        ctx.set_style(style);
    }
}
