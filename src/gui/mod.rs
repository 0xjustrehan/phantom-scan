/// Phantom Scan Native Tool GUI
///
/// Dense, flat dark gray native scanner interface inspired by KPort, NLBrute,
/// and Advanced Port Scanner. Built with eframe/egui into a single native binary.

pub mod config;
pub mod state;
pub mod theme;
pub mod views;

use eframe::egui::{self, CentralPanel, SidePanel, TopBottomPanel, Vec2};
use self::state::{AppState, ScanStatus};
use self::theme::Theme;
use self::views::{GeoModalView, LeftTargetsView, OptionsModalView, ResultsTableView, StatusBarView, ToolbarView};

pub struct PhantomScanApp {
    state: AppState,
}

impl PhantomScanApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Apply flat dark gray native utility theme
        Theme::apply(&cc.egui_ctx);

        Self {
            state: AppState::new(),
        }
    }
}

impl eframe::App for PhantomScanApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Hotkeys: F5=Start, Esc=Stop, Ctrl+S=Save, Ctrl+L=Clear, Ctrl+O=Load
        self.state.handle_hotkeys(ctx);

        // Poll incoming events from worker threads
        self.state.poll_updates();

        // 1. Top Toolbar (Single row, 28 px)
        TopBottomPanel::top("top_toolbar")
            .exact_height(28.0)
            .frame(
                egui::Frame::none()
                    .fill(Theme::BG_WINDOW)
                    .inner_margin(egui::Margin { left: 6.0, right: 6.0, top: 4.0, bottom: 3.0 })
                    .stroke(egui::Stroke::new(1.0_f32, Theme::BORDER)),
            )
            .show(ctx, |ui| {
                ToolbarView::render(ui, &mut self.state);
            });

        // 2. Bottom Status (20 px, exact single line)
        TopBottomPanel::bottom("bottom_status")
            .exact_height(20.0)
            .frame(
                egui::Frame::none()
                    .fill(Theme::BG_WINDOW)
                    .inner_margin(egui::Margin { left: 6.0, right: 6.0, top: 3.0, bottom: 2.0 })
                    .stroke(egui::Stroke::new(1.0_f32, Theme::BORDER)),
            )
            .show(ctx, |ui| {
                StatusBarView::render(ui, &self.state);
            });

        // 3. Left Panel (Fixed ~168–172 px content width, single 1px separator)
        SidePanel::left("left_targets")
            .exact_width(180.0)
            .resizable(false)
            .frame(
                egui::Frame::none()
                    .fill(Theme::BG_PANEL)
                    .inner_margin(egui::Margin { left: 6.0, right: 6.0, top: 4.0, bottom: 4.0 })
                    .stroke(egui::Stroke::new(1.0_f32, Theme::BORDER)),
            )
            .show(ctx, |ui| {
                LeftTargetsView::render(ui, &mut self.state);
            });

        // 4. Center Area (Results Table + Filter Box directly above table, shared margins)
        CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(Theme::BG_WINDOW)
                    .inner_margin(egui::Margin { left: 6.0, right: 6.0, top: 4.0, bottom: 4.0 }),
            )
            .show(ctx, |ui| {
                ResultsTableView::render(ui, &mut self.state);
            });

        // 5. Options Modal (Secondary CLI flags behind "Options..." button)
        OptionsModalView::render(ctx, &mut self.state);

        // 6. BGP Geo-IP Routing Downloader Modal
        GeoModalView::render(ctx, &mut self.state);

        // Repaint when actively scanning to update live counters & table
        if self.state.status == ScanStatus::Scanning || self.state.status == ScanStatus::Draining {
            ctx.request_repaint();
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.state.config.save_to_disk();
    }
}

/// Launch the desktop GUI with dual-engine fallback (WGPU/DirectX + Glow/OpenGL)
pub fn run_gui() -> Result<(), eframe::Error> {
    #[cfg(windows)]
    {
        // On Windows: Primary renderer is WGPU (DirectX 12 / Direct3D 11 with built-in WARP software fallback)
        // Works on all Windows editions (Windows Server, VMs, RDP sessions, and consumer Windows)
        let wgpu_options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title("Phantom Scan")
                .with_inner_size(Vec2::new(780.0, 480.0))
                .with_min_inner_size(Vec2::new(600.0, 360.0))
                .with_maximized(false)
                .with_decorations(true),
            renderer: eframe::Renderer::Wgpu,
            ..Default::default()
        };

        match eframe::run_native(
            "Phantom Scan",
            wgpu_options,
            Box::new(|cc| Ok(Box::new(PhantomScanApp::new(cc)))),
        ) {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("[!] WGPU/DirectX initialization failed ({}). Attempting OpenGL fallback...", e);
            }
        }
    }

    // Secondary / Linux renderer: Glow (OpenGL / EGL)
    let glow_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Phantom Scan")
            .with_inner_size(Vec2::new(780.0, 480.0))
            .with_min_inner_size(Vec2::new(600.0, 360.0))
            .with_maximized(false)
            .with_decorations(true),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    eframe::run_native(
        "Phantom Scan",
        glow_options,
        Box::new(|cc| Ok(Box::new(PhantomScanApp::new(cc)))),
    )
}
