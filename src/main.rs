use gpui::*;
pub mod backend;

fn main() {
    Application::new().run(|cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(800.0), px(800.0)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            |w, cx| cx.new(|cx| backend::app::BarkApp::new(w, cx)),
        )
        .unwrap();
    });
}
