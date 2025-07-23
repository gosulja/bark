use gpui::*;
use gpui_component::Root;
pub mod backend;

fn main() {
    Application::new().run(|cx: &mut App| {
        gpui_component::init(cx);

        let bounds = Bounds::centered(None, size(px(600.0), px(1000.0)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            |window, cx| {
                let app_view = cx.new(|cx| backend::app::BarkApp::new(window, cx));
                cx.new(|cx| Root::new(app_view.into(), window, cx))
            },
        )
        .unwrap();
    });
}
