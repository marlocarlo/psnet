//! High-resolution world map using braille characters (U+2800–U+28FF).
//!
//! Each braille cell encodes a 2x4 dot pattern, giving 2x the horizontal
//! and 4x the vertical resolution of normal characters. The map is stored
//! as a set of (x, y) coastline points in a normalized coordinate system
//! and rendered at whatever terminal size is available.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

// ── Color palette ──────────────────────────────────────────────────────────

const CLR_OCEAN: Color = Color::Rgb(8, 12, 24);
const CLR_BORDER: Color = Color::Rgb(30, 50, 85);
const CLR_LAND: Color = Color::Rgb(30, 55, 85);
const CLR_NORMAL: Color = Color::Rgb(80, 200, 120);
const CLR_MODERATE: Color = Color::Rgb(255, 200, 80);
const CLR_HIGH: Color = Color::Rgb(255, 130, 60);
const CLR_THREAT: Color = Color::Rgb(255, 60, 60);

// ── Public types ──────────────────────────────────────────────────────────

pub struct CountryMarker {
    pub code: &'static str,
    pub name: &'static str,
    pub count: usize,
    pub has_threat: bool,
}

// ── Country coordinates (longitude, latitude) ─────────────────────────────
// Approximate geographic centers used for marker placement.

const COUNTRY_COORDS: &[(&str, f64, f64)] = &[
    ("US", -98.0, 38.0),
    ("CA", -106.0, 56.0),
    ("MX", -102.0, 23.0),
    ("BR", -51.0, -14.0),
    ("AR", -64.0, -34.0),
    ("CO", -74.0, 4.0),
    ("CL", -71.0, -35.0),
    ("GB", -3.0, 54.0),
    ("IE", -8.0, 53.0),
    ("FR", 2.0, 46.0),
    ("ES", -4.0, 40.0),
    ("PT", -8.0, 39.0),
    ("DE", 10.0, 51.0),
    ("NL", 5.0, 52.0),
    ("BE", 4.0, 51.0),
    ("IT", 12.0, 43.0),
    ("CH", 8.0, 47.0),
    ("AT", 14.0, 48.0),
    ("PL", 20.0, 52.0),
    ("CZ", 15.0, 50.0),
    ("SE", 18.0, 62.0),
    ("NO", 10.0, 62.0),
    ("FI", 26.0, 64.0),
    ("DK", 10.0, 56.0),
    ("UA", 32.0, 49.0),
    ("RO", 25.0, 46.0),
    ("HU", 20.0, 47.0),
    ("BG", 25.0, 43.0),
    ("GR", 22.0, 39.0),
    ("TR", 35.0, 39.0),
    ("RU", 100.0, 60.0),
    ("IL", 35.0, 31.0),
    ("AE", 54.0, 24.0),
    ("SA", 45.0, 24.0),
    ("IN", 79.0, 21.0),
    ("PK", 69.0, 30.0),
    ("BD", 90.0, 24.0),
    ("CN", 105.0, 35.0),
    ("JP", 138.0, 36.0),
    ("KR", 128.0, 36.0),
    ("HK", 114.0, 22.0),
    ("TW", 121.0, 24.0),
    ("SG", 104.0, 1.0),
    ("VN", 108.0, 16.0),
    ("TH", 101.0, 15.0),
    ("MY", 102.0, 4.0),
    ("ID", 120.0, -5.0),
    ("PH", 122.0, 13.0),
    ("ZA", 25.0, -29.0),
    ("NG", 8.0, 10.0),
    ("KE", 38.0, -1.0),
    ("EG", 30.0, 27.0),
    ("AU", 134.0, -25.0),
    ("NZ", 174.0, -41.0),
];

// ── Simplified world coastline points ─────────────────────────────────────
// (longitude, latitude) pairs tracing major landmass outlines.
// Each sub-array is a separate polyline. Points are connected within
// each polyline to form coastlines.

fn world_coastlines() -> Vec<Vec<(f64, f64)>> {
    vec![
        // North America
        vec![
            (-168.0,72.0),(-162.0,70.0),(-156.0,71.0),(-148.0,70.0),(-141.0,69.5),
            (-141.0,60.0),(-138.0,59.0),(-136.0,58.5),(-134.0,56.0),(-130.0,54.0),
            (-127.0,50.0),(-124.0,48.0),(-123.0,46.0),(-122.0,42.0),(-118.0,34.0),
            (-117.0,32.5),(-110.0,30.0),(-105.0,28.0),(-100.0,26.0),(-97.0,26.0),
            (-95.0,29.0),(-90.0,29.5),(-85.0,30.0),(-82.0,25.0),(-80.0,25.5),
            (-81.0,31.0),(-77.0,35.0),(-75.0,38.0),(-74.0,41.0),(-71.0,42.0),
            (-70.0,43.5),(-67.0,45.0),(-66.0,44.5),(-64.0,47.0),(-61.0,46.0),
            (-60.0,47.0),(-64.0,49.0),(-66.0,49.0),(-71.0,47.0),(-75.0,46.0),
            (-79.0,43.5),(-83.0,42.0),(-87.0,43.0),(-88.0,44.0),(-87.0,45.0),
            (-84.0,46.0),(-82.0,46.0),(-80.0,48.0),(-86.0,49.0),(-95.0,49.0),
            (-95.0,52.0),(-90.0,53.0),(-85.0,55.0),(-82.0,56.0),(-80.0,58.0),
            (-78.0,60.0),(-77.0,63.0),(-80.0,67.0),(-85.0,69.0),(-90.0,70.0),
            (-100.0,72.0),(-110.0,74.0),(-120.0,74.0),(-130.0,72.0),(-140.0,70.0),
        ],
        // Central America
        vec![
            (-100.0,20.0),(-96.0,18.0),(-92.0,15.0),(-88.0,14.0),(-85.0,11.0),
            (-83.0,10.0),(-80.0,9.0),(-77.0,8.0),
        ],
        // South America
        vec![
            (-77.0,8.0),(-73.0,11.0),(-71.0,12.0),(-67.0,11.0),(-63.0,10.0),
            (-60.0,8.0),(-55.0,5.0),(-51.0,4.0),(-50.0,2.0),(-48.0,0.0),
            (-45.0,-3.0),(-42.0,-3.0),(-38.0,-5.0),(-35.0,-8.0),(-35.0,-12.0),
            (-38.0,-15.0),(-39.0,-18.0),(-40.0,-22.0),(-43.0,-23.0),(-46.0,-24.0),
            (-48.0,-27.0),(-50.0,-29.0),(-52.0,-33.0),(-56.0,-35.0),(-58.0,-38.0),
            (-62.0,-39.0),(-65.0,-42.0),(-66.0,-45.0),(-68.0,-48.0),(-70.0,-50.0),
            (-73.0,-53.0),(-75.0,-52.0),(-74.0,-48.0),(-72.0,-45.0),(-71.0,-40.0),
            (-72.0,-35.0),(-71.0,-30.0),(-70.0,-25.0),(-70.0,-18.0),(-75.0,-15.0),
            (-76.0,-12.0),(-78.0,-8.0),(-80.0,-3.0),(-80.0,0.0),(-78.0,3.0),
            (-77.0,8.0),
        ],
        // Europe
        vec![
            (-10.0,36.0),(-8.0,37.0),(-9.0,39.0),(-8.0,42.0),(-4.0,43.5),
            (-2.0,44.0),(0.0,43.0),(3.0,43.0),(5.0,43.5),(7.0,44.0),
            (10.0,44.0),(13.0,45.5),(14.0,45.0),(17.0,43.0),(19.0,42.0),
            (20.0,40.0),(24.0,38.0),(26.0,38.0),(28.0,41.0),(26.0,42.0),
            (28.0,44.0),(30.0,46.0),(32.0,46.5),(34.0,45.0),(37.0,47.0),
            (40.0,47.0),(40.0,55.0),(35.0,57.0),(30.0,60.0),(25.0,60.5),
            (25.0,65.0),(28.0,69.0),(30.0,70.0),(20.0,70.0),(15.0,69.0),
            (14.0,65.0),(12.0,63.0),(8.0,58.0),(7.0,57.5),(8.0,55.0),
            (10.0,54.5),(14.0,54.0),(18.0,55.0),(20.0,55.0),(22.0,56.0),
            (24.0,57.0),(24.0,58.0),(22.0,59.0),(20.0,59.5),(18.0,60.0),
            (16.0,57.0),(13.0,55.5),(12.0,56.0),(9.0,55.0),(8.0,54.0),
        ],
        // British Isles
        vec![
            (-6.0,50.0),(-5.0,51.0),(-3.0,51.0),(0.0,51.0),(2.0,53.0),
            (0.0,53.5),(-1.0,55.0),(-2.0,57.0),(-5.0,58.0),(-6.0,57.0),
            (-5.0,55.0),(-3.0,54.0),(-4.0,53.0),(-5.0,52.0),(-6.0,50.0),
        ],
        // Ireland
        vec![
            (-10.0,52.0),(-9.0,54.0),(-8.0,55.0),(-6.0,55.0),(-6.0,52.5),
            (-8.0,51.5),(-10.0,52.0),
        ],
        // Africa
        vec![
            (-17.0,14.5),(-16.0,12.0),(-12.0,8.0),(-8.0,5.0),(-5.0,5.0),
            (2.0,6.0),(8.0,4.5),(10.0,4.0),(10.0,2.0),(9.5,1.0),(10.0,0.0),
            (12.0,-5.0),(14.0,-8.0),(17.0,-12.0),(16.0,-18.0),(13.0,-23.0),
            (15.0,-27.0),(18.0,-34.0),(20.0,-34.5),(26.0,-34.0),(28.0,-32.0),
            (32.0,-29.0),(35.0,-24.0),(40.0,-15.0),(42.0,-12.0),(44.0,-12.0),
            (50.0,-16.0),(48.0,-10.0),(42.0,-2.0),(44.0,2.0),(48.0,8.0),
            (50.0,12.0),(44.0,12.0),(43.0,16.0),(38.0,18.0),(33.0,22.0),
            (32.0,30.0),(30.0,31.0),(25.0,32.0),(20.0,33.0),(10.0,37.0),
            (5.0,37.0),(0.0,36.0),(-5.0,36.0),(-6.0,35.0),(-2.0,35.5),
            (-1.0,35.0),(-5.0,34.0),(-8.0,33.0),(-13.0,28.0),(-17.0,21.0),
            (-16.0,18.0),(-17.0,14.5),
        ],
        // Asia (mainland)
        vec![
            (26.0,42.0),(30.0,42.0),(33.0,42.0),(36.0,37.0),(36.0,34.0),
            (35.5,32.0),(34.0,29.0),(33.0,28.0),(34.0,27.0),(36.0,26.0),
            (40.0,22.0),(43.0,16.0),(45.0,13.0),(48.0,14.0),(52.0,17.0),
            (56.0,20.0),(57.0,25.0),(56.0,27.0),(52.0,25.0),(50.0,26.0),
            (48.0,30.0),(48.0,31.0),(50.0,37.0),(52.0,37.0),(54.0,38.0),
            (58.0,38.0),(60.0,36.0),(62.0,35.0),(66.0,25.0),(68.0,24.0),
            (72.0,21.0),(73.0,16.0),(76.0,10.0),(78.0,8.0),(80.0,7.0),
            (80.0,10.0),(85.0,16.0),(87.0,22.0),(89.0,22.0),(92.0,21.0),
            (95.0,16.0),(98.0,10.0),(99.0,7.0),(100.0,3.0),(104.0,1.0),
            (104.0,3.0),(106.0,10.0),(109.0,12.0),(109.0,15.0),(108.0,18.0),
            (107.0,21.0),(110.0,22.0),(117.0,24.0),(120.0,26.0),(121.0,28.0),
            (122.0,30.0),(120.0,34.0),(118.0,36.0),(120.0,37.0),(122.0,37.0),
            (121.0,40.0),(118.0,40.0),(117.0,41.0),(120.0,42.0),(124.0,40.0),
            (126.0,38.0),(128.0,37.0),(130.0,43.0),(132.0,43.5),(135.0,48.0),
            (138.0,48.0),(140.0,52.0),(137.0,54.0),(135.0,55.0),(130.0,56.0),
            (128.0,58.0),(135.0,60.0),(140.0,62.0),(150.0,60.0),(160.0,62.0),
            (170.0,63.0),(180.0,65.0),
        ],
        // Japan
        vec![
            (130.0,31.0),(131.0,33.0),(133.0,34.0),(135.0,34.5),(137.0,35.0),
            (140.0,36.0),(141.0,38.0),(140.0,40.0),(140.0,42.0),(142.0,43.0),
            (145.0,44.0),(145.0,43.0),(143.0,42.0),(141.0,40.0),
        ],
        // Australia
        vec![
            (114.0,-22.0),(115.0,-20.0),(119.0,-17.0),(123.0,-16.0),(127.0,-14.0),
            (130.0,-12.0),(132.0,-12.0),(136.0,-12.0),(137.0,-16.0),(139.0,-17.0),
            (142.0,-11.0),(143.0,-14.0),(145.0,-15.0),(146.0,-19.0),(148.0,-20.0),
            (150.0,-24.0),(153.0,-28.0),(153.0,-31.0),(151.0,-34.0),(148.0,-37.0),
            (145.0,-38.5),(141.0,-38.0),(138.0,-35.5),(136.0,-35.0),(134.0,-33.0),
            (130.0,-32.0),(125.0,-34.0),(120.0,-34.0),(116.0,-34.0),(115.0,-32.0),
            (113.0,-26.0),(114.0,-22.0),
        ],
        // New Zealand
        vec![
            (173.0,-41.0),(175.0,-41.5),(177.0,-40.0),(178.0,-38.0),(176.0,-37.0),
            (174.0,-36.0),(173.0,-38.0),(173.0,-41.0),
        ],
        // NZ South Island
        vec![
            (167.0,-46.0),(168.0,-44.0),(171.0,-44.0),(173.0,-43.0),(174.0,-42.0),
            (174.0,-41.5),(172.0,-41.0),(170.0,-43.0),(168.0,-45.0),(167.0,-46.0),
        ],
        // Greenland
        vec![
            (-45.0,60.0),(-44.0,62.0),(-42.0,65.0),(-38.0,68.0),(-30.0,72.0),
            (-22.0,75.0),(-18.0,77.0),(-20.0,80.0),(-30.0,82.0),(-42.0,83.0),
            (-55.0,82.0),(-60.0,79.0),(-58.0,76.0),(-52.0,72.0),(-48.0,68.0),
            (-46.0,65.0),(-43.0,62.0),(-45.0,60.0),
        ],
        // Iceland
        vec![
            (-22.0,64.0),(-18.0,65.0),(-14.0,66.0),(-14.0,65.0),(-18.0,63.5),
            (-22.0,64.0),
        ],
        // Sri Lanka
        vec![
            (80.0,10.0),(82.0,8.0),(81.0,6.5),(80.0,7.0),(80.0,10.0),
        ],
        // Taiwan
        vec![
            (121.0,22.0),(121.5,24.0),(122.0,25.0),(121.0,25.5),(120.0,23.0),(121.0,22.0),
        ],
        // Madagascar
        vec![
            (44.0,-13.0),(48.0,-14.0),(50.0,-16.0),(50.0,-22.0),(47.0,-25.0),
            (44.0,-24.0),(44.0,-19.0),(44.0,-13.0),
        ],
        // Russia (northern coast continuation)
        vec![
            (40.0,68.0),(50.0,70.0),(60.0,72.0),(70.0,73.0),(80.0,73.0),
            (90.0,75.0),(100.0,76.0),(110.0,74.0),(120.0,73.0),(130.0,72.0),
            (140.0,71.0),(155.0,69.0),(165.0,67.0),(170.0,65.0),(180.0,65.0),
        ],
    ]
}

// ── Mercator projection ───────────────────────────────────────────────────

/// Convert (longitude, latitude) to normalized (x, y) in [0,1].
fn mercator(lon: f64, lat: f64) -> (f64, f64) {
    let x = (lon + 180.0) / 360.0;
    let lat_rad = lat.to_radians();
    let merc_y = (((std::f64::consts::PI / 4.0) + (lat_rad / 2.0)).tan()).ln();
    let y = 0.5 - merc_y / (2.0 * std::f64::consts::PI);
    (x, y)
}

// ── Braille rendering ─────────────────────────────────────────────────────

/// Braille dot positions within a cell (col 0-1, row 0-3):
/// Col 0: bits 0,1,2,6  Col 1: bits 3,4,5,7
const BRAILLE_BASE: u32 = 0x2800;

fn dot_mask(cx: usize, cy: usize) -> u8 {
    match (cx, cy) {
        (0, 0) => 0x01,
        (0, 1) => 0x02,
        (0, 2) => 0x04,
        (1, 0) => 0x08,
        (1, 1) => 0x10,
        (1, 2) => 0x20,
        (0, 3) => 0x40,
        (1, 3) => 0x80,
        _ => 0,
    }
}

struct BrailleCanvas {
    /// Grid of braille dot bitmasks. Indexed [row][col].
    cells: Vec<Vec<u8>>,
    /// Color layer: each cell has an optional foreground override.
    colors: Vec<Vec<Option<Color>>>,
    /// Width in terminal columns (each = 2 dots wide).
    cols: usize,
    /// Height in terminal rows (each = 4 dots tall).
    rows: usize,
}

impl BrailleCanvas {
    fn new(cols: usize, rows: usize) -> Self {
        Self {
            cells: vec![vec![0u8; cols]; rows],
            colors: vec![vec![None; cols]; rows],
            cols,
            rows,
        }
    }

    /// Set a single dot at pixel coordinates (px, py).
    /// px range: 0..cols*2, py range: 0..rows*4.
    fn set(&mut self, px: usize, py: usize, color: Color) {
        let cell_col = px / 2;
        let cell_row = py / 4;
        if cell_col >= self.cols || cell_row >= self.rows {
            return;
        }
        let cx = px % 2;
        let cy = py % 4;
        self.cells[cell_row][cell_col] |= dot_mask(cx, cy);
        self.colors[cell_row][cell_col] = Some(color);
    }

    /// Draw a line between two pixel points using Bresenham's algorithm.
    fn line(&mut self, x0: i32, y0: i32, x1: i32, y1: i32, color: Color) {
        let mut x = x0;
        let mut y = y0;
        let dx = (x1 - x0).abs();
        let dy = -(y1 - y0).abs();
        let sx = if x0 < x1 { 1 } else { -1 };
        let sy = if y0 < y1 { 1 } else { -1 };
        let mut err = dx + dy;

        loop {
            if x >= 0 && y >= 0 {
                self.set(x as usize, y as usize, color);
            }
            if x == x1 && y == y1 {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x += sx;
            }
            if e2 <= dx {
                err += dx;
                y += sy;
            }
        }
    }

    /// Draw a filled circle at pixel coordinates.
    fn filled_circle(&mut self, cx: i32, cy: i32, r: i32, color: Color) {
        for dy in -r..=r {
            for dx in -r..=r {
                if dx * dx + dy * dy <= r * r {
                    let px = cx + dx;
                    let py = cy + dy;
                    if px >= 0 && py >= 0 {
                        self.set(px as usize, py as usize, color);
                    }
                }
            }
        }
    }

    /// Render to styled Lines for ratatui.
    fn render(&self) -> Vec<Line<'static>> {
        let mut lines = Vec::with_capacity(self.rows);
        for row in 0..self.rows {
            let mut spans: Vec<Span<'static>> = Vec::with_capacity(self.cols);
            for col in 0..self.cols {
                let bits = self.cells[row][col];
                let ch = char::from_u32(BRAILLE_BASE + bits as u32).unwrap_or(' ');
                let fg = if bits == 0 {
                    CLR_OCEAN
                } else {
                    self.colors[row][col].unwrap_or(CLR_LAND)
                };
                spans.push(Span::styled(
                    ch.to_string(),
                    Style::default().fg(fg).bg(CLR_OCEAN),
                ));
            }
            lines.push(Line::from(spans));
        }
        lines
    }
}

// ── Marker color logic ────────────────────────────────────────────────────

fn marker_color(count: usize, has_threat: bool) -> Color {
    if has_threat {
        CLR_THREAT
    } else if count > 20 {
        CLR_HIGH
    } else if count >= 6 {
        CLR_MODERATE
    } else {
        CLR_NORMAL
    }
}

// ── Main draw function ───────────────────────────────────────────────────

pub fn draw_world_map(f: &mut Frame, area: Rect, countries: &[CountryMarker]) {
    if area.width < 6 || area.height < 5 {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(CLR_BORDER))
            .style(Style::default().bg(CLR_OCEAN));
        f.render_widget(block, area);
        return;
    }

    // Inner dimensions (accounting for border + legend row)
    let inner_w = (area.width - 2) as usize;
    let legend_rows = 1usize;
    let inner_h = (area.height - 2) as usize;
    let map_h = inner_h.saturating_sub(legend_rows);

    if inner_w < 4 || map_h < 2 {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(CLR_BORDER))
            .style(Style::default().bg(CLR_OCEAN));
        f.render_widget(block, area);
        return;
    }

    // Braille resolution: each cell = 2 dots wide, 4 dots tall
    let dot_w = inner_w * 2;
    let dot_h = map_h * 4;

    let mut canvas = BrailleCanvas::new(inner_w, map_h);

    // Determine visible map bounds (Mercator projection)
    // Clip latitude to ~-60..80 for reasonable Mercator
    let (_, y_top) = mercator(0.0, 78.0);
    let (_, y_bot) = mercator(0.0, -58.0);

    let coastlines = world_coastlines();

    // Draw coastlines
    for polyline in &coastlines {
        for i in 1..polyline.len() {
            let (lon0, lat0) = polyline[i - 1];
            let (lon1, lat1) = polyline[i];

            let (mx0, my0) = mercator(lon0, lat0);
            let (mx1, my1) = mercator(lon1, lat1);

            // Skip lines that wrap around the date line
            if (mx1 - mx0).abs() > 0.4 {
                continue;
            }

            let px0 = (mx0 * dot_w as f64) as i32;
            let py0 = (((my0 - y_top) / (y_bot - y_top)) * dot_h as f64) as i32;
            let px1 = (mx1 * dot_w as f64) as i32;
            let py1 = (((my1 - y_top) / (y_bot - y_top)) * dot_h as f64) as i32;

            canvas.line(px0, py0, px1, py1, CLR_LAND);
        }
    }

    // Draw country markers
    for cm in countries {
        if let Some(&(_, lon, lat)) = COUNTRY_COORDS.iter().find(|(c, _, _)| *c == cm.code) {
            let (mx, my) = mercator(lon, lat);
            let px = (mx * dot_w as f64) as i32;
            let py = (((my - y_top) / (y_bot - y_top)) * dot_h as f64) as i32;
            let color = marker_color(cm.count, cm.has_threat);
            let r = if cm.count > 10 { 3 } else { 2 };
            canvas.filled_circle(px, py, r, color);
        }
    }

    // Render braille to lines
    let mut lines = canvas.render();

    // Legend row
    let legend = Line::from(vec![
        Span::styled(" \u{25CF}", Style::default().fg(CLR_NORMAL).bg(CLR_OCEAN)),
        Span::styled(" Low ", Style::default().fg(Color::Rgb(100, 120, 150)).bg(CLR_OCEAN)),
        Span::styled("\u{25CF}", Style::default().fg(CLR_MODERATE).bg(CLR_OCEAN)),
        Span::styled(" Med ", Style::default().fg(Color::Rgb(100, 120, 150)).bg(CLR_OCEAN)),
        Span::styled("\u{25CF}", Style::default().fg(CLR_HIGH).bg(CLR_OCEAN)),
        Span::styled(" High ", Style::default().fg(Color::Rgb(100, 120, 150)).bg(CLR_OCEAN)),
        Span::styled("\u{25CF}", Style::default().fg(CLR_THREAT).bg(CLR_OCEAN)),
        Span::styled(" Threat", Style::default().fg(Color::Rgb(100, 120, 150)).bg(CLR_OCEAN)),
    ]);
    lines.push(legend);

    // Title
    let active = countries.len();
    let threat_count = countries.iter().filter(|c| c.has_threat).count();

    let mut title_spans = vec![
        Span::styled(
            " Connection Map ",
            Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} countries ", active),
            Style::default().fg(Color::Rgb(100, 120, 150)),
        ),
    ];
    if threat_count > 0 {
        title_spans.push(Span::styled(
            format!(" {} threats ", threat_count),
            Style::default().fg(CLR_THREAT).add_modifier(Modifier::BOLD),
        ));
    }

    let block = Block::default()
        .title(Line::from(title_spans))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CLR_BORDER))
        .style(Style::default().bg(CLR_OCEAN));

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}
