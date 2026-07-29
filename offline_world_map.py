import tkinter as tk

class OfflineWorldMap(tk.Canvas):
    """A simplified, fully offline world map with a single active marker."""

    _CONTINENTS = {
        "north_america": [
            (71, -156), (70, -141), (69, -125), (60, -141), (55, -130), (48, -125),
            (40, -124), (32, -117), (23, -109), (20, -105), (15, -92), (18, -88),
            (21, -87), (25, -97), (29, -95), (30, -89), (25, -80), (30, -81),
            (35, -76), (40, -74), (44, -67), (47, -52), (52, -56), (58, -63),
            (60, -65), (63, -68), (68, -81), (70, -95), (72, -110), (71, -156),
        ],
        "south_america": [
            (12, -72), (11, -74), (8, -77), (1, -78), (-4, -81), (-14, -76),
            (-18, -70), (-23, -70), (-33, -71), (-42, -73), (-52, -74), (-55, -68),
            (-52, -68), (-45, -65), (-38, -58), (-34, -58), (-33, -53), (-23, -43),
            (-13, -38), (-5, -35), (0, -50), (4, -52), (8, -60), (10, -62), (12, -72),
        ],
        "africa": [
            (37, 10), (33, 10), (31, 25), (22, 37), (12, 43), (11, 51), (0, 42),
            (-4, 39), (-15, 40), (-26, 33), (-34, 20), (-34, 19), (-29, 17),
            (-22, 14), (-17, 12), (-13, 13), (-6, 12), (4, 9), (6, 3), (4, 8),
            (6, -6), (10, -16), (15, -17), (21, -17), (28, -13), (31, -9),
            (35, -6), (37, 10),
        ],
        "europe": [
            (71, 25), (69, 29), (66, 34), (60, 30), (59, 28), (54, 20), (54, 14),
            (58, 11), (55, 8), (53, 7), (51, 3), (49, -1), (43, -2), (38, -9),
            (36, -6), (37, -5), (36, 3), (38, 15), (40, 18), (40, 20), (37, 23),
            (35, 25), (40, 26), (41, 29), (45, 29), (46, 31), (44, 34), (45, 36),
            (47, 38), (52, 40), (58, 40), (63, 35), (66, 33), (71, 25),
        ],
        "asia": [
            (77, 68), (73, 60), (70, 58), (66, 68), (68, 80), (73, 90), (76, 105),
            (77, 130), (70, 140), (65, 170), (60, 163), (55, 158), (52, 140),
            (46, 140), (43, 132), (38, 128), (35, 127), (31, 121), (23, 117),
            (20, 110), (10, 105), (8, 99), (1, 104), (2, 102), (6, 100), (13, 100),
            (16, 97), (20, 93), (21, 89), (20, 87), (17, 83), (13, 80), (9, 79),
            (8, 77), (11, 75), (15, 73), (21, 70), (25, 67), (24, 62), (26, 57),
            (30, 49), (29, 48), (27, 50), (25, 56), (24, 58), (26, 63), (36, 53),
            (37, 49), (41, 48), (43, 47), (45, 37), (41, 29), (45, 29), (47, 38),
            (52, 40), (58, 40), (63, 35), (66, 33), (71, 25), (77, 68),
        ],
        "australia": [
            (-11, 131), (-12, 136), (-15, 140), (-17, 141), (-19, 146), (-24, 153),
            (-29, 153), (-34, 151), (-38, 146), (-38, 140), (-35, 136), (-33, 134),
            (-31, 131), (-27, 113), (-21, 114), (-18, 122), (-14, 126), (-11, 131),
        ],
    }

    def __init__(self, master, bg_color="#0d1b2a", land_color="#1e3a2f",
                 land_outline="#2d5a45", grid_color="#16283d",
                 marker_color="#ff5252", marker_text_color="#ffffff",
                 width=400, height=320, **kwargs):
        super().__init__(master, width=width, height=height,
                         bg=bg_color, highlightthickness=0, **kwargs)

        self._land_color = land_color
        self._land_outline = land_outline
        self._grid_color = grid_color
        self._marker_color = marker_color
        self._marker_text_color = marker_text_color

        self._marker_ids = []       
        self._current_marker = None  

        self.bind("<Configure>", self._on_resize)
        self._draw()

    def set_position(self, lat, lon):
        self._draw()

    def set_zoom(self, level):
        pass

    def set_marker(self, lat, lon, text=""):
        self._current_marker = (lat, lon, text)
        self._draw()
        return self._current_marker

    def delete_all_marker(self):
        self._current_marker = None
        self._draw()

    def _on_resize(self, event):
        self._draw()

    def _latlon_to_xy(self, lat, lon, w, h):
        x = (lon + 180) / 360 * w
        y = (90 - lat) / 180 * h
        return x, y

    def _draw(self):
        self.delete("all")
        w = max(self.winfo_width(), 10)
        h = max(self.winfo_height(), 10)

        for lon in range(-180, 181, 30):
            x, _ = self._latlon_to_xy(0, lon, w, h)
            self.create_line(x, 0, x, h, fill=self._grid_color, width=1)
        for lat in range(-90, 91, 30):
            _, y = self._latlon_to_xy(lat, 0, w, h)
            self.create_line(0, y, w, y, fill=self._grid_color, width=1)

        for points in self._CONTINENTS.values():
            xy = []
            for lat, lon in points:
                x, y = self._latlon_to_xy(lat, lon, w, h)
                xy.extend([x, y])
            self.create_polygon(xy, fill=self._land_color,
                               outline=self._land_outline, width=1.2, smooth=True)

        if self._current_marker:
            lat, lon, text = self._current_marker
            try:
                lat = float(lat)
                lon = float(lon)
            except (TypeError, ValueError):
                return
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                x, y = self._latlon_to_xy(lat, lon, w, h)
                r = 5
                self.create_oval(x - r, y - r, x + r, y + r,
                                fill=self._marker_color, outline="#ffffff", width=1.5)
                self.create_line(x, y + r, x, y + r + 6,
                                fill=self._marker_color, width=2)
                if text:
                    self.create_text(x, y - r - 8, text=text,
                                    fill=self._marker_text_color,
                                    font=("Segoe UI", 9, "bold"))
