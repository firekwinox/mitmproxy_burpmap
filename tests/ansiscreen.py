"""A minimal ANSI screen model - just enough to read urwid's output back.

urwid repaints only the cells it believes changed, so the raw pty stream is not
a screen. This keeps a grid and applies the cursor movements, which makes
assertions against "what is on screen right now" possible.
"""

import re

CSI = re.compile(r"\x1b\[([0-9;?]*)([@-~])")


class Screen:
    def __init__(self, rows=45, cols=150):
        self.rows, self.cols = rows, cols
        self.grid = [[" "] * cols for _ in range(rows)]
        # Parallel grid of "this cell has a non-default background", which is how
        # a highlighted row is told apart from an ordinary one.
        self.bg = [[False] * cols for _ in range(rows)]
        self.cur_bg = False
        self.r = self.c = 0

    def _put(self, ch):
        if self.r < self.rows and self.c < self.cols:
            self.grid[self.r][self.c] = ch
            self.bg[self.r][self.c] = self.cur_bg
        self.c += 1

    def feed(self, data: str) -> None:
        i = 0
        while i < len(data):
            ch = data[i]
            if ch == "\x1b":
                m = CSI.match(data, i)
                if m:
                    self._csi(m.group(1), m.group(2))
                    i = m.end()
                    continue
                i += 2 if i + 1 < len(data) and data[i + 1] in "()=>#" else 1
                if i <= len(data) and data[i - 1] in "()#":
                    i += 1
                continue
            if ch == "\n":
                self.r, self.c = self.r + 1, 0
            elif ch == "\r":
                self.c = 0
            elif ch == "\x08":
                self.c = max(0, self.c - 1)
            elif ch in ("\x0e", "\x0f", "\x07"):
                pass
            else:
                self._put(ch)
            i += 1

    def _csi(self, params: str, final: str) -> None:
        nums = [int(p) for p in params.split(";") if p.isdigit()]
        if final in ("H", "f"):
            self.r = (nums[0] - 1) if nums else 0
            self.c = (nums[1] - 1) if len(nums) > 1 else 0
        elif final == "m":
            self._sgr(params)
        elif final == "J" and (nums[0] if nums else 0) == 2:
            self.grid = [[" "] * self.cols for _ in range(self.rows)]
            self.bg = [[False] * self.cols for _ in range(self.rows)]
            self.r = self.c = 0
        elif final == "K" and self.r < self.rows:
            for c in range(self.c, self.cols):
                self.grid[self.r][c] = " "
                self.bg[self.r][c] = self.cur_bg
        elif final == "A":
            self.r = max(0, self.r - (nums[0] if nums else 1))
        elif final == "B":
            self.r += nums[0] if nums else 1
        elif final == "C":
            self.c += nums[0] if nums else 1
        elif final == "D":
            self.c = max(0, self.c - (nums[0] if nums else 1))

    def _sgr(self, params: str) -> None:
        parts = [p for p in params.split(";")]
        i = 0
        while i < len(parts):
            p = parts[i]
            if p in ("", "0", "39"):
                if p != "39":
                    self.cur_bg = False
            elif p == "49":
                self.cur_bg = False
            elif p == "48":  # 48;5;n or 48;2;r;g;b
                self.cur_bg = True
                i += 2 if i + 1 < len(parts) and parts[i + 1] == "5" else 4
            elif p.isdigit() and (40 <= int(p) <= 47 or 100 <= int(p) <= 107):
                self.cur_bg = True
            i += 1

    def highlighted(self) -> list:
        """Lines drawn with a non-default background, i.e. the cursor row."""
        out = []
        for r in range(self.rows):
            if any(self.bg[r]):
                text = "".join(
                    self.grid[r][c] for c in range(self.cols) if self.bg[r][c]
                ).strip()
                if text:
                    out.append(text)
        return out

    def text(self) -> str:
        return "\n".join("".join(row).rstrip() for row in self.grid)

    def flat(self) -> str:
        return re.sub(r"[ \t]+", " ", self.text().replace("\n", " "))
