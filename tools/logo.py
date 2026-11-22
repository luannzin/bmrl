"""Draws BMRL's mark and everything made from it:

    python tools/logo.py

assets/icon.png (512), assets/mark.png (32), assets/mark-spin.png (the coin turning, SPIN frames
of 32x32 side by side), assets/banner.webp (the README header, the coin turning) with
assets/banner.png (the same banner, still, for reduced motion) and assets/preview.png (1200x630,
the repository's social preview).

The mark is 32x32 pixel art in the family of Deskline, Sightline and Hostline: a coin with the
bitcoin sign, turning on its vertical axis, its face dithered in luannzin.com's dusk (plum low,
ember, gold high), a glint crossing the face as it turns and three sparks blinking around it.
Pixels are placed one by one and scaled up with nearest-neighbour, so every size stays crisp.

The banner and the preview are the same world at their sizes: a field of dots on a grid dithered
from the night down to the dusk glow, the mark, and the name in a 5x7 pixel face drawn here.
"""

import math
import os

from PIL import Image

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets")


def rgb(h):
    return tuple(int(h[i : i + 2], 16) for i in (1, 3, 5)) + (255,)


NIGHT = rgb("#110d24")
DUSK = [rgb("#3a2a6b"), rgb("#7a3361"), rgb("#e0703f"), rgb("#ffd180")]
LINE = rgb("#1a1424")  # outlines
WALL_LIT = rgb("#ffffff")
INK = rgb("#f5f5f5")
MUTED = rgb("#b2b2b2")
CLEAR = (0, 0, 0, 0)
BAYER = ((0, 8, 2, 10), (12, 4, 14, 6), (3, 11, 1, 9), (15, 7, 13, 5))


def dither(ramp, t, x, y):
    """Colour of cell (x, y) at position t (0..1) along `ramp`, ordered-dithered."""
    step = t * (len(ramp) - 1) + BAYER[y % 4][x % 4] / 16 - 0.5
    return ramp[max(0, min(len(ramp) - 1, round(step)))]


CX, CY, R = 15.5, 15.5, 13.0  # the coin
THICK = 2.2  # the rim's depth in pixels, seen edge-on
FACE = [DUSK[1], DUSK[2], DUSK[3], DUSK[3]]  # plum low, ember, gold high
GLYPH_INK = DUSK[0]

# The bitcoin sign, 12x16, two bars through a B.
GLYPH = [
    "...#..#.....",
    "...#..#.....",
    "#########...",
    ".##.....##..",
    ".##......##.",
    ".##......##.",
    ".##.....##..",
    ".########...",
    ".##.....##..",
    ".##......##.",
    ".##......##.",
    ".##......##.",
    ".##.....##..",
    "#########...",
    "...#..#.....",
    "...#..#.....",
]
GW, GH = len(GLYPH[0]), len(GLYPH)


def glyph_at(u, v):
    """Whether face point (u, v) in -1..1 falls on the sign (drawn in the face's middle 58% x 74%)."""
    gx = (u / 0.58 + 1) / 2 * GW + 0.5  # nudged right so the B sits optically centred
    gy = (v / 0.74 + 1) / 2 * GH
    return 0 <= gx < GW and 0 <= gy < GH and GLYPH[int(gy)][int(gx)] == "#"


def mark(turn=0.0, glint=0.4, twinkle=0):
    """The 32x32 mark: the coin at `turn` (0..1 is one full turn on its vertical axis), the
    glint at `glint` (0..1 across the face) and the sparks at step `twinkle`."""
    img = Image.new("RGBA", (32, 32), CLEAR)
    px = img.load()
    phi = turn * 2 * math.pi
    sx = math.cos(phi)  # how wide the face looks
    a = max(1.0, R * abs(sx))
    depth = THICK * math.sin(phi)  # the rim shows on the side the coin turns away from
    for y in range(32):
        for x in range(32):
            v = (y + 0.5 - CY) / R
            if v * v > 0.98:
                continue
            u = (x + 0.5 - CX) / a
            on_face = u * u + v * v <= 0.98
            # the rim: the same ellipse shifted by the coin's depth, behind the face
            ur = (x + 0.5 - CX - depth) / a
            on_rim = ur * ur + v * v <= 0.98 or (min(0, depth) <= x + 0.5 - CX <= max(0, depth) and abs(v) < 0.99)
            if on_face:
                r = math.sqrt(u * u + v * v)
                # light from the upper left: gold high, ember, plum low
                t = 0.78 - 0.42 * v - 0.18 * u * math.copysign(1, sx)
                c = dither(FACE, max(0.0, min(1.0, t)), x, y)
                if 0.80 <= r <= 0.88 and a > 4:
                    c = DUSK[2] if v < 0.2 else DUSK[1]  # the raised ring
                # the back carries the same sign, read the right way round
                if a > 5 and glyph_at(u, v):
                    c = GLYPH_INK
                # the glint: a narrow diagonal band crossing the face
                band = (u + 0.5 * v) / 2 - (glint * 2.2 - 1.1) / 2
                if abs(band) < 0.045 and a > 4 and c != GLYPH_INK:
                    c = WALL_LIT
                px[x, y] = c
            elif on_rim:
                px[x, y] = dither([DUSK[1], DUSK[2]], 0.6 - 0.4 * v, x, y)
    # three sparks, each lit for part of the loop
    for i, (sx_, sy_) in enumerate(((3, 4), (28, 9), (26, 28))):
        phase = (twinkle + 5 * i) % 16
        if phase < 2:
            px[sx_, sy_] = WALL_LIT
            for ox, oy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
                px[sx_ + ox, sy_ + oy] = DUSK[3]
        elif phase < 4:
            px[sx_, sy_] = DUSK[3]
    # the family's dark outline: every clear pixel touching the art
    art = [[px[x, y][3] > 0 for x in range(32)] for y in range(32)]
    for y in range(32):
        for x in range(32):
            if art[y][x]:
                continue
            if any(0 <= x + ox < 32 and 0 <= y + oy < 32 and art[y + oy][x + ox] for ox, oy in ((-1, 0), (1, 0), (0, -1), (0, 1))):
                px[x, y] = LINE
    return img


def scaled(img, size):
    """Nearest-neighbour up to a multiple, then down to `size` with a box filter so odd sizes
    stay sharp-edged without uneven pixels."""
    k = max(1, -(-size // img.width))
    big = img.resize((img.width * k, img.height * k), Image.NEAREST)
    return big if big.width == size else big.resize((size, size), Image.BOX)


# 5x7 pixel face for the banner: one string of 35 cells per glyph, rows top to bottom.
FONT = {
    "A": ".###.#...##...#######...##...##...#",
    "B": "####.#...##...#####.#...##...#####.",
    "C": ".###.#...##....#....#....#...#.###.",
    "D": "####.#...##...##...##...##...#####.",
    "E": "######....#....####.#....#....#####",
    "G": ".###.#...##....#.####...##...#.####",
    "H": "#...##...##...#######...##...##...#",
    "I": ".###...#....#....#....#....#...###.",
    "K": "#...##..#.#.#..##...#.#..#..#.#...#",
    "L": "#....#....#....#....#....#....#####",
    "M": "#...###.###.#.##.#.##...##...##...#",
    "N": "#...###..##.#.##..###...##...##...#",
    "O": ".###.#...##...##...##...##...#.###.",
    "P": "####.#...##...#####.#....#....#....",
    "Q": ".###.#...##...##...##.#.##..#..##.#",
    "R": "####.#...##...#####.#.#..#..#.#...#",
    "S": ".#####....#.....###.....#....#####.",
    "T": "#####..#....#....#....#....#....#..",
    "U": "#...##...##...##...##...##...#.###.",
    "V": "#...##...##...##...##...#.#.#...#..",
    "W": "#...##...##...##.#.##.#.###.###...#",
    "Y": "#...##...#.#.#...#....#....#....#..",
    "2": ".###.#...#....#...#...#...#...#####",
    "5": "######....####.....#....##...#.###.",
    "6": "..##..#...#....####.#...##...#.###.",
    "·": "." * 17 + "#" + "." * 17,
    " ": "." * 35,
}


def text(img, s, x, y, scale, color):
    """Draw `s` in the 5x7 face, `scale` image pixels per font pixel, 1 font pixel between
    letters. Returns the x after the last letter."""
    px = img.load()
    for ch in s.upper():
        for i, c in enumerate(FONT[ch]):
            if c == "#":
                gx, gy = x + (i % 5) * scale, y + (i // 5) * scale
                for yy in range(gy, gy + scale):
                    for xx in range(gx, gx + scale):
                        px[xx, yy] = color
        x += 6 * scale
    return x


def field(w, h, glow, reach, cell=4):
    """A field of dots on a grid, night at the top dithering down to the dusk glow at `glow`."""
    img = Image.new("RGBA", (w, h), NIGHT)
    px = img.load()
    ramp = [NIGHT] + DUSK
    for y in range(0, h, cell):
        for x in range(0, w, cell):
            near = max(0.0, 1 - ((x - glow[0]) ** 2 + ((y - glow[1]) * 1.6) ** 2) ** 0.5 / reach)
            t = max(near ** 1.6, 0.08 + 0.25 * (y / h) ** 2)
            c = dither(ramp, t, x // cell, y // cell)
            if c != NIGHT:
                for yy in range(y, min(h, y + cell - 1)):  # a dot, with a 1px gap: the grid shows
                    for xx in range(x, min(w, x + cell - 1)):
                        px[xx, yy] = c
    return img


# One loop: a full turn of the coin, the glint crossing once and every spark blinking once.
SPIN = 24
FRAME = 80  # ms


def spun(frame):
    """The mark at `frame` of the loop; None is the still: head-on, the glint across it."""
    if frame is None:
        return mark(turn=0.0, glint=0.35, twinkle=0)
    k = frame / SPIN
    return mark(turn=k, glint=(2 * k) % 1.0, twinkle=round(k * 16))


def sprite():
    """The turn as one strip, frame after frame, for a CSS steps() animation."""
    img = Image.new("RGBA", (32 * SPIN, 32), CLEAR)
    for f in range(SPIN):
        img.alpha_composite(spun(f), (32 * f, 0))
    return img


def banner(frame=None):
    """1600x420: the field with the glow at the bottom right, where the mark sits, the name
    and two lines in the pixel face."""
    img = field(1600, 420, (1300, 330), 900)
    img.alpha_composite(scaled(spun(frame), 256), (1172, 82))
    text(img, "BMRL", 110, 120, 14, INK)
    text(img, "BITCOIN MINING RESEARCH LAB", 112, 260, 4, INK)
    text(img, "SHA256D · GPU KERNELS · MAINNET · QUANTUM", 112, 310, 3, MUTED)
    return img


def preview():
    """1200x630, the repository's social preview."""
    img = field(1200, 630, (600, 700), 820)
    img.alpha_composite(scaled(spun(None), 224), ((1200 - 224) // 2, 96))
    name = "BMRL"
    w = len(name) * 6 * 10 - 10
    text(img, name, (1200 - w) // 2, 360, 10, INK)
    line = "BITCOIN MINING RESEARCH LAB"
    w = len(line) * 6 * 4 - 4
    text(img, line, (1200 - w) // 2, 470, 4, INK)
    return img


def main():
    os.makedirs(ROOT, exist_ok=True)
    scaled(spun(None), 512).save(os.path.join(ROOT, "icon.png"))
    spun(None).save(os.path.join(ROOT, "mark.png"))
    sprite().save(os.path.join(ROOT, "mark-spin.png"))
    banner().save(os.path.join(ROOT, "banner.png"))
    # The README shows this one; banner.png stays for prefers-reduced-motion.
    loop = [banner(f) for f in range(SPIN)]
    loop[0].save(
        os.path.join(ROOT, "banner.webp"),
        save_all=True,
        append_images=loop[1:],
        duration=FRAME,
        loop=0,
        lossless=True,
        method=6,
    )
    preview().convert("RGB").save(os.path.join(ROOT, "preview.png"), optimize=True)
    print("wrote", ", ".join(sorted(os.listdir(ROOT))))


if __name__ == "__main__":
    main()
