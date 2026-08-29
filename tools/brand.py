"""Generate Redoubt's mark and every raster it is needed in.

A redoubt is an enclosed defensive work, and the classic form of one is the
bastion fort: a square whose corners are pushed out into arrowheads so that
every face can be covered from another. That plan makes a better mark than a
shield - it is specific, it is geometric enough to survive being drawn at
sixteen pixels, and nobody else's antivirus uses it.

Everything is drawn at SUPERSAMPLE times the target size and reduced with a
Lanczos filter. Drawing polygons directly at 16x16 gives ragged diagonals, and
diagonals are the whole mark.

Colours come from the interface's own theme so the installer, the icon and the
application cannot drift apart.

    python tools/brand.py
"""

import math
import os

from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "brand")

# --- palette, converted from the oklch values in ui/src/app.css -------------

PRIMARY = (20, 171, 235)      # --color-primary, dark theme
PRIMARY_DEEP = (0, 118, 186)  # --color-primary, light theme: the shadow tone
BASE = (23, 28, 38)           # --color-base-100
BASE_LIFT = (32, 39, 51)      # --color-base-200
PAPER = (250, 250, 252)       # light backdrop for installer artwork

SUPERSAMPLE = 8

# Sizes Windows actually asks for. 256 is what File Explorer shows at its
# largest, 16 is the title bar; missing either is immediately visible.
ICON_SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]


def bastion_polygon(cx, cy, radius, wall=0.52, flank=0.30):
    """The star-fort outline: a square curtain with an arrowhead at each corner.

    Built the way the real thing is. Take a square curtain wall; at each
    corner, draw back along both walls by `flank` and push the corner itself
    outward along the diagonal. What you get is four arrowhead bastions joined
    by straight walls - concave nowhere, which is what separates a fort from a
    shuriken.

    `wall` is the curtain's half-width as a fraction of `radius`, and `radius`
    is the distance from centre to bastion tip.
    """
    w = radius * wall
    f = w * flank
    tip = radius / math.sqrt(2)  # so the diagonal tip lands at `radius`

    corners = [(-w, -w), (w, -w), (w, w), (-w, w)]
    verts = []
    for i, (x, y) in enumerate(corners):
        # Unit vectors along the two walls meeting at this corner.
        px, py = corners[i - 1]
        nx, ny = corners[(i + 1) % 4]

        def toward(ax, ay, bx, by, dist):
            dx, dy = bx - ax, by - ay
            n = math.hypot(dx, dy) or 1.0
            return (ax + dx / n * dist, ay + dy / n * dist)

        # Shoulder on the incoming wall, the bastion point, shoulder on the
        # outgoing wall.
        verts.append(toward(x, y, px, py, f))
        sx = 1 if x > 0 else -1
        sy = 1 if y > 0 else -1
        verts.append((sx * tip, sy * tip))
        verts.append(toward(x, y, nx, ny, f))

    return [(cx + vx, cy + vy) for vx, vy in verts]


def rounded_rect_mask(size, radius):
    m = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(m)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return m


def draw_mark(size, background=True, bg=BASE, ring=True):
    """Draw the mark at `size` pixels, supersampled."""
    s = size * SUPERSAMPLE
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    if background:
        plate = Image.new("RGBA", (s, s), bg + (255,))
        # A very slight lift towards the top so the tile is not dead flat.
        grad = Image.new("L", (1, s))
        for y in range(s):
            t = y / max(1, s - 1)
            grad.putpixel((0, y), int(255 * (1 - t) * 0.35))
        lift = Image.new("RGBA", (s, s), BASE_LIFT + (255,))
        plate = Image.composite(lift, plate, grad.resize((s, s)))
        img.paste(plate, (0, 0), rounded_rect_mask(s, int(s * 0.18)))

    cx = cy = s / 2
    outer = s * (0.40 if background else 0.48)

    # The fort itself.
    d.polygon(bastion_polygon(cx, cy, outer), fill=PRIMARY + (255,))

    # Below this the ditch is thinner than a pixel and fills in to mush, so
    # the small sizes get a solid silhouette instead. A recognisable shape
    # beats a faithful one nobody can resolve.
    if size <= 24:
        ring = False

    # A darker ditch inside the walls, so the outline reads at larger sizes
    # instead of filling in to a blob.
    if ring:
        d.polygon(
            bastion_polygon(cx, cy, outer * 0.70),
            fill=(bg if background else BASE) + (255,),
        )

    # The keep at the centre.
    d.polygon(bastion_polygon(cx, cy, outer * 0.34), fill=PRIMARY + (255,))

    return img.resize((size, size), Image.LANCZOS)


def write_ico(path):
    """Write a multi-resolution .ico.

    Pillow's `save(sizes=...)` re-samples one image for every entry, which
    turns 16x16 into mush. Each size is drawn and reduced independently.
    """
    frames = [draw_mark(n) for n in ICON_SIZES]
    frames[-1].save(
        path,
        format="ICO",
        sizes=[(n, n) for n in ICON_SIZES],
        append_images=frames[:-1],
    )


def wizard_banner(path, w=493, h=58):
    """The strip across the top of the installer's inner pages."""
    img = Image.new("RGB", (w, h), PAPER)
    d = ImageDraw.Draw(img)
    d.rectangle([0, h - 2, w, h], fill=PRIMARY_DEEP)
    mark = draw_mark(int(h * 0.62), background=False, bg=PAPER)
    img.paste(mark, (18, int((h - mark.height) / 2)), mark)
    img.save(path)


def wizard_dialog(path, w=493, h=312):
    """The full-bleed panel on the installer's first and last pages."""
    img = Image.new("RGB", (w, h), BASE)
    d = ImageDraw.Draw(img)

    # A quiet diagonal wash, so the panel is not a flat rectangle.
    for y in range(h):
        t = y / (h - 1)
        c = tuple(int(BASE[i] + (BASE_LIFT[i] - BASE[i]) * t) for i in range(3))
        d.line([(0, y), (w, y)], fill=c)

    # The left third carries the mark; WiX writes its text over the right.
    mark = draw_mark(150, background=False, bg=BASE)
    img.paste(mark, (26, int(h / 2 - 96)), mark)
    d.rectangle([26, int(h / 2 + 68), 26 + 150, int(h / 2 + 70)], fill=PRIMARY)
    img.save(path)


def main():
    os.makedirs(OUT, exist_ok=True)

    write_ico(os.path.join(OUT, "redoubt.ico"))
    for n in (256, 128, 64, 48, 32, 16):
        draw_mark(n).save(os.path.join(OUT, f"icon-{n}.png"))
    draw_mark(512, background=False, bg=BASE).save(os.path.join(OUT, "mark-512.png"))

    wizard_banner(os.path.join(OUT, "wizard-banner.bmp"))
    wizard_dialog(os.path.join(OUT, "wizard-dialog.bmp"))

    print("wrote", OUT)
    for f in sorted(os.listdir(OUT)):
        print("  ", f, os.path.getsize(os.path.join(OUT, f)), "bytes")


if __name__ == "__main__":
    main()
