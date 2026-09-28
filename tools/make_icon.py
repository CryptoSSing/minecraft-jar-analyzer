"""Generate the application icon: assets/icon.ico (Windows) and assets/icon.png.

Run:  python -m tools.make_icon

The design is original (dark tile, green block, magnifying glass) - no
Minecraft or antivirus branding. Replace the files with your own art anytime.

An .ico file can hold several sizes so Windows can pick a sharp one for each
place (taskbar, Explorer, title bar). Qt can only write single-size .ico
files, so we write the (simple) format ourselves:

    ICONDIR       6 bytes: reserved=0, type=1 (icon), count
    ICONDIRENTRY  16 bytes per image: width, height, colours, reserved,
                  planes, bits-per-pixel, data size, data offset
    image data    PNG files (allowed inside .ico since Windows Vista)
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt  # noqa: E402
from PySide6.QtGui import QBrush, QColor, QGuiApplication, QImage, QPainter, QPen, QPolygonF  # noqa: E402

SIZES = [16, 24, 32, 48, 64, 128, 256]
ASSETS = Path(__file__).resolve().parent.parent / "assets"


def draw(size: int) -> QImage:
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.scale(size / 256, size / 256)  # draw on a 256x256 canvas

    # Background tile
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#1b2029"))
    p.drawRoundedRect(QRectF(8, 8, 240, 240), 48, 48)

    # Isometric block (three faces)
    top = QPolygonF([QPointF(112, 40), QPointF(184, 78), QPointF(112, 116), QPointF(40, 78)])
    left = QPolygonF([QPointF(40, 78), QPointF(112, 116), QPointF(112, 196), QPointF(40, 158)])
    right = QPolygonF([QPointF(112, 116), QPointF(184, 78), QPointF(184, 158), QPointF(112, 196)])
    for poly, color in ((top, "#5fd3a5"), (left, "#2f9c74"), (right, "#23775a")):
        p.setBrush(QColor(color))
        p.drawPolygon(poly)

    # Magnifying glass
    p.setBrush(QBrush(QColor(255, 255, 255, 40)))
    p.setPen(QPen(QColor("#e6edf3"), 18))
    p.drawEllipse(QPointF(170, 164), 44, 44)
    p.setPen(QPen(QColor("#e6edf3"), 24, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    p.drawLine(QPointF(202, 196), QPointF(230, 224))
    p.end()
    return img


def png_bytes(img: QImage) -> bytes:
    data = QByteArray()
    buf = QBuffer(data)
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, "PNG")
    return bytes(data)


def write_ico(path: Path, images: list[bytes]) -> None:
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for size, data in zip(SIZES, images):
        dim = 0 if size == 256 else size  # 0 means 256 in the ICO format
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    path.write_bytes(header + entries + blobs)


def main() -> None:
    app = QGuiApplication.instance() or QGuiApplication([])  # noqa: F841 - Qt needs an app for painting
    ASSETS.mkdir(exist_ok=True)
    write_ico(ASSETS / "icon.ico", [png_bytes(draw(s)) for s in SIZES])
    draw(256).save(str(ASSETS / "icon.png"))
    print(f"Wrote {ASSETS / 'icon.ico'} and {ASSETS / 'icon.png'}")


if __name__ == "__main__":
    main()
