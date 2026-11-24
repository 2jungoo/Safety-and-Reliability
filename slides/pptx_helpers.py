"""python-pptx 보조 함수. 16:9, 강의안과 같은 파란 제목 막대."""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

BLUE = RGBColor(0x24, 0x5A, 0x8D)
DARK = RGBColor(0x22, 0x22, 0x22)
GRAY = RGBColor(0x66, 0x66, 0x66)
RED = RGBColor(0xC4, 0x4E, 0x52)
GREEN = RGBColor(0x55, 0xA8, 0x68)
LIGHT = RGBColor(0xEE, 0xF3, 0xF8)
FONT = "맑은 고딕"
W, H = Inches(13.333), Inches(7.5)


def new_prs():
    p = Presentation()
    p.slide_width, p.slide_height = W, H
    return p


def _blank(prs):
    return prs.slides.add_slide(prs.slide_layouts[6])


def _run(par, text, size, bold=False, color=DARK):
    r = par.add_run(); r.text = text
    r.font.size = Pt(size); r.font.bold = bold; r.font.name = FONT; r.font.color.rgb = color
    return r


def textbox(slide, x, y, w, h, text, size=18, bold=False, color=DARK, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP):
    tb = slide.shapes.add_textbox(x, y, w, h); tf = tb.text_frame; tf.word_wrap = True; tf.vertical_anchor = anchor
    for i, line in enumerate(str(text).split("\n")):
        par = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        par.alignment = align; _run(par, line, size, bold, color)
    return tb


def title_bar(slide, text, page=None):
    bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, Inches(1.0))
    bar.fill.solid(); bar.fill.fore_color.rgb = BLUE; bar.line.fill.background()
    textbox(slide, Inches(0.5), Inches(0.12), Inches(12.3), Inches(0.8), text, size=28, bold=True, color=RGBColor(255, 255, 255), anchor=MSO_ANCHOR.MIDDLE)
    if page is not None:
        textbox(slide, Inches(12.3), Inches(7.05), Inches(0.9), Inches(0.35), str(page), size=11, color=GRAY, align=PP_ALIGN.RIGHT)


def bullets(slide, items, x, y, w, h, size=18, gap=6):
    """items: 문자열 또는 (문자열, 들여쓰기 수준) 목록. 수준 1은 작은 글씨."""
    tb = slide.shapes.add_textbox(x, y, w, h); tf = tb.text_frame; tf.word_wrap = True
    first = True
    for it in items:
        txt, lvl = (it, 0) if isinstance(it, str) else it
        par = tf.paragraphs[0] if first else tf.add_paragraph(); first = False
        par.space_after = Pt(gap)
        bullet = "• " if lvl == 0 else "– "
        _run(par, ("    " * lvl) + bullet + txt, size - 2 * lvl, False, DARK if lvl == 0 else GRAY)
    return tb


def image(slide, path, x, y, w=None, h=None):
    return slide.shapes.add_picture(str(path), x, y, width=w, height=h)


def table(slide, rows, x, y, w, col_w=None, size=12, header_fill=BLUE, row_h=0.36):
    """rows[0]이 머리글. col_w는 비율 목록."""
    nr, nc = len(rows), len(rows[0])
    gt = slide.shapes.add_table(nr, nc, x, y, w, Inches(row_h * nr)); t = gt.table
    if col_w:
        tot = sum(col_w)
        for i, c in enumerate(col_w): t.columns[i].width = int(w * c / tot)
    for r in range(nr):
        for c in range(nc):
            cell = t.cell(r, c); cell.text = ""
            par = cell.text_frame.paragraphs[0]
            _run(par, str(rows[r][c]), size, r == 0, RGBColor(255, 255, 255) if r == 0 else DARK)
            cell.margin_left = cell.margin_right = Inches(0.06); cell.margin_top = cell.margin_bottom = Inches(0.03)
            cell.fill.solid(); cell.fill.fore_color.rgb = header_fill if r == 0 else (LIGHT if r % 2 == 0 else RGBColor(255, 255, 255))
    return t


def callout(slide, text, x, y, w, h, size=16, color=RED):
    box = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, x, y, w, h)
    box.fill.solid(); box.fill.fore_color.rgb = RGBColor(255, 255, 255); box.line.color.rgb = color; box.line.width = Pt(2)
    tf = box.text_frame; tf.word_wrap = True; tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    for i, line in enumerate(text.split("\n")):
        par = tf.paragraphs[0] if i == 0 else tf.add_paragraph(); par.alignment = PP_ALIGN.CENTER
        _run(par, line, size, True, color)
    return box


def notes(slide, text):
    slide.notes_slide.notes_text_frame.text = text


def add_slide(prs, title, page):
    s = _blank(prs); title_bar(s, title, page); return s
