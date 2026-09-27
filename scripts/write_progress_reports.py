"""Write ten short mentor progress reports as editable Word files.

Each report adds one step. It does not mention results from later reports.
Pictures are drawn with Pillow and embedded in the DOCX. Text stays real
Word text so the file can be edited.
"""

from __future__ import annotations

from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "progress"
FIG = OUT / "figures"

NAVY = (27, 58, 75)
CREAM = (246, 241, 231)
RUST = (196, 92, 38)
INK = (28, 25, 21)
CARD = (255, 252, 247)
LINE = (217, 208, 195)
MUTED = (92, 86, 76)

TITLE = (
    "RAG-Augmented Multi-Agent LLM Framework for Explainable "
    "Software Vulnerability Detection Using CWE Knowledge Bases"
)
WHO = "Richa Verma (25MCSS02)    Advisor: Dr. Akshay Pandey"


def _font(size: int, bold: bool = False) -> ImageFont.ImageFont:
    names = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/Library/Fonts/Arial Bold.ttf" if bold else "/Library/Fonts/Arial.ttf",
    ]
    for name in names:
        if Path(name).is_file():
            return ImageFont.truetype(name, size)
    return ImageFont.load_default()


def _canvas() -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (1600, 560), CREAM)
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, 1600, 10), fill=NAVY)
    return image, draw


def _box(draw: ImageDraw.ImageDraw, xy: tuple[int, int, int, int], fill: tuple[int, int, int], title: str, body: str) -> None:
    draw.rounded_rectangle(xy, radius=18, fill=fill, outline=NAVY, width=3)
    x1, y1, x2, _y2 = xy
    draw.text((x1 + 24, y1 + 22), title, font=_font(28, bold=True), fill=NAVY)
    y = y1 + 72
    for line in body.split("\n"):
        draw.text((x1 + 24, y), line, font=_font(22), fill=INK)
        y += 32


def _arrow(draw: ImageDraw.ImageDraw, x1: int, x2: int, y: int) -> None:
    draw.line((x1, y, x2 - 18, y), fill=RUST, width=8)
    draw.polygon([(x2 - 18, y - 14), (x2, y), (x2 - 18, y + 14)], fill=RUST)


def _save(image: Image.Image, name: str) -> Path:
    FIG.mkdir(parents=True, exist_ok=True)
    path = FIG / name
    image.save(path, "PNG")
    return path


def fig_question() -> Path:
    image, draw = _canvas()
    _box(draw, (40, 80, 520, 480), CARD, "Java file", "A short method.\nMaybe a bug.\nMaybe safe code.")
    _arrow(draw, 540, 700, 280)
    _box(draw, (720, 70, 1560, 490), CARD, "A note a person can read", "Unsafe or safe\nWhich weakness (CWE)\nWhich lines\nWhy, and how to fix it")
    return _save(image, "01_question.png")


def fig_split() -> Path:
    image, draw = _canvas()
    _box(draw, (80, 70, 740, 490), CARD, "Train  ·  8 files", "4 unsafe\n4 safe\nWe use these to shape the tool.")
    _box(draw, (860, 70, 1520, 490), (255, 236, 224), "Test  ·  4 files", "2 unsafe\n2 safe\nHeld back for a first check.")
    return _save(image, "02_practice_set.png")


def fig_card() -> Path:
    image, draw = _canvas()
    _box(draw, (60, 50, 980, 510), CARD, "CWE-89  SQL injection", "Name and short description\nHow it happens\nHow to fix it\nParent and child weaknesses")
    _box(draw, (1040, 80, 1540, 230), (255, 236, 224), "Parent", "A broader group")
    _box(draw, (1040, 260, 1540, 470), CARD, "Child", "A more specific case")
    return _save(image, "03_knowledge.png")


def fig_search() -> Path:
    image, draw = _canvas()
    _box(draw, (40, 140, 460, 420), (255, 236, 224), "Question from code", "\"SQL string built\nby sticking text\ntogether\"")
    _arrow(draw, 480, 640, 280)
    _box(draw, (660, 40, 1560, 180), CARD, "1  CWE-89", "Best match")
    _box(draw, (660, 200, 1560, 340), CARD, "2  a related weakness", "Next match")
    _box(draw, (660, 360, 1560, 500), CARD, "3  another related page", "Still useful context")
    return _save(image, "04_retrieval.png")


def fig_answer() -> Path:
    image, draw = _canvas()
    rows = [
        "Decision     unsafe  /  safe  /  not sure",
        "CWE          id and name",
        "Lines        file and line numbers",
        "Why          one short cause",
        "Explain      plain words",
        "Fix          what to change",
    ]
    draw.rounded_rectangle((180, 40, 1420, 520), radius=18, fill=CARD, outline=NAVY, width=3)
    draw.text((220, 60), "Every answer uses the same fields", font=_font(30, bold=True), fill=NAVY)
    y = 130
    for row in rows:
        draw.text((240, y), row, font=_font(26), fill=INK)
        y += 58
    return _save(image, "05_answer_shape.png")


def fig_pipeline() -> Path:
    image, draw = _canvas()
    labels = [
        (40, "1  Mark lines", "Find risky spans.\nNot the final yes/no."),
        (420, "2  Search book", "Pick CWE pages\nthat fit the code."),
        (800, "3  Write note", "Fill the answer\nfrom a template."),
        (1180, "4  Check note", "Fields present.\nLines are real."),
    ]
    for x, title, body in labels:
        _box(draw, (x, 120, x + 360, 440), CARD, title, body)
    for x in (400, 780, 1160):
        _arrow(draw, x, x + 20, 280)
    return _save(image, "06_pipeline.png")


def fig_traps() -> Path:
    image, draw = _canvas()
    _box(draw, (60, 70, 740, 490), (255, 228, 224), "Simple checker", "Score 0 on 24 hard files.\nIt misses real bugs\nand also flags safe code.")
    _arrow(draw, 760, 900, 280)
    _box(draw, (920, 70, 1540, 490), (226, 240, 230), "Live model", "Score 0.923 on the same 24.\n2 false alarms.\n0 missed bugs.")
    return _save(image, "07_traps.png")


def fig_bars() -> Path:
    image, draw = _canvas()
    rows = [
        ("Juliet", 0.316, 20728),
        ("OWASP", 0.395, 2740),
        ("Securibench", 0.072, 119),
        ("Find Security Bugs", 0.435, 79),
        ("Vul4J", 0.244, 62),
        ("CVEfixes slice", 0.207, 92),
    ]
    draw.text((40, 24), "Simple checker score (F1) on six public Java sets", font=_font(28, bold=True), fill=NAVY)
    y = 80
    for name, score, n in rows:
        draw.text((40, y + 8), name, font=_font(22), fill=INK)
        width = int(700 * score / 0.5)
        draw.rounded_rectangle((420, y, 420 + max(width, 8), y + 42), radius=8, fill=RUST)
        draw.text((1140, y + 8), f"{score:.3f}    n={n}", font=_font(22), fill=INK)
        y += 72
    return _save(image, "08_six_suites.png")


def fig_pair() -> Path:
    image, draw = _canvas()
    _box(draw, (50, 80, 620, 420), (255, 228, 224), "Bad file", "Must be called unsafe.")
    _box(draw, (980, 80, 1550, 420), (226, 240, 230), "Good file", "Must be called safe.")
    draw.text((660, 200), "Both must\nbe right", font=_font(32, bold=True), fill=NAVY)
    draw.text((80, 450), "One right and one wrong  =  the pair is wrong", font=_font(24), fill=MUTED)
    return _save(image, "09_pairs.png")


def fig_console() -> Path:
    image, draw = _canvas()
    _box(draw, (40, 70, 700, 490), CARD, "Web page on this computer", "Pick a test set\nPick a setting\nSet a token budget\nPress start")
    _arrow(draw, 720, 880, 280)
    _box(draw, (900, 70, 1560, 490), CARD, "Same pipeline as the command line", "Mark lines\nSearch the CWE book\nWrite the note\nCheck the note")
    return _save(image, "10_console.png")


REPORTS: list[dict] = [
    {
        "num": 1,
        "slug": "01_question",
        "name": "The question",
        "adds": "This is the first report. It only says what we want to build.",
        "figure": fig_question,
        "did": [
            "We want a tool that reads a small piece of Java and explains the risk in plain words.",
            "The explanation should name a weakness from CWE. CWE is a public list of common software mistakes.",
            "A useful answer says four things: unsafe or safe, which weakness, which lines, and how to fix it.",
            "We are not trying to beat every scanner. We want an answer a person can check.",
        ],
        "headers": ["Weakness", "Plain meaning"],
        "rows": [
            ["CWE-89", "SQL injection. User text is stuck into a database query."],
            ["CWE-79", "Cross-site scripting. User text is shown as part of a web page."],
            ["CWE-22", "A file path can be steered outside the intended folder."],
            ["CWE-502", "Loading a saved object can run attacker-controlled data."],
            ["CWE-798", "A password is written directly in the code."],
            ["CWE-327", "The code uses weak encryption or a weak hash."],
        ],
        "next": "Next we will make a tiny set of Java examples, half unsafe and half safe.",
        "not_claim": "This report has no test scores. We have not measured anything yet.",
    },
    {
        "num": 2,
        "slug": "02_practice_set",
        "name": "A small practice set",
        "adds": "This report adds a 12-file Java set and a first simple check. It continues report 1.",
        "figure": fig_split,
        "did": [
            "We wrote 12 short Java files for the six weaknesses in report 1. Six files are unsafe. Six are safe.",
            "Eight files are for practice. Four files are held back as a first check (two unsafe, two safe).",
            "A simple checker looks for risky text patterns. On these 12 files it found every unsafe file and did not flag a safe file.",
            "F1 is one score that mixes two ideas. Precision is how many alarms were real bugs. Recall is how many real bugs we caught. Here both are 1.000, so F1 is 1.000.",
            "The checker is only a list of text patterns. It does not understand the program. A perfect score on 12 files we wrote ourselves is a first check, not a real test.",
        ],
        "headers": ["Split", "Files", "Unsafe", "Safe"],
        "rows": [
            ["Train", "8", "4", "4"],
            ["Test", "4", "2", "2"],
            ["All", "12", "6", "6"],
        ],
        "next": "Next we will store short CWE facts so the tool can look up a name and a fix.",
        "not_claim": "A perfect score here does not mean the checker works on real projects. This is not Juliet and not OWASP.",
    },
    {
        "num": 3,
        "slug": "03_knowledge_book",
        "name": "A small CWE book",
        "adds": "This report adds a lookup book of CWE facts. It continues report 2.",
        "figure": fig_card,
        "did": [
            "The simple checker should not invent the words for a weakness. Those words should come from a stored page.",
            "Each page has a name, a short description, related weaknesses, and a fix.",
            "We can look up one id, search by words, and list parents and children.",
            "For example, the CWE-89 page says SQL injection, what goes wrong when user text is stuck into a query, and a safer way to write that query.",
            "The book is a subset we need for this project. It is not the whole CWE catalog. Later answers must use a name from this book. They must not invent one.",
        ],
        "headers": ["On each page", "Why we keep it"],
        "rows": [
            ["Id and name", "So the answer uses the official name."],
            ["Description", "So the note can say what the weakness is."],
            ["Parents and children", "So a close match can still be explained."],
            ["Fixes", "So the answer can suggest a repair."],
        ],
        "next": "Next we will search this book from the words in a Java file.",
        "not_claim": "This report does not change the detection score from report 2.",
    },
    {
        "num": 4,
        "slug": "04_search",
        "name": "Finding the right CWE page",
        "adds": "This report adds search over the CWE book. It continues report 3.",
        "figure": fig_search,
        "did": [
            "Given a Java file, we turn the risky part into a short question and search the book.",
            "We try word match, a small meaning model called MiniLM, and a mix of both. The mix also uses the simple checker's hint and related CWE pages.",
            "On 18 practice questions, MiniLM put the right CWE first about 94 times out of 100 (R@1 = 0.944). Word match did this about 78 times out of 100.",
            "R@1 means the right page was the first result. MiniLM was first on about 17 of the 18 questions. 17 divided by 18 is 0.944.",
            "On this small set the mix matched MiniLM. It did not beat it yet. If the meaning model is missing, we fall back to word match and we record that.",
        ],
        "headers": ["Search", "Right page first (R@1)", "Questions"],
        "rows": [
            ["Word match (TF-IDF)", "0.778", "18"],
            ["Meaning match (MiniLM)", "0.944", "18"],
            ["Mix of both", "0.944", "18"],
        ],
        "next": "Next we will fix the shape of the written answer so every run looks the same.",
        "not_claim": "These 18 questions are from our practice files. This is not a public benchmark.",
    },
    {
        "num": 5,
        "slug": "05_answer_shape",
        "name": "One shape for every answer",
        "adds": "This report adds a fixed answer form. It continues report 4.",
        "figure": fig_answer,
        "did": [
            "Every answer must use the same fields. If a field is missing, the answer is rejected.",
            "The fields are: the decision, the CWE, the cited lines, the cause, a short explanation, and a fix.",
            "The decision can be unsafe, safe, or not sure.",
            "The form has no place for attack steps. The tool is not asked to write an exploit.",
            "We keep two sample answers in the project, one unsafe and one safe, so we can check the form before any model is called.",
            "Line numbers start at 1. That is the same way a person counts lines in an editor.",
            "If two runs use different shapes, we cannot put them in one table. The fixed form lets us compare the simple checker, the template, and the live model later.",
            "The check is automatic. A person does not have to open every file to see if a field is missing.",
        ],
        "headers": ["Field", "What it means"],
        "rows": [
            ["Decision", "Unsafe, safe, or not sure."],
            ["CWE", "Id and name from the book."],
            ["Lines", "The file and the line numbers we point at."],
            ["Fix", "What a programmer should change."],
        ],
        "next": "Next we will run the steps in order: mark lines, search, write, then check the form.",
        "not_claim": "The simple checker still only marks lines. It is not the final yes or no.",
    },
    {
        "num": 6,
        "slug": "06_pipeline",
        "name": "The steps, without a live model",
        "adds": "This report connects the steps into one pipeline. It continues report 5.",
        "figure": fig_pipeline,
        "did": [
            "The tool now runs in a fixed order. First it marks risky lines. Those marks are evidence. They are not the final decision.",
            "Then it searches the CWE book. Then a template fills the answer form. No paid model is called in this report.",
            "A checker then looks at the form. The CWE must be in the book. The cited lines must exist. The fields must agree with each other.",
            "If the decision disagrees with the simple checker, that is only a warning. We also save a confidence number. We do not use it to skip work.",
        ],
        "headers": ["Step", "Job"],
        "rows": [
            ["Mark lines", "Point at risky spans."],
            ["Search", "Pick CWE pages."],
            ["Write", "Fill the form from a template."],
            ["Check", "Reject a broken form."],
        ],
        "next": "Next we will try a live language model on examples written to fool the simple checker.",
        "not_claim": "The template is only a stand-in. It is not the system we want to rely on.",
    },
    {
        "num": 7,
        "slug": "07_hard_traps",
        "name": "Hard examples and a live model",
        "adds": "This report adds 24 harder files and a live model. It continues report 6.",
        "figure": fig_traps,
        "did": [
            "We wrote 24 extra Java files to fool the simple checker. Some safe files look risky. Some unsafe files look quiet.",
            "On these 24, the simple checker scores F1 = 0. It raises 12 false alarms and misses 12 bugs. The template also scores 0. It sees fewer false alarms only because comments were blanked. It still misses every bug.",
            "The live model is Groq, model openai/gpt-oss-20b. On the same 24 files its F1 is 0.923. It has 2 false alarms and misses none.",
            "We also turned the CWE search off and ran the model again. The score stayed 0.923. So on these 24 files, search did not improve detection.",
        ],
        "headers": ["System", "F1", "False alarms", "Missed bugs", "Files"],
        "rows": [
            ["Simple checker", "0.000", "12", "12", "24"],
            ["Template", "0.000", "6", "12", "24"],
            ["Live model", "0.923", "2", "0", "24"],
            ["Live model, no search", "0.923", "2", "0", "24"],
        ],
        "next": "Next we will run the simple checker on six public Java test sets.",
        "not_claim": "These 24 files were written by us. They are not Juliet. We do not say that CWE search helps detection.",
    },
    {
        "num": 8,
        "slug": "08_six_public_sets",
        "name": "Six public Java test sets",
        "adds": "This report adds six public test sets for the simple checker. It continues report 7.",
        "figure": fig_bars,
        "did": [
            "We ran only the simple pattern checker on six named public Java sets. The scores are modest.",
            "The best F1 here is 0.435. The lowest is 0.072. A bigger set is not an easier set.",
            "We did try the live model on small samples of these sets earlier. Those scores are withdrawn.",
            "The old prompts still showed words that gave away the true label, such as a method named bad. A fair test must not show the answer inside the question.",
        ],
        "headers": ["Test set", "Files", "Simple checker F1"],
        "rows": [
            ["Juliet Java", "20728", "0.316"],
            ["OWASP Benchmark", "2740", "0.395"],
            ["Securibench Micro", "119", "0.072"],
            ["Find Security Bugs", "79", "0.435"],
            ["Vul4J", "62", "0.244"],
            ["CVEfixes Java slice", "92", "0.207"],
        ],
        "next": "Next we will score the live model on Juliet pairs, after hiding the answer words.",
        "not_claim": "The simple checker is not CodeQL and not a commercial scanner. The withdrawn model scores must not be quoted.",
    },
    {
        "num": 9,
        "slug": "09_juliet_pairs",
        "name": "The Juliet number we can stand behind",
        "adds": "This report adds a fair Juliet pair score. It continues report 8.",
        "figure": fig_pair,
        "did": [
            "A Juliet pair is one unsafe file and one matching safe file. The model is correct only if it calls the bad file unsafe and the good file safe.",
            "We kept 17 complete pairs. The model got 9 right. That is 0.529.",
            "Because 17 is small, we repeated the sample many times. The score usually falls between 0.294 and 0.765. The range is wide.",
            "One more pair was cut off by the free daily token limit. We do not count that cutoff as a model mistake. The run is partial: 35 of 36 files were scored.",
        ],
        "headers": ["Item", "Value"],
        "rows": [
            ["Complete pairs correct", "9 of 17"],
            ["Pair accuracy", "0.529"],
            ["Likely range if repeated", "0.294 to 0.765"],
            ["Files scored", "35 of 36 (stopped by token limit)"],
            ["Binary F1 on scored files", "0.789"],
        ],
        "next": "Next we will add a simple screen to run these tests, and list what is still open.",
        "not_claim": "We have not yet run Juliet with CWE search turned off. We do not say that search helps on Juliet. This is not a claim of the best published score.",
    },
    {
        "num": 10,
        "slug": "10_how_to_run",
        "name": "How to run it, and what is still open",
        "adds": "This report adds a local screen and a list of unfinished tests. It continues report 9.",
        "figure": fig_console,
        "did": [
            "A web page on this computer lets us pick a test set, a setting, and a token budget, then start a run.",
            "The page only listens on this machine. It has no login because it is not open to the network.",
            "The six public test sets are now stored in the project, with their licenses noted. A new copy of the project does not have to download them again.",
            "GitHub runs the unit tests on each push. Those tests do not call the live model.",
        ],
        "headers": ["Still open", "Status"],
        "rows": [
            ["Finish the one Juliet file cut off by the token limit", "Not finished"],
            ["Juliet again with CWE search turned off", "Not run"],
            ["Sliced real bugs from Vul4J", "Not run for the live model"],
            ["A second model, if tokens remain", "Not run"],
            ["A person marking whether explanations are good", "Labels still empty"],
        ],
        "next": "The next real run needs a Groq key and the daily token budget. Empty human labels stay empty until a person fills them.",
        "not_claim": "We still do not claim that CWE search improves Juliet detection. We have no score for agreement between human raters.",
    },
]


def _shade(cell, hex_color: str) -> None:
    tc = cell._tc
    tc_pr = tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), hex_color)
    shd.set(qn("w:val"), "clear")
    tc_pr.append(shd)


def _set_run(run, text: str, *, size: int, bold: bool = False, color: RGBColor | None = None) -> None:
    run.text = text
    run.bold = bold
    run.font.size = Pt(size)
    run.font.name = "Calibri"
    if color is not None:
        run.font.color.rgb = color


def _add_text(doc: Document, text: str, *, size: int = 12, bold: bool = False, color: RGBColor | None = None, space_after: int = 6) -> None:
    paragraph = doc.add_paragraph()
    paragraph.paragraph_format.space_after = Pt(space_after)
    paragraph.paragraph_format.space_before = Pt(0)
    _set_run(paragraph.add_run(), text, size=size, bold=bold, color=color)


def _build(report: dict, figure: Path) -> Document:
    doc = Document()
    section = doc.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
    section.left_margin = Inches(0.75)
    section.right_margin = Inches(0.75)
    section.top_margin = Inches(0.65)
    section.bottom_margin = Inches(0.65)
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(12)

    _add_text(doc, f"Progress report {report['num']} of 10", size=11, bold=True, color=RGBColor(0xC4, 0x5C, 0x26), space_after=2)
    _add_text(doc, TITLE, size=14, bold=True, color=RGBColor(0x1B, 0x3A, 0x4B), space_after=2)
    _add_text(doc, WHO, size=11, color=RGBColor(0x5C, 0x56, 0x4C), space_after=2)
    _add_text(doc, report["name"], size=16, bold=True, color=RGBColor(0x1C, 0x19, 0x15), space_after=2)
    _add_text(doc, report["adds"], size=12, space_after=8)

    _add_text(doc, "What we did", size=13, bold=True, color=RGBColor(0x1B, 0x3A, 0x4B), space_after=4)
    for sentence in report["did"]:
        paragraph = doc.add_paragraph(style=None)
        paragraph.paragraph_format.space_after = Pt(4)
        paragraph.paragraph_format.left_indent = Inches(0.15)
        _set_run(paragraph.add_run(), sentence, size=12)

    _add_text(doc, "Picture", size=13, bold=True, color=RGBColor(0x1B, 0x3A, 0x4B), space_after=4)
    doc.add_picture(str(figure), width=Inches(7.0))
    doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER

    _add_text(doc, "Numbers for this step only", size=13, bold=True, color=RGBColor(0x1B, 0x3A, 0x4B), space_after=4)
    table = doc.add_table(rows=1, cols=len(report["headers"]))
    table.style = "Table Grid"
    for index, header in enumerate(report["headers"]):
        cell = table.rows[0].cells[index]
        cell.text = ""
        _set_run(cell.paragraphs[0].add_run(), header, size=11, bold=True, color=RGBColor(0xFF, 0xFC, 0xF7))
        _shade(cell, "1B3A4B")
    for row in report["rows"]:
        cells = table.add_row().cells
        for index, value in enumerate(row):
            cells[index].text = ""
            _set_run(cells[index].paragraphs[0].add_run(), value, size=11)

    _add_text(doc, "What is next", size=13, bold=True, color=RGBColor(0x1B, 0x3A, 0x4B), space_after=2)
    _add_text(doc, report["next"], size=12, space_after=6)
    _add_text(doc, "What this report does not claim", size=13, bold=True, color=RGBColor(0x1B, 0x3A, 0x4B), space_after=2)
    _add_text(doc, report["not_claim"], size=12, space_after=2)
    return doc


def write_pdf(report: dict, figure: Path) -> tuple[Path, int]:
    from fpdf import FPDF

    pdf = FPDF(format="Letter")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.set_margins(18, 16, 18)
    pdf.add_page()

    def say(text: str, size: int, bold: bool = False, color: tuple[int, int, int] = (28, 25, 21), height: float = 6) -> None:
        pdf.set_x(pdf.l_margin)
        pdf.set_text_color(*color)
        pdf.set_font("Helvetica", "B" if bold else "", size)
        pdf.multi_cell(0, height, text, new_x="LMARGIN", new_y="NEXT")

    say(f"Progress report {report['num']} of 10", 11, bold=True, color=(196, 92, 38))
    pdf.ln(1)
    say(TITLE, 13, bold=True, color=(27, 58, 75))
    pdf.ln(1)
    say(WHO, 11, color=(92, 86, 76))
    pdf.ln(1)
    say(report["name"], 16, bold=True, height=8)
    say(report["adds"], 12)
    pdf.ln(2)
    say("What we did", 13, bold=True, color=(27, 58, 75), height=7)
    for sentence in report["did"]:
        say(sentence, 12)
        pdf.ln(1)
    pdf.ln(1)
    say("Picture", 13, bold=True, color=(27, 58, 75), height=7)
    pdf.image(str(figure), w=170)
    pdf.ln(3)
    say("Numbers for this step only", 13, bold=True, color=(27, 58, 75), height=7)
    pdf.set_font("Helvetica", size=11)
    pdf.set_text_color(28, 25, 21)
    with pdf.table(width=170) as table:
        heading = table.row()
        for header in report["headers"]:
            heading.cell(header)
        for values in report["rows"]:
            row = table.row()
            for value in values:
                row.cell(value)
    pdf.ln(3)
    say("What is next", 13, bold=True, color=(27, 58, 75), height=7)
    say(report["next"], 12)
    pdf.ln(2)
    say("What this report does not claim", 13, bold=True, color=(27, 58, 75), height=7)
    say(report["not_claim"], 12)
    dest = OUT / f"{report['slug']}_RichaVerma_25MCSS02.pdf"
    pages = len(pdf.pages)
    pdf.output(dest)
    return dest, pages


def write_readme() -> None:
    lines = [
        "# Progress reports for the mentor",
        "",
        "Ten short reports. Each one adds a single step and does not use numbers from later reports.",
        "The Word file is the one to edit. The PDF has the same words and the same picture, for sending.",
        "",
        "Student: Richa Verma (25MCSS02). Advisor: Dr. Akshay Pandey.",
        "",
    ]
    for report in REPORTS:
        lines.append(f"- Report {report['num']}: {report['name']}. {report['adds']}")
    lines.append("")
    lines.append("Regenerate with `uv run python scripts/write_progress_reports.py`.")
    lines.append("")
    (OUT / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for report in REPORTS:
        figure = report["figure"]()
        doc = _build(report, figure)
        dest = OUT / f"{report['slug']}_RichaVerma_25MCSS02.docx"
        doc.save(dest)
        pdf, pages = write_pdf(report, figure)
        print(dest)
        print(pdf, "pages", pages)
    write_readme()
    print(OUT / "README.md")


if __name__ == "__main__":
    main()
