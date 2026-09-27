# Progress reports for the mentor

Ten separate notes. Each one can be read on its own. The opening and the closing connect it to the work around it.
The Word file is the one to edit. The PDF has the same words and the same picture, for sending.

Student: Richa Verma (25MCSS02). Advisor: Dr. Akshay Pandey.

- What we want the tool to explain. Many scanners only say that a piece of code is unsafe. The programmer still has to guess the kind of mistake and the fix.
- A small Java practice set and a first check. The aim is a Java tool that explains a weakness in plain words, using a CWE name. This note is only about the first files and a very simple checker.
- A small book of CWE facts. We already have 12 short Java files and a pattern checker that matches them. That checker can raise an alarm. It cannot yet say the official name of the weakness or how to fix it.
- Finding the right CWE page. We have short Java examples, a pattern checker, and a small book of CWE facts. This note is about search: given some Java, which book page should we show.
- One shape for every answer. We can mark risky lines, and we can search the CWE book. What was missing was a single shape for the written answer. Without that, two runs cannot be compared.
- The steps running in one order. The separate pieces are a pattern checker, a CWE book, search, and a fixed answer form. This note connects them into one run.
- Hard examples and a live model. The pipeline can already mark lines, search the CWE book, fill the answer form, and check that form. On our first 12 files the simple checker looked perfect, because those files were easy.
- Six public Java test sets. Our own 24 hard files showed that a live model can recover cases the pattern checker misses. Those files were written by us, so they are not enough.
- A Juliet score we can stand behind. Juliet is a large public Java suite. The simple checker scores 0.316 there. An earlier model score on Juliet was withdrawn because the question showed the answer.
- How to run the tool, and what is still open. The tool can explain a Java method with a CWE page, and we have scores: a perfect score only on 12 practice files, a 0.923 score on 24 hard files we wrote, modest pattern-checker scores on six public sets, and a Juliet pair score of 9 out of 17.

Regenerate with `uv run python scripts/write_progress_reports.py`.
