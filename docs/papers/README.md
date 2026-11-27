# VORB3-SP1 Papers

This directory contains the long-form companion documents for the
VORB3-SP1 release line:

| Document | LaTeX source | PDF |
|---|---|---|
| Academic white paper | [`VORB3-SP1-Whitepaper.tex`](VORB3-SP1-Whitepaper.tex) | [`VORB3-SP1-Whitepaper.pdf`](VORB3-SP1-Whitepaper.pdf) |
| Yellow paper | [`VORB3-SP1-Yellow-Paper.tex`](VORB3-SP1-Yellow-Paper.tex) | [`VORB3-SP1-Yellow-Paper.pdf`](VORB3-SP1-Yellow-Paper.pdf) |

The shared preamble is [`common.tex`](common.tex). The PDFs are checked in so
the documents can be read without a TeX installation.

## Build

From this directory:

```bash
pdflatex -interaction=nonstopmode VORB3-SP1-Whitepaper.tex
pdflatex -interaction=nonstopmode VORB3-SP1-Whitepaper.tex
pdflatex -interaction=nonstopmode VORB3-SP1-Yellow-Paper.tex
pdflatex -interaction=nonstopmode VORB3-SP1-Yellow-Paper.tex
```

Two passes are required for the table of contents, cross-references, and
bookmarks. The build uses only standard TeX Live packages: `lmodern`,
`amsmath`, `amsthm`, `booktabs`, `tikz`, `algorithm`, `algorithmic`,
`listings`, `hyperref`, `geometry`, `fancyhdr`, `microtype`, and `setspace`.

## Status

These documents describe a locally verified candidate implementation. They are
not an external audit, a formal proof of computational security, or a
NIST/FIPS certification. The frozen specification, wire-binding table, and
KATs are the normative artifacts.

License: **GPL-3.0-or-later**.
