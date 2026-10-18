# Build the CVEX v3 technical report.
#   make          refresh stats.tex from the corpus, then build main.pdf
#   make docker   same, using the texlive/texlive image (no local TeX needed)
#   make clean
TEX = latexmk -pdf -interaction=nonstopmode -halt-on-error

all: stats
	$(TEX) main.tex

stats:
	python3 gen_stats.py

docker: stats
	docker run --rm -u $$(id -u):$$(id -g) -v "$(CURDIR)":/doc -w /doc texlive/texlive:latest $(TEX) main.tex

clean:
	latexmk -C main.tex 2>/dev/null || rm -f main.aux main.bbl main.blg main.log main.out main.fls main.fdb_latexmk

.PHONY: all stats docker clean
