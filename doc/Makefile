# vim:ft=automake
# included from Top Level Makefile.am
# All paths should be given relative to the root

#dist_doc_DATA+= doc/README.txt

dox-pdf:
	echo "Generating PDF"
	./generate_documentation.sh -install -pdf || (echo "HTML generation failed $$?"; exit 1)

dox-html:
	echo "Generating HTML"
	./generate_documentation.sh -install -html || (echo "HTML generation failed $$?"; exit 1)

dox: dox-html dox-pdf

clean-local:
	-rm -rf build/
	-rm -rf html/
	-rm -f refman.pdf
	-rm -f doxygen_warnings
