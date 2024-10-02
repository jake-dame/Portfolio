###############################################################################
#  Makefile - makefile for msdscript + test_msdscript programs
#  Author: Jake Dame
#  Date: Spring 2024
###############################################################################

##################################  TARGETS  ##################################
# all - see the rule itself, it changes a lot
# run - runs msdscript
# build - builds msdscript

# msd - builds + runs msdscript

# test_msd - builds + runs test_msdscript

# help - runs program with "--help" argument
# test - runs program with "--test" argument
# interp - runs program with "--interp" argument
# print - runs program with "--print" argument
# pprint - runs program with "--pretty-print" argument

# open - updates documentation, opens doxygen index.html
# pdf - uses pdflatex to make a pdf of Doxygen documentation
# doc - updates/produces Doxygen documentation files

# clean - deletes msdscript and test_msdscript executables

##################################  MACROS  ###################################

# DOCUMENTATION
DOX_CONFIG = Doxyfile
DOX = documentation

# COMPILATION
CXX = c++
CXXFLAGS = -std=c++11

# PROGRAM - msdscript
DIR = msdscript/src
EXEC = $(DIR)/msdscript
CFILES := $(wildcard $(DIR)/*.cpp) # using simple expansion assignment
HFILES := $(wildcard $(DIR)/*.h) # using simple expansion assignment

# PROGRAM - test_msdscript
TEST_DIR = test_msdscript/src
TEST_EXEC = $(TEST_DIR)/test_msdscript
TEST_CFILES := $(wildcard $(TEST_DIR)/*.cpp) # using simple expansion assignment
TEST_HFILES := $(wildcard $(TEST_DIR)/*.h) # using simple expansion assignment

TEST_ARGS ?= msdscript0

################################  DIRECTIVES  #################################
.SILENT:
.PHONY: all run build msd test_msd help test interp print pprint open pdf doc clean

###################################  RULES  ###################################

# STANDARD RULES
all: test clean # runs msdscript --test ; then cleans
run: build
	./$(EXEC)
build: msd

# PROGRAM - msdscript # TODO if I try and name this rule "msdscript", github workflow breaks
msd: $(HFILES)
	@echo "...building msdscript..." \
	&& $(CXX) $(CXXFLAGS) -fsanitize=undefined $(CFILES) -o $(EXEC) \
	&& ./$(EXEC)

# PROGRAM - test_msdscript
test_msd: $(TEST_HFILES)
	@echo "...building test_msdscript..." \
	&& $(CXX) $(CXXFLAGS) $(TEST_CFILES) -o $(TEST_EXEC) \
	&& ./$(TEST_EXEC) $(TEST_ARGS)

# ARGUMENTS RULES
help: msd
	./$(EXEC) --help
test: msd
	./$(EXEC) --test
interp: msd
	./$(EXEC) --interp
print: msd
	./$(EXEC) --print
pprint: msd
	./$(EXEC) --pretty-print

# DOCUMENTATION RULES
open: doc
	cd $(DOX)/html && open index.html
pdf: doc
	cd $(DOX)/latex \
	&& make pdf > /dev/null \
	&& cp refman.pdf ../msdscript_man.pdf
doc:
	cd $(DOX) && doxygen $(DOX_CONFIG) > /dev/null

# MISC RULES
clean:
	rm -rf $(EXEC) $(TEST_EXEC)