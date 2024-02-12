DEPEND = github.com/norayr/strutils github.com/norayr/Internet github.com/norayr/http
CC = gcc -O0
VOC = /opt/voc/bin/voc
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir_path := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
$(info $$mkfile_path is [${mkfile_path}])
$(info $$mkfile_dir_path is [${mkfile_dir_path}])
ifndef BUILD
BUILD="build"
endif
build_dir_path := $(mkfile_dir_path)/$(BUILD)
current_dir := $(notdir $(patsubst %/,%,$(dir $(mkfile_path))))
BLD := $(mkfile_dir_path)/build
DPD  =  deps
ifndef DPS
DPS := $(mkfile_dir_path)/$(DPD)
endif
all: get_deps build_deps buildThis

get_deps:
	@for i in $(DEPEND); do \
			if [ -d "$(DPS)/$${i}" ]; then \
				 cd "$(DPS)/$${i}"; \
				 git pull; \
				 cd - ;    \
				 else \
				 mkdir -p "$(DPS)/$${i}"; \
				 cd "$(DPS)/$${i}"; \
				 cd .. ; \
				 git clone "https://$${i}"; \
				 cd - ; \
			fi; \
	done

build_deps:
	mkdir -p $(BLD)
	cd $(BLD); \
	for i in $(DEPEND); do \
		if [ -f "$(DPS)/$${i}/GNUmakefile" ]; then \
			make -f "$(DPS)/$${i}/GNUmakefile" BUILD=$(BLD); \
		else \
			make -f "$(DPS)/$${i}/Makefile" BUILD=$(BLD); \
		fi; \
	done

buildThis:
	cp $(mkfile_dir_path)/certs/* $(BUILD)/
	cp $(mkfile_dir_path)/libs/*.a $(BUILD)/
	cp $(mkfile_dir_path)/src/mb.h $(BUILD)/
	cd $(BUILD) && $(CC) -c $(mkfile_dir_path)/src/mb.c
	cd $(BUILD) && $(VOC) -s $(mkfile_dir_path)/src/mbedtls.Mod
	cd $(BUILD) && $(VOC) -cm $(mkfile_dir_path)/src/tls.Mod
	cd $(BUILD) && gcc -o Test *.o -static -L/opt/voc/lib -lvoc-O2 /opt/voc/lib/libvoc-O2.a -L. -lmbedtls -lmbedcrypto -lmbedx509 libmbedcrypto.a libmbedtls.a libmbedx509.a
	#cd $(BUILD) && gcc -o Test tls.o mbedtls.o mb.o *.o -static -L/opt/voc/lib -lvoc-O2 /opt/voc/lib/libvoc-O2.a -L. -lmbedtls -lmbedcrypto -lmbedx509 libmbedcrypto.a libmbedtls.a libmbedx509.a
	#cd $(BUILD) && $(CC) -o Test -L/opt/voc/lib -lvoc-O2 -lmbedtls -lmbedcrypto -lmbedx509 *.o
	#cd $(BUILD) && gcc -o Test -L/opt/voc/lib -lvoc-O2 -lmbedtls -lmbedcrypto -lmbedx509 mbedtls.o mb.o

tests:
	cd $(BUILD) && $(VOC) $(mkfile_dir_path)/test/testHttp.Mod -m
	#build/testList

clean:
	if [ -d "$(BUILD)" ]; then rm -rf $(BLD); fi
