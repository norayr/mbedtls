DEPEND = github.com/norayr/strutils github.com/norayr/base64 github.com/norayr/Internet github.com/norayr/http
ARCH := $(shell uname -m)
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

all: get_mbedtls_libs get_deps build_deps buildThis


get_mbedtls_libs:
		@echo "Detected architecture: $(ARCH)"
		mkdir -p $(BUILD)
		cd $(BUILD) && wget -c https://norayr.am/mbedtls/$(ARCH)/libmbedcrypto.a
		cd $(BUILD) && wget -c https://norayr.am/mbedtls/$(ARCH)/libmbedtls.a
		cd $(BUILD) && wget -c https://norayr.am/mbedtls/$(ARCH)/libmbedx509.a

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
	mkdir -p $(BUILD)
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
				#cp $(mkfile_dir_path)/libs/*.a $(BUILD)/
				cd $(BLD) && $(VOC) -s $(mkfile_dir_path)/src/mbedtls.Mod
				cd $(BLD) && $(VOC) -c $(mkfile_dir_path)/src/https.Mod
				cd $(BLD) && $(VOC) -cm $(mkfile_dir_path)/test/testHttps.Mod
				cd $(BLD) && gcc -o testHttps *.o -static -L/opt/voc/lib -lvoc-O2 /opt/voc/lib/libvoc-O2.a -L. -lmbedtls -lmbedcrypto -lmbedx509 libmbedcrypto.a libmbedtls.a libmbedx509.a

tests:
	#cd $(BUILD) && $(VOC) $(mkfile_dir_path)/test/testHttp.Mod -m
	#build/testList

clean:
	if [ -d "$(BUILD)" ]; then rm -rf $(BLD); fi
