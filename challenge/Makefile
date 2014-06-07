# Find every Python files in subdirectories, to highlight the syntax and run them
PY_FILES := $(wildcard */*.py)
C_FILES := $(wildcard */*.c)
SCITE_LATEX_FILES := $(PY_FILES:%.py=%.py.scite.tex) $(C_FILES:%.c=%.c.scite.tex)
INC_LATEX_FILES := $(PY_FILES:%.py=%.py.inc.tex) $(C_FILES:%.c=%.c.inc.tex)
OUT_FILES := $(PY_FILES:%.py=%.py.out)

all: $(INC_LATEX_FILES) $(OUT_FILES) 3_mcu/mcu/upload.py solution.pdf

clean:
	rm -f */*.scite.tex
	rm -f */*.inc.tex
	rm -f */*.py.out
	rm -f */usbtrace */badbios.bin
	rm -f */*.bin.disasm
	rm -f */*.bin
	rm -f *.aux *.log *.out *.pdf *.toc
	rm -rf 3_mcu/mcu

# SciTE LaTex export is buggy: ^ needs to be replaced with ^{ }, and other patterns too.
%.inc.tex: %.scite.tex
	sed -n '/^\\small{/,/^} %end small/p' < $< | \
	sed 's/\^/^{ }/g;s/~/~{ }/g;s/--/-{}-/g;s/\\hspace\*{1em}/\\hspace*{1.2ex}/g' > $@

# SciTE "-quit" command is buggy with Gtk+. Dirty hack to kill it once the output file is written
# FIXME: there is a race condition here!
%.scite.tex: %
	rm -f "$@"
	scite -open:$< -exportaslatex:$@ -close: -quit: & PIDSCITE=$$! && \
	while ! [ -r "$@" ] ; do sleep .5 ; done && kill $$PIDSCITE


# Python script dependencies
1_usb/extract_badbios.py.out 1_usb/read_androidcomm.py.out 1_usb/read_usbtrace.py.out: 1_usb/usbtrace
2_arm64/unpack_badbios.py.out: 2_arm64/badbios.bin 2_arm64/badbios.bin.disasm
2_arm64/run_unpacked_badbios1.py.out 2_arm64/run_unpacked_badbios2.py.out 2_arm64/run_unpacked_badbios3.py.out: 2_arm64/badbios-400000.bin.disasm
2_arm64/decrypt_badbios_mem.py.out: 2_arm64/badbios-400000.bin.disasm
2_arm64/disasm_badbiosrisc.py.out 2_arm64/find_badbios_key.py.out 2_arm64/decrypt_badbios_payload.py.out: 2_arm64/badbios-decrypt.bin
3_mcu/parse_fw.py.out: 3_mcu/fw.bin
3_mcu/parse_kernel.py.out: 3_mcu/kernel.bin

%.py.out: %.py
	cd $(<D) && python3 ./$(<F) > $(@F).tmp || (rm -f $(@F).tmp ; false)
	fmt -95 -s < $@.tmp > $@
	rm $@.tmp

# Download initial file
1_usb/usbtrace.xz:
	wget -O $@ --quiet 'http://static.sstic.org/challenge2014/usbtrace.xz'
	echo '3783cd32d09bda669c189f3f874794bf $@' | md5sum -c -

1_usb/usbtrace: 1_usb/usbtrace.xz
	unxz < $< > $@

# Extract badbios.bin
1_usb/badbios.bin: 1_usb/extract_badbios.py.out

2_arm64/badbios.bin: 1_usb/badbios.bin
	cat < $< > $@

# Use binutils-aarch64 from Ubuntu
# TODO: test for installed binutils binaries
OBJDUMP_BIN := binutils-aarch64-linux/usr/bin/aarch64-linux-gnu-objdump
OBJDUMP_LIB := binutils-aarch64-linux/usr/x86_64-linux-gnu/aarch64-linux-gnu/lib/

binutils-aarch64-linux_amd64.deb:
	wget --quiet -O $@ 'http://fr.archive.ubuntu.com/ubuntu/pool/main/b/binutils-arm64-cross/binutils-aarch64-linux-gnu_2.24-1ubuntu1cross0.11_amd64.deb'

binutils-aarch64-linux/data.tar.xz: binutils-aarch64-linux_amd64.deb
	[ -d $(@D) ] || mkdir -p $(@D)
	cd $(@D) && ar x ../$<
	touch $@

$(OBJDUMP_BIN) $(OBJDUMP_LIB): binutils-aarch64-linux/data.tar.xz
	cd $(<D) && tar xf $(<F)
	touch $@

# Unpack badbios.bin
2_arm64/badbios.bin.disasm: 2_arm64/badbios.bin $(OBJDUMP_BIN) $(OBJDUMP_LIB)
	LD_LIBRARY_PATH=$$(pwd)/$(OBJDUMP_LIB) \
	$(OBJDUMP_BIN) -d $< > $@ || (rm -f $@ ; false)

2_arm64/badbios-400000.bin 2_arm64/badbios-500000.bin: 2_arm64/unpack_badbios.py.out

2_arm64/badbios-400000.bin.disasm: 2_arm64/badbios-400000.bin $(OBJDUMP_BIN) $(OBJDUMP_LIB)
	LD_LIBRARY_PATH=$$(pwd)/$(OBJDUMP_LIB) \
	$(OBJDUMP_BIN) -D -b binary -maarch64 --adjust-vma=0x400000 --start-address=0x4000b0 --stop-address=0x402b38 $< > $@ || (rm -f $@ ; false)

# Decrypt payload
2_arm64/badbios-decrypt.bin: 2_arm64/decrypt_badbios_mem.py.out

2_arm64/payload.bin: 2_arm64/decrypt_badbios_payload.py.out

3_mcu/mcu/upload.py 3_mcu/mcu/fw.hex: 2_arm64/payload.bin
	[ -d $(@D) ] || mkdir -p $(@D)
	rm -f $@
	cd 3_mcu && unzip ../$< mcu/$(@F)
	touch $@

3_mcu/fw.bin: 3_mcu/mcu/fw.hex
	sed 's/^:.\{8\}\(.*\)..$$/\1/' < $< | xxd -p -r > $@

3_mcu/kernel.bin: 3_mcu/kernel.hex
	xxd -p -r < $< > $@

# LATEX
solution.pdf: solution.tex $(INC_LATEX_FILES) $(OUT_FILES)
	pdflatex $< < /dev/null
	pdflatex $< < /dev/null

.PHONY: all clean
