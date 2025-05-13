
all:
	clang -g -O2 -target bpf -D__TARGET_ARCH_arm64 -c kexec_pe_parser_bpf.c -o kexec_pe_parser_bpf.o
	gcc -o loader_pe_parser loader_pe_parser.c -lbpf
	#
	gcc -g -O2 -o zboot_image_builder zboot_image_builder.c

clean:
	rm -f *.o
