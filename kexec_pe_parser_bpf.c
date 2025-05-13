// SPDX-License-Identifier: GPL-2.0
//
// This file works on bpf kfunc
//

//test
//   bpftool prog load zboot_decompress_bpf.o /sys/fs/bpf/zboot_decompress
//bpftool prog attach   <program_fd_or_id>    <attach_type>     <target_fd_or_id>
//

//bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
/* For le32toh() */
#include <endian.h>

/* 1GB =  1^28 * sizeof(__uint) */
#define MAX_BUF_SIZE	(1 << 28)
/* 512MB is big enough to hold either kernel or initramfs */
#define MAX_RECORD_SIZE	(1 << 27)

#define KEXEC_RES_KERNEL_NAME "kernel"
#define KEXEC_RES_INITRD_NAME "initrd"
#define KEXEC_RES_CMDLINE_NAME "cmdline"

/* ringbuf is safe since the user space has no write access to them */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_BUF_SIZE);
} ringbuf_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_BUF_SIZE);
} ringbuf_2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_BUF_SIZE);
} ringbuf_3 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_BUF_SIZE);
} ringbuf_4 SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

/*
 * This function ensures that the sections .rodata, .data .bss and .rodata.str1.1
 * are created for a bpf prog.
 */
__attribute__((used)) static int dummy(void)
{
	static const char res_kernel[16] __attribute__((used, section(".rodata"))) = KEXEC_RES_KERNEL_NAME;
	static char local_name[16] __attribute__((used, section(".data"))) = KEXEC_RES_CMDLINE_NAME;
	static char res_cmdline[16] __attribute__((used, section(".bss")));

	__builtin_memcpy(local_name, KEXEC_RES_INITRD_NAME, 16);
	return __builtin_memcmp(local_name, res_kernel, 4);
}

extern int bpf_kexec_carrier(const char *name, struct mem_range_result *map_value) __weak __ksym;

//Verify whether it is exported or not
//  bpftool btf dump file /sys/kernel/btf/vmlinux | grep kexec_decompress
//    [71386] FUNC 'bpf_kexec_decompress' type_id=71385 linkage=static
//
//  bpftool btf dump file /sys/kernel/btf/vmlinux format c | grep kexec_decompress
extern struct mem_range_result *bpf_kexec_decompress(char *image_gz_payload, int image_gz_sz, unsigned int expected_decompressed_sz) __weak __ksym;
extern int bpf_kexec_result_release(struct mem_range_result *result) __weak __ksym;



/* see drivers/firmware/efi/libstub/zboot-header.S */
struct linux_pe_zboot_header {
	unsigned int mz_magic;
	char image_type[4];
	unsigned int payload_offset;
	unsigned int payload_size;
	unsigned int reserved[2];
	char comp_type[4];
	unsigned int linux_pe_magic;
	unsigned int pe_header_offset;
} __attribute__((packed));


SEC("fentry/bpf_handle_pefile")
int BPF_PROG(parse_pe, char *image_buf, unsigned int image_sz, char *unused_initrd,
		unsigned int unused_initrd_sz, char *unused_cmd)
{
	struct linux_pe_zboot_header *zboot_header;
	char *image_gz_payload;
	int image_gz_sz;
	unsigned int decompressed_sz;
	char *decompressed_buf;
	char *buf;
	unsigned int key = 0;
	char local_name[32];

	bpf_printk("begin parse PE\n");
	/* BPF verifier should know each variable initial state */
	if (!image_buf || (image_sz > MAX_RECORD_SIZE)) {
		bpf_printk("Err: image size is greater than 0x%lx\n", MAX_RECORD_SIZE);
		return 0;
	}

	/* In order to access bytes not aligned on 2 order, copy into ringbuf */
	buf = (char *)bpf_ringbuf_reserve(&ringbuf_1, sizeof(struct linux_pe_zboot_header), 0);
	if (!buf) {
	    	bpf_printk("Err: fail to reserve ringbuf to parse zboot header\n");
		return 0;
	}
	/* Ensure the second parameter for bpf_probe_read() is Positive */
	image_sz = image_sz & (MAX_RECORD_SIZE - 1);
	bpf_probe_read((void *)buf, sizeof(struct linux_pe_zboot_header), image_buf);
	zboot_header = (struct linux_pe_zboot_header *)buf;
	if (!!__builtin_memcmp(&zboot_header->image_type, "zimg",
			sizeof(zboot_header->image_type))) {
	    	bpf_printk("Err: image is not zboot image\n");
		bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
		return 0;
	}

	unsigned int payload_offset = zboot_header->payload_offset;
	unsigned int payload_size = zboot_header->payload_size;
	bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
	image_gz_sz = payload_size - 4;
	if (image_gz_sz <= 0 || image_gz_sz + 4 > image_sz) {
		bpf_printk("Invalid offset for decompressed size\n");
		return 0;
	}
	/* Ensure the boundary to make verifier satisfied */
	unsigned int d_pos = (payload_offset + image_gz_sz) & (MAX_RECORD_SIZE - 1);
	/* appended le32 is the size */
	bpf_probe_read((void *)&decompressed_sz, sizeof(int), image_buf + d_pos);
	decompressed_sz = le32toh(decompressed_sz);
	bpf_printk("payload_offset:0x%lx, payload_size:0x%lx, decompressed size:0x%lx\n",
			payload_offset, payload_size, decompressed_sz);
	if (decompressed_sz == 0) {
	    	bpf_printk("decompressed size %d is wrong\n", decompressed_sz);
		return 0;
	}

	/* Strict check on pointer */
	if (payload_offset >= MAX_RECORD_SIZE ) {
		bpf_printk("Err: payload_offset > 0x%lx\n", MAX_RECORD_SIZE);
		return 0;
	}
	buf = (char *)bpf_ringbuf_reserve(&ringbuf_1, MAX_RECORD_SIZE, 0);
	if (!buf) {
		bpf_printk("Err: fail to reserve from ringbuf_1 for reading payload\n");
		return 0;
	}
	bpf_probe_read((void *)buf, payload_size, image_buf + payload_offset);
	bpf_printk("Calling bpf_kexec_decompress()\n");
	struct mem_range_result *r = bpf_kexec_decompress(buf, payload_size - 4, decompressed_sz);
	bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
	if (!r) {
		bpf_printk("Err: fail to decompress\n");
		return 0;
	}

	bpf_printk("Calling bpf_kexec_carrier()\n");
	/* Verifier is unhappy to expose .rodata.str1.1 'map' to kernel */
	__builtin_memcpy(local_name, KEXEC_RES_KERNEL_NAME, 32);
	const char *res_name = local_name;
	bpf_kexec_carrier(res_name, r);
	bpf_kexec_result_release(r);

	return 0;
}

SEC("fentry/bpf_post_handle_pefile")
int BPF_PROG(post_parse_pe, char *image_buf, int buf_sz)
{
	return 0;
}
