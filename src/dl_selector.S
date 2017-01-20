.file "dl_selector.s"

.text
.globl	dl_selector
.type	dl_selector, @function

dl_selector:
	movq %r11, %rax		# %r11 contains the absolute address of the target API
	jmp *%rax			# Jump to the API

.size	dl_selector, .-dl_selector
