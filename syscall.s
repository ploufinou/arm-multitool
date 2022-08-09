.thumb

.global syscall

syscall:
	push {r4, r7}
	mov r7, r0
	mov r0, r1
	mov r1, r2
	mov r2, r3
	ldr r3, [sp, #0x8]
	ldr r4, [sp, #0xC]
	svc #0
	pop {r4, r7}
	bx lr

