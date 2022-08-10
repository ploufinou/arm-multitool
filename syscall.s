.thumb

.global syscall4

syscall4:
	push {r4, r7}
	mov r7, r0
	mov r0, r1
	mov r1, r2
	mov r2, r3
	ldr r3, [sp, #0x8]
	mov r4, #0
	svc #0
	pop {r4, r7}
	bx lr

