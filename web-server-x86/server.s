.intel_syntax noprefix
.globl _start
.section .text

_start:
    #socket
    mov rax, 41          # SYS_socket
    mov rdi, 2           # AF_INET
    mov rsi, 1           # SOCK_STREAM
    mov rdx, 0           # IPPROTO_IP (usually defined as 0 for auto)
    syscall              # The file descriptor is returned in rax
    mov rbx, rax

    #bind
    mov rax, 49
    mov rdi, rbx
    #prepare weird object here
    lea rsi, [rip + sockaddr]
    mov rdx, 16
    syscall
    
    #listen
    mov rax, 50
    mov rdi, rbx
    mov rsi, 0
    syscall

accept_loop:
    #accept
    mov rax, 43
    mov rdi, rbx
    xor rsi, rsi
    xor rdx, rdx
    syscall
    mov r12, rax    #r12 stores 4


    #fork
    mov rax, 57
    syscall
    cmp rax, 0
    jne parent_process


child_process:
    #close
    mov rax, 3
    mov rdi, rbx
    syscall
   
    #read
    mov rax, 0
    mov rdi, r12
    lea rsi, [buffer]
    mov rdx, 1024          #doesn't matter atm
    syscall
    
    #jmp level9
    # Check if GET or POST
    cmp byte ptr [buffer], 'G'
    je level9
    cmp byte ptr [buffer], 'P'
    je level10


level9:
    #open
    mov rax, 2
    mov r10, rsi #parsing

find_start:
    cmp byte ptr [r10], ' '
    jz found_space
    inc r10
    jmp find_start

found_space:
    inc r10
    mov rdi, r10

find_end:
    cmp byte ptr [r10], ' '
    jz terminate
    inc r10
    jmp find_end

terminate:
    mov byte ptr [r10], 0
    mov rsi, 0
    syscall
    mov r8, rax     # r8 will store 5

    #read
    mov rax, 0
    mov rdi, r8
    lea rsi, [buffer]
    mov rdx, 1024
    syscall
    mov r15, rax


    #close
    mov rax, 3
    mov rdi, r8
    syscall

    #write     
    mov rax, 1 
    mov rdi, 4
    lea rsi, [http_response]
    mov rdx, 19
    syscall

    #write
    mov rax, 1
    mov rdi, 4
    lea rsi, [buffer]
    mov rdx, r15
    syscall

    #exit
    jmp finalize


################################


level10:
    #open
    mov rax, 2
    mov r10, rsi #parsing

find_start10:
    cmp byte ptr [r10], ' '
    jz found_space10
    inc r10
    jmp find_start10

found_space10:
    inc r10
    mov rdi, r10

find_end10:
    cmp byte ptr [r10], ' '
    jz terminate10
    inc r10
    jmp find_end10

terminate10:
    mov byte ptr [r10], 0
    mov rsi, 0x0001 | 0x0040
    mov rdx, 0777
    syscall
    mov r8, rax     # r8 will store 5

    lea rsi, [buffer + 176]   # Start position in the buffer
    lea rdi, [output_buffer]  # Target buffer start
    mov rcx, 0                # Character counter

copy_loop:
    mov al, [rsi]             # Load byte from source
    cmp al, 13                # Check if it's a carriage return
    je end_copy               # Jump to end if it is
    cmp rcx, 255              # Check if we're at output buffer capacity
    jae end_copy              # Stop if buffer is full
    mov [rdi], al             # Copy byte to target
    inc rsi                   # Increment source pointer
    inc rdi                   # Increment target pointer
    inc rcx                   # Increment counter
    jmp copy_loop             # Continue loop

end_copy:
    mov byte ptr [rdi], 0     # Null-terminate the output string

    # Convert string in output_buffer to an integer
    xor rax, rax              # Clear RAX to store the result
    lea rsi, [output_buffer]  # Load the address of output_buffer into RSI

convert_to_int:
    movzx rdx, byte ptr [rsi] # Load the next byte from the string
    test rdx, rdx             # Test if it's the null terminator
    jz continue_here
    sub rdx, '0'              # Convert ASCII to integer
    imul rax, rax, 10         # Multiply current result by 10
    add rax, rdx              # Add new digit
    inc rsi                   # Move to the next character
    jmp convert_to_int        # Repeat

continue_here:
    mov r14, rax

    #write
    mov rax, 1
    mov rdi, 3
    # Check the character at buffer + 183
    movzx rcx, byte ptr [buffer + 182]  # Load the byte at buffer + 183 into rcx
    cmp cl, 10                # Compare cl with 10 (newline character '\n')
    je adjust_for_newline     # If it is a newline, adjust the pointer

    # If not a newline, use buffer + 182
    lea rsi, [buffer + 182]   # Set source pointer to buffer + 182
    jmp prepare_write         # Skip to writing

adjust_for_newline:
    # If it is a newline, use buffer + 183
    lea rsi, [buffer + 183]   # Set source pointer to buffer + 183

prepare_write:
    # Set the length of data to write from r14 and perform the syscall
    mov rdx, r14              # Length of data to write from content-length
    syscall                   # Perform the write

    #close
    mov rax, 3
    mov rdi, r8
    syscall

    #write
    mov rax, 1
    mov rdi, 4
    lea rsi, [http_response]
    mov rdx, 19
    syscall
    jmp finalize

finalize:
    #close
    mov rax, 3
    mov rdi, r12
    syscall

    #exit
    mov rdi, 0
    mov rax, 60     # SYS_exit
    syscall



parent_process:
    #close 4
    mov rax, 3
    mov rdi, r12
    syscall

    #accept
    jmp accept_loop

    #exit
    mov rdi, 0
    mov rax, 60     # SYS_exit
    syscall

.section .data
sockaddr:
    .word 2                  # sin_family, AF_INET
    .word 0x5000                 # sin_port, port 80 (need to convert to network byte order)
    .long 0                  # sin_addr, 0.0.0.0 (INADDR_ANY, already in network byte order)
    .zero 8                  # sin_zero
output_buffer:
    .space 256


http_response:
    .ascii "HTTP/1.0 200 OK\r\n\r\n"

.section .bss
buffer:
    .space 1024
buffer2:
    .space 1024 
