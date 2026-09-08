extern void start(void);
__asm__(".global __chkstk\n\t"
        "__chkstk:\n\t"
        "jmp ___chkstk_ms\n\t");
int main(void){start();return 0;}
