#include <stdio.h>
extern void report(const char* msg);
void start(void) {
    report("hello from test");
}
int main(void) { start(); return 0; }
