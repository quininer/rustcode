#include <linux/module.h>

extern int init_mod(void);
extern void exit_mod(void);

static int {ko}_init(void) {
    return init_mod();
}

static void {ko}_exit(void) {
    return exit_mod();
}

module_init({ko}_init);
module_exit({ko}_exit);

MODULE_LICENSE("Dual BSD/GPL");
