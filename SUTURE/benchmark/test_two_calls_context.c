struct Carrier {
    int *ptr;
    int value;
};

static void helper(struct Carrier *c) {
    if (c && c->ptr) {
        *c->ptr = c->value;
    }
}

int entry(int *user_ptr, int *kernel_ptr) {
    struct Carrier tainted;
    struct Carrier clean;

    tainted.ptr = user_ptr;
    tainted.value = 1;

    clean.ptr = kernel_ptr;
    clean.value = 2;

    helper(&tainted);
    helper(&clean);
    return 0;
}
