extern "C" {
int _fltused = 0;
}

struct S {
    int a[4];
    char const *b;
    float c;
};

struct T {
    int x[4];
    S *s;
};

long long hash(long long v)
{
    return v * 0x5851F42D4C957F2D + 0x14057B7EF767814F;
}

int test(int a, int b, int c, int d, S const &s)
{
    int x[4] = { a, b, c, d };
    int result = 0;
    for (int i = 0; i < 4; i++) {
        result ^= hash(s.a[i]);
        result ^= hash(s.b[i]);
        result ^= x[i];
    }
    result %= static_cast<int>(1.0f / s.c);
    return result;
}

int foo(int a, int b, int c, int d, T &t)
{
    for (int i = 0; i < 4; i++) {
        t.x[i] ^= hash(t.s->a[i]) ^ hash(t.s->b[i]);
    }
    return test(a, b, c, d, *t.s);
}

int main()
{
    S s;
    T t;
    char h[5];
    for (int i = 0; i < 4; i++) {
        s.a[i] = hash(i);
        h[i] = 'A' + s.a[i] % ('Z' - 'A');
    }
    h[4] = '\0';
    s.b = h;
    s.c = 0.01;
    t.s = &s;
    return foo(s.a[0], s.a[1], s.a[2], s.a[3], t);
}
