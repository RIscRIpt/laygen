extern "C" {
int _fltused = 0;
}

struct S {
    int a[4];
    char const *b;
    double c;
    float d;
};

struct U {
    unsigned int a;
    float b;
    double c;
};

struct T {
    int a;
    unsigned int b;
    S *s;
    U *u;
};

long long hash(long long v)
{
    return v * 0x5851F42D4C957F2D + 0x14057B7EF767814F;
}

int baz(int a, int b, int c, int d, U *u)
{
    a ^= hash(u->a);
    b ^= hash(static_cast<int>(1.0f / u->b));
    c ^= hash(static_cast<int>(1.0 / u->c));
    return a ^ b ^ c ^ d;
}

int bar(S *s)
{
    int result = 0;
    for (int i = 0; i < 4; i++) {
        result ^= hash(s->a[i]);
        result ^= hash(s->b[i]);
    }
    result %= static_cast<int>(1.0f / (s->c * s->d));
    return result;
}

int foo(T *t)
{
    int x = bar(t->s);
    int y = baz(hash(0), hash(1), hash(2), hash(3), t->u);
    return ((x ^ y) * t->a) % t->b;
}

int main()
{
    S s;
    T t;
    U u;
    char h[5];
    for (int i = 0; i < 4; i++) {
        s.a[i] = hash(i);
        h[i] = 'A' + s.a[i] % ('Z' - 'A');
    }
    h[4] = '\0';
    s.b = h;
    s.c = 0.1;
    s.d = 0.1;
    u.a = 1;
    u.b = 0.1;
    u.c = 0.1;
    t.a = -1;
    t.b = 1;
    t.s = &s;
    t.u = &u;
    return foo(&t);
}
