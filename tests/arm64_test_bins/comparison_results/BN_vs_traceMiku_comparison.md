# Binary Ninja vs traceMiku Decompiler Comparison

Generated: $(date)

## test_add — Arithmetic

**Source C:**
```c
int32_t test_add(int32_t a, int32_t b) { return a + b; }
```

**Binary Ninja HLIL:**
```
return zx.q(arg1 + arg2)
```
