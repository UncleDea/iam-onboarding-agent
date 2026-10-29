# Build order

Each file is written, then implemented, then checked with:

```
python -m unittest discover -s tests
```

The next component starts only after that suite is green.

1. [01-policy-and-approval.md](01-policy-and-approval.md) — policy file and loader first; approval follows in the same area once the loader is green
2. [02-execution.md](02-execution.md)
3. [03-entra.md](03-entra.md)
4. [04-audit-health-auth.md](04-audit-health-auth.md)
5. [05-product.md](05-product.md)
6. [06-removals.md](06-removals.md)
7. [07-groups.md](07-groups.md) — read-only group membership, after the product is in use
