# Improvments

## `USER_FAST_ACQUIRE`

It's possible to enhance the fuzzing speed by leveraging a specific hypercall in kAFL's API: [`USER_FAST_ACQUIRE`](../../../reference/hypercall_api.md#user_fast_acquire).

Rewriting the harness with this hypercall:

```{code-block} C
---
linenos: true
caption: Updated selffuzz.c harness with USER_FAST_ACQUIRE
---
kAFL_hypercall(HYPERCALL_KAFL_USER_FAST_ACQUIRE, 0);
fuzzme(payload_buffer->data, payload_buffer->size);
kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
```
