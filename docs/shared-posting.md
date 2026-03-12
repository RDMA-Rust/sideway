# Relaxing `start_post_send` from `&mut self` to `&self`

## Current state

```rust
// QueuePair trait (line 385)
fn start_post_send(&mut self) -> Self::Guard<'_>;
```

`ExtendedQueuePair` already declares `unsafe impl Send` and `unsafe impl Sync`
(line 684-685), yet `start_post_send(&mut self)` prevents using the QP through a
shared reference.  The `&mut` makes `Sync` a dead letter.

## Proposal

Change the trait method to `&self`:

```rust
fn start_post_send(&self) -> Self::Guard<'_>;
```

Update both implementors (`ExtendedQueuePair`, `BasicQueuePair`) and the
`GenericQueuePair` dispatch accordingly.

## Why `&mut` is unnecessary

### ExtendedQueuePair (new posting API)

`start_post_send` calls `ibv_wr_start`, which acquires a **provider-internal
per-QP lock** (see `ibv_wr_post(3)`, CONCURRENCY section):

> The provider will provide locking to ensure that `ibv_wr_start()` and
> `ibv_wr_complete()`/`abort()` form a per-QP critical section where no other
> threads can enter.

So the provider already serializes concurrent `start_post_send` calls:

```
Thread A: ibv_wr_start()    — acquires provider lock
Thread B: ibv_wr_start()    — blocks until A's ibv_wr_complete()
Thread A: construct_wr(), setup_sge(), ...
Thread A: ibv_wr_complete() — posts batch, releases lock
Thread B: ibv_wr_start()    — proceeds
```

The guard (`ExtendedPostSendGuard`) holds a copied `NonNull<ibv_qp_ex>` — it
does not carry the `&mut` borrow beyond the PhantomData lifetime tie. All
mutable state (`wr_id`, `wr_flags`, `cur_post`) lives behind the C pointer and
is protected by the provider lock.

### BasicQueuePair (legacy posting API)

`start_post_send` does no FFI — it creates a `BasicPostSendGuard` with a copied
`NonNull<ibv_qp>` and **fresh, owned** `Vec`s for work requests and SGEs. Two
concurrent guards would operate on completely independent WR lists. The final
`ibv_post_send` call is documented as thread-safe on the same QP.

### The guard already prevents double-start within a single thread

Even with `&self`, Rust's borrow rules on the returned guard prevent misuse
within a single thread:

```rust
let guard1 = qp.start_post_send(); // borrows &'_ self
let guard2 = qp.start_post_send(); // fine — &self is re-borrowable
// But guard1 and guard2 can coexist safely because:
// - Extended: provider lock serializes ibv_wr_start (guard2 blocks)
// - Basic: independent Vec buffers, ibv_post_send is thread-safe
```

## What about `ibv_td` (thread domain)?

The `ibv_td` opt-out disables the provider lock for maximum posting throughput
when the caller guarantees single-threaded access. If a QP is created with
`ibv_td`, concurrent `&self` posting would be unsound.

This is already an `unsafe` contract at QP creation time. We can document it:

> If the QP was created with an `ibv_td`, the caller must ensure exclusive access
> externally (e.g., via `Mutex` or single-threaded ownership). The `Sync` impl
> on `ExtendedQueuePair` assumes the default provider-locked mode.

Sideway does not currently expose `ibv_td` in QP creation, so this is a future
concern.

## Changes required

### `src/ibverbs/queue_pair.rs`

| Location | Change |
|----------|--------|
| Trait `QueuePair::start_post_send` (line 385) | `&mut self` → `&self` |
| `ExtendedQueuePair` impl (line 703) | `&mut self` → `&self` |
| `BasicQueuePair` impl (line 653) | `&mut self` → `&self` |
| `GenericQueuePair` dispatch (line 1775) | `&mut self` → `&self` |
| Guard `PhantomData<&'qp ()>` | Already uses shared ref — no change |

### Downstream impact (aquifer)

With `&self` on `start_post_send`, `QpHandle::post_read` can take `&self`
instead of `&mut self`. This enables:

1. **Shared QP access** — no `&mut` borrow conflicts in the UFFD handler; the
   scoped `Prefetcher` block becomes unnecessary.
2. **Cross-thread posting** — async RDMA prefetch can spawn a thread that posts
   reads via `Arc<QpHandle>`, with the provider lock handling serialization.
3. **Batched posting** — the lock is held for the entire start→complete span,
   so batching N reads into one guard amortizes both lock and doorbell overhead.

## Risk

None for the default (non-`ibv_td`) path. The provider lock is unconditional.
The only risk is a future `ibv_td` API in sideway, which would need to document
the single-threaded requirement or gate it behind an `unsafe` constructor.
