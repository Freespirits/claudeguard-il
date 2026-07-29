# Guard: business-logic intent

The business-logic audit checks your code against what your app is *supposed to permit* — and only
you can state that. These recipes cover the two fixes it asks for: writing the intent file, and
enforcing a state transition server-side.

<a id="intent-file"></a>
## Confirm the intent file (turns guesses into a review)

When no `claudeguard.intent.yml` exists, the audit still runs — against an ownership model the tool
*guessed* from column names. A guess that happens to match your code produces a clean section that
means nothing. Confirming the file is what anchors every business-logic conclusion.

The tool prints a proposed draft (`node grader.mjs <path> --propose-intent`). Save it at the repo
root, correct it, commit it:

```yaml
# claudeguard.intent.yml
roles: [anonymous, user, admin]
default_role: user

resources:
  orders:
    owned_by: user_id                    # a user may touch only rows where user_id = them
    tenant: null                         # not a multi-tenant resource
    state_column: status
    states: [cart, placed, paid, shipped, cancelled]
    transitions:                         # who may move an order between states
      placed->paid: [system]             # only the payment webhook, never the user
      placed->cancelled: [user, admin]
      any->shipped: [admin]
    mutable_fields: [item, quantity]     # fields a user may set; price/total are NOT here
  profiles:
    owned_by: id
  invoices:
    owned_by: user_id
    read_only_for: [user]                # users read theirs; only the system writes them

rules:
  - "A coupon code may be applied at most once per order."

system_routes:
  - "pages/api/webhooks/**"              # driven by the system, not by a user
```

Three rules of thumb:

- **State what is true, not what is aspirational.** The audit reports where code diverges from this
  file; a wishful `owned_by` produces findings about a model you do not actually have.
- **A rule you do not state is reported as `undeterminable`, never as passing.** Leaving
  `mutable_fields` out does not make the tampering check pass — it makes it declared unanswerable.
- **List webhooks and cron handlers under `system_routes`.** A payment webhook legitimately writes
  `status = 'paid'`; without the listing, that correct write is reported as a user-driven one.

<a id="state-transitions"></a>
## Enforce a state transition server-side

The intent says only the system may mark an order paid. The enforcement has to live where the write
happens — the client not offering a button is not a control.

```ts
// app/api/orders/[id]/route.ts — the USER-facing route must not accept a status at all.
const Update = z.object({ item: z.string(), quantity: z.number().int().min(1) }) // no `status`
const patch = Update.parse(await req.json())
await supabase.from('orders').update(patch).eq('id', params.id)
```

```ts
// app/api/webhooks/payment/route.ts — the SYSTEM route verifies the caller, then transitions.
const sig = req.headers.get('stripe-signature')
const event = stripe.webhooks.constructEvent(await req.text(), sig, process.env.STRIPE_WEBHOOK_SECRET)
// Guard the ORDER of states too: only a placed order becomes paid.
await supabase.from('orders')
  .update({ status: 'paid' })
  .eq('id', event.data.object.metadata.order_id)
  .eq('status', 'placed')
```

For defence in depth, make the database itself refuse an illegal transition, so a forgotten check in
a future route cannot skip a step:

```sql
create function public.enforce_order_transitions()
returns trigger language plpgsql security invoker as $$
begin
  if old.status = 'placed' and new.status in ('paid', 'cancelled') then return new; end if;
  if old.status = 'paid' and new.status = 'shipped' then return new; end if;
  if old.status = new.status then return new; end if;
  raise exception 'illegal order transition: % -> %', old.status, new.status;
end;
$$;

create trigger order_transitions before update of status on public.orders
for each row execute function public.enforce_order_transitions();
```

The trigger enforces the *order* of states for everyone. *Who* may drive each transition stays in
the route (webhook signature, role check — see
[auth-middleware.md](auth-middleware.md#role-check)), because `security invoker` triggers run as the
caller and a role check inside one would need the caller's identity anyway.
