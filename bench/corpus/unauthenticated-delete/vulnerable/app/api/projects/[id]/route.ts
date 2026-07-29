import { store } from '@/lib/store'

// The whole case, in eight lines: anyone on the internet can destroy any project by id.
// Nothing here is CONFIRMED — the absence of an auth token is not proof that the route is
// unauthenticated (LAW 1), so the grader raises a P1 at `needs-review`. Before LAW 4 the verdict
// counted only `confirmed` findings, so this repository graded 🟢 clean.
export async function DELETE(_req: Request, { params }: { params: { id: string } }) {
  store.remove(params.id)
  return new Response(null, { status: 204 })
}

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  return Response.json(store.get(params.id))
}
