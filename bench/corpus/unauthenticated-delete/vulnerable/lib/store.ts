// A plain in-memory store, so nothing in this fixture is a database finding. The point of the
// case is the HTTP surface, not the persistence layer.
const projects = new Map<string, { id: string, name: string }>()

export const store = {
  get: (id: string) => projects.get(id) ?? null,
  remove: (id: string) => projects.delete(id),
}
