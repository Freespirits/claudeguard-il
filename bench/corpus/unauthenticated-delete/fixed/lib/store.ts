// A plain in-memory store, so nothing in this fixture is a database finding. The point of the
// case is the HTTP surface, not the persistence layer.
const projects = new Map<string, { id: string, ownerId: string, name: string }>()

export const store = {
  get: (id: string) => projects.get(id) ?? null,
  removeOwned: (id: string, ownerId: string) => {
    const p = projects.get(id)
    if (!p || p.ownerId !== ownerId) return false
    return projects.delete(id)
  },
}
