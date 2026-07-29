exports.requireAuth = function requireAuth(req, res, next) {
  const session = getServerSession(req)
  if (!session) return res.status(401).json({ error: 'unauthenticated' })
  req.user = session.user
  next()
}
