const express = require('express')
const rateLimit = require('express-rate-limit')
const { z } = require('zod')
const { db } = require('./db')
const { requireAuth } = require('./auth')

const app = express()
app.use(express.json())
app.use(rateLimit({ windowMs: 60_000, max: 60 }))
app.use(requireAuth)

const OrderSchema = z.object({ item: z.string(), qty: z.number().int().positive() })

app.get('/api/orders/:id', async (req, res) => {
  res.json(await db.orders.findForUser(req.params.id, req.user.id))
})

app.post('/api/orders', async (req, res) => {
  const body = OrderSchema.parse(req.body)
  res.json(await db.orders.insert({ ...body, user_id: req.user.id }))
})

app.delete('/api/orders/:id', async (req, res) => {
  res.json(await db.orders.removeForUser(req.params.id, req.user.id))
})

app.listen(3000)
