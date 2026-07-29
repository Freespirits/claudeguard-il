const express = require('express')
const { db } = require('./db')

const app = express()
app.use(express.json())

app.get('/api/orders/:id', async (req, res) => {
  res.json(await db.orders.find(req.params.id))
})

app.post('/api/orders', async (req, res) => {
  res.json(await db.orders.insert(req.body))
})

app.delete('/api/orders/:id', async (req, res) => {
  res.json(await db.orders.remove(req.params.id))
})

app.listen(3000)
