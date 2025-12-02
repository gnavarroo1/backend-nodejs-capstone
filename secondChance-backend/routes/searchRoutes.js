const express = require('express')
const router = express.Router()
const connectToDatabase = require('../models/db')
require('dotenv').config()

// Search for secondChanceItems
router.get('/', async (req, res, next) => {
  try {
    const db = await connectToDatabase()
    const collection = db.collection('secondChanceItems')

    const query = {}

    if (req.query.name && req.query.name.trim() !== '') {
      query.name = {
        $regex: req.query.name,
        $options: 'i'
      }
    }

    if (req.query.category) {
      query.category = req.query.category
    }
    if (req.query.condition) {
      query.condition = req.query.condition
    }
    if (req.query.age_years) {
      query.age_years = {
        $lte: parseInt(req.query.age_years)
      }
    }
    const secondChanceItems = await collection.find(query).toArray()
    res.json(secondChanceItems)
  } catch (e) {
    next(e)
  }
})

module.exports = router
