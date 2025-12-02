/*jshint esversion: 8 */
const express = require("express")
const router = express.Router()
// Step 1 - Task 2: Import necessary packages
const bcryptjs = require("bcryptjs")
const jwt = require("jsonwebtoken")
const { body, validationResult } = require("express-validator")
const connectToDatabase = require("../models/db")
const dotenv = require("dotenv")
// Import Pino logger
const pino = require("pino")

// Step 1 - Task 3: Create a Pino logger instance
const logger = pino()

dotenv.config()

// Step 1 - Task 4: Create JWT secret
const JWT_SECRET = process.env.JWT_SECRET

// Basic validations for register
const registerValidation = [
  body("email").isEmail().withMessage("Valid email required"),
  body("password")
    .isLength({
      min: 6,
    })
    .withMessage("Password must be at least 6 characters"),
  body("firstName")
    .isString()
    .trim()
    .notEmpty()
    .withMessage("First name is required"),
  body("lastName")
    .isString()
    .trim()
    .notEmpty()
    .withMessage("Last name is required"),
]

// /register endpoint
router.post("/register", registerValidation, async (req, res) => {
  try {
    // Validate inputs
    const errors = validationResult(req)
    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
      })
    }

    if (!JWT_SECRET) {
      logger.error("JWT_SECRET is not configured")
      return res.status(500).send("Server configuration error")
    }

    const db = await connectToDatabase()
    const collection = db.collection("users")
    const existingEmail = await collection.findOne({
      email: req.body.email,
    })
    if (existingEmail) {
      logger.warn(
        {
          email: req.body.email,
        },
        "Email already registered"
      )
      return res.status(400).json({
        error: "Email already registered",
      })
    }
    const salt = await bcryptjs.genSalt(10)
    const hash = await bcryptjs.hash(req.body.password, salt)
    const email = req.body.email

    const newUser = await collection.insertOne({
      email: req.body.email,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      password: hash,
      createdAt: new Date(),
    })

    const payload = {
      user: {
        id: newUser.insertedId,
      },
    }
    const authtoken = jwt.sign(payload, JWT_SECRET)
    logger.info("User registered successfully")
    return res.json({
      authtoken,
      email,
    })
  } catch (e) {
    return res.status(500).send("Internal server error")
  }
})

// /login endpoint
router.post("/login", async (req, res) => {
  try {
    if (!JWT_SECRET) {
      logger.error("JWT_SECRET is not configured")
      return res.status(500).send("Server configuration error")
    }

    const db = await connectToDatabase()
    const collection = db.collection("users")
    const theUser = await collection.findOne({
      email: req.body.email,
    })

    if (theUser) {
      let result = await bcryptjs.compare(req.body.password, theUser.password)
      if (!result) {
        logger.error("Passwords do not match")
        return res.status(404).json({
          error: "Wrong pasword",
        })
      }
      let payload = {
        user: {
          id: theUser._id.toString(),
        },
      }
      const userName = theUser.firstName
      const userEmail = theUser.email
      const authtoken = jwt.sign(payload, JWT_SECRET)
      logger.info("User logged in successfully")
      return res.status(200).json({
        authtoken,
        userName,
        userEmail,
      })
    } else {
      logger.error("User not found")
      return res.status(404).json({
        error: "User not found",
      })
    }
  } catch (e) {
    logger.error(
      {
        err: e,
      },
      "Internal server error in /login"
    )
    return res.status(500).send("Internal server error")
  }
})

// /update endpoint - update user profile (e.g., first name)
router.put(
  "/update",
  [body("name").isString().trim().notEmpty().withMessage("Name is required")],
  async (req, res) => {
    try {
      const errors = validationResult(req)
      if (!errors.isEmpty()) {
        logger.error("Validation errors in update request", errors.array())
        return res.status(400).json({
          errors: errors.array(),
        })
      }

      if (!JWT_SECRET) {
        logger.error("JWT_SECRET is not configured")
        return res.status(500).send("Server configuration error")
      }

      const email = req.headers.email
      if (!email) {
        logger.error("Email not found in the request headers")
        return res.status(400).json({
          error: "Email not found in the request headers",
        })
      }
      const db = await connectToDatabase()
      const collection = db.collection("users")
      const existingUser = await collection.findOne({
        email,
      })
      if (!existingUser) {
        logger.error(
          {
            email,
          },
          "User not found for update"
        )
        return res.status(404).json({
          error: "User not found",
        })
      }

      existingUser.firstName = req.body.name || existingUser.firstName
      existingUser.updatedAt = new Date()

      const result = await collection.findOneAndUpdate(
        {
          email,
        },
        {
          $set: existingUser,
        },
        {
          returnDocument: "after",
        }
      )

      const updatedUser = result && result.value ? result.value : existingUser

      const payload = {
        user: {
          id: updatedUser._id.toString(),
        },
      }
      const authtoken = jwt.sign(payload, JWT_SECRET)

      logger.info(
        {
          email,
        },
        "User profile updated successfully"
      )
      return res.json({
        authtoken,
        userName: updatedUser.firstName,
        userEmail: updatedUser.email,
      })
    } catch (e) {
      logger.error(
        {
          err: e,
        },
        "Internal server error in /update"
      )
      return res.status(500).send("Internal server error")
    }
  }
)

module.exports = router
