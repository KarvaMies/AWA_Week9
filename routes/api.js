require('dotenv').config();
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const {body, validationResult } = require("express-validator");
const User = require("../models/User");
const jwt = require("jsonwebtoken");
const validateToken = require("../auth/validateToken.js")

router.use(express.json());

router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.post("/user/register",
  body("email").isLength({min: 3}).trim().escape(),
  body("password").isLength({min: 5}),
  (req, res, next) => {
  console.log("Trying to add new user");
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  User.findOne({ email: req.body.email }, (err, user) => {
    if (err) {
      console.log(err);
      throw err;
    };
    if (user) {
      return res.status(403).json({ email: "Email already in use." });
    } else {
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(req.body.password, salt, (err, hash) => {
          if (err) throw err;
          User.create(
            {
              email: req.body.email,
              password: hash
            },
            (err, ok) => {
              if (err) throw err;
              console.log({ email: req.body.email, password: hash })
              return res.status(200).send("ok")
            }
          )
        })
      })
    }
  })
});


router.get("/user/list", async (req, res) => {
  const users = await User.find();
  console.log("User list:")
  res.json(users);
})



router.post("/user/login", 
  body("username").trim().escape(),
  body("password"),
  (req, res, next) => {
  console.log("Trying to login");
  User.findOne({ email: req.body.email }, (err, user) => {
    if (err) throw err;
    if (!user) {
      return res.status(403).json({ message: "Invalid email and/or password."})
    } else {
      bcrypt.compare(req.body.password, user.password, (err, isMatch) => {
        if (err) throw err;
        if (isMatch) {
          const jwtPayload = {
            id: user._id,
            email: user.email
          }
          jwt.sign(jwtPayload, process.env.SECRET, { expiresIn: 120 }, (err, token) => {
            console.log("Logging in:")
            console.log({ success: true, token });
            res.json({ success: true, token });
          })
        }
      })
    }
  })
});

router.get("/private", validateToken, (req, res) => {
  res.json({ email: req.user.email})
})

module.exports = router;
