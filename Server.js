// server.js

const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

// connect to MongoDB database
mongoose.connect("mongodb://127.0.0.1/myapp", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// create a schema for User
const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
});

// create a model for User
const User = mongoose.model("User", userSchema);

// create a schema for Card
const cardSchema = new mongoose.Schema(
  {
    title: String,
    description: String,
    category: String,
    projectName: String,
  },
  { timestamps: true }
);

// create a model for Card
const Card = mongoose.model("Card", cardSchema);

// middleware to parse request body
app.use(bodyParser.json());

// API endpoints for User
app.post("/signup", (req, res) => {
  const { username, email, password } = req.body;
  const saltRounds = 10;
  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) {
      res.status(500).send(err);
    } else {
      const newUser = new User({ username, email, password: hashedPassword });
      newUser.save((err, user) => {
        if (err) {
          res.status(400).send(err);
        } else {
          res.send(user);
        }
      });
    }
  });
});

app.post("/signin", (req, res) => {
  const { email, password } = req.body;
  User.findOne({ email }, (err, user) => {
    if (err) {
      res.status(400).send(err);
    } else if (!user) {
      res.status(401).send("Invalid email or password");
    } else {
      bcrypt.compare(password, user.password, (err, result) => {
        if (err) {
          res.status(500).send(err);
        } else if (!result) {
          res.status(401).send("Invalid email or password");
        } else {
          const token = jwt.sign({ email }, "secret", { expiresIn: "1h" });
          res.send({ token });
        }
      });
    }
  });
});

app.post("/forgotpassword", (req, res) => {
  const { email } = req.body;
  User.findOne({ email }, (err, user) => {
    if (err) {
      res.status(400).send(err);
    } else if (!user) {
      res.status(404).send("User not found");
    } else {
      res.send("Email sent to reset password");
    }
  });
});

// middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    res.status(401).send("Unauthorized access");
  } else {
    jwt.verify(token, "secret", (err, decodedToken) => {
      if (err) {
        res.status(401).send("Unauthorized access");
      } else {
        req.email = decodedToken.email;
        next();
      }
    });
  }
};

// API endpoint for Card
app.post("/addcard", verifyToken, (req, res) => {
  const { title, description, category } = req.body;
  const newCard = new Card({ title, description, category });
  newCard.save((err, card) => {
    if (err) {
      res.status(400).send(err);
    } else {
      res.send(card);
    }
  });
});

app.get("/listboard", verifyToken, (req, res) => {
  Card.find({})
    .sort({ createdAt: "desc" }) // Sort by createdAt in descending order
    .exec((err, cards) => {
      if (err) {
        res.status(400).send(err);
      } else {
        res.send(cards);
      }
    });
});

// start the server
app.listen(3000, () => {
  console.log("Server listening on port 3000");
});
