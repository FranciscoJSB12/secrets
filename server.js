require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
//mongoose@6.10.1
const session = require("express-session");
const MongoDBStore = require("connect-mongodb-session")(session);
const bcrypt = require("bcrypt");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static("public"));
app.use(express.urlencoded({extended: true}));
app.set('view engine', 'ejs');

mongoose.set('strictQuery', true);

async function connectDB() {
  try {
     const conn =  await mongoose.connect(process.env.mongodb);
     console.log("MongoDB Connected: " + conn.connection.host);
    } catch(err) {
     console.log(err);
     process.exit(1);
    }
}

const store = new MongoDBStore({
  uri: process.env.mongodb,
  collection: 'mySessions'
});

app.use(session({
  secret: process.env.MYSECRET,
  resave: false,
  saveUninitialized: false, 
  store: store
}));

const isAuth = (req, res, next) => {
  if(req.session.isAuth) {
    next();
  } else {
    res.redirect("/login");
  }
};

const userSchema = new mongoose.Schema({
  username: String,
  password: String
});

const secretSchema = new mongoose.Schema({
  secret: String
});

const User = mongoose.model("User", userSchema);

const Secret = mongoose.model("Secret", secretSchema);

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", isAuth, function (req, res) {
  Secret.find({}, function(err, foundSecrets){
    res.render("secrets", {foundSecrets: foundSecrets});
  });
});

app.get("/logout", function (req, res) {
  req.session.destroy( (err) => {
    if(err) {
      console.log("Error");
    } else {
      res.redirect("/");
    }
  });
});

app.get("/submit", isAuth, function (req, res) {
  res.render("submit");
});

app.post("/register", function (req, res) {
  const {username, password} = req.body;
  User.findOne({username}, (err, foundUser) => {
    if (!err && !foundUser) {
      bcrypt.hash(password, 10)
      .then(function(password) {
        const user = new User({
          username,
          password
        });
        user.save();
        req.session.isAuth = true;
        res.redirect("/secrets");
      });
    } else {
      res.redirect("/register");
    }
  });
});

app.post("/login", function (req, res) {
  const {username, password} = req.body;
  User.findOne({username}, (err, foundUser) => {
    if(!foundUser || err) {
      res.redirect("/register");
    } else {
      bcrypt.compare(password, foundUser.password).then(function(result) {
        if(result) {
          req.session.isAuth = true;
          res.redirect("/secrets");
        } else {
          res.redirect("/login");
        }
      });
    }
  });
});

app.post("/submit", function(req, res){
  const newSecret = new Secret({secret: req.body.secret});
  newSecret.save();
  res.redirect("/secrets");
});

connectDB().then( function() {
  app.listen(PORT, function() {
    console.log("Server started. Listening on port " + PORT);
  });
});
  


       