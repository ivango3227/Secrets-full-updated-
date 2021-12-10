require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const ejs = require("ejs");
const encrypt = require("mongoose-encryption");
const app = express();
const md5 = require("md5");
//const bcrypt = require('bcrypt');
//const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate= require("mongoose-findorcreate");

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
mongoose.connect('mongodb://localhost:27017/userDB', {
  useNewUrlParser: true
});
app.use(express.static("public"));
app.use(session({
  secret: "Our little secret",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID:process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));




const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId:String,
  secret: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);
//*****passport local mongoose**************
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
//**********LOCAL STRATEGY*********************
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

app.get("/", function(req, res) {
  res.render("home.ejs");
})

app.get("/auth/google", passport.authenticate('google', {

    scope: ['profile']

}));

app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });



app.get("/login", function(req, res) {
  res.render("login.ejs");
})

app.get("/register", function(req, res) {
  res.render("register.ejs");
})

app.get("/secrets", function(req, res) {
    User.find({
      "secret": {
        $ne: null
      }
    }, function(err, foundUsers) {
      if (err) {
        console.log(err);
      } else {
        if (foundUsers) {
          res.render("secrets", {
            usersWithSecrets: foundUsers
          });
        }

    }

});
})

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
      res.render("submit");
    } else {
    res.redirect("/login");
  }
})

app.post("/submit",function(req,res){
const submittedSecret=req.body.secret;
console.log(req.user);
User.findById(req.user.id,function(err,foundUser){
  if(err){
    console.log(err);
  } else {
    if(foundUser){
      foundUser.secret=submittedSecret;
      foundUser.save(function(){
        res.redirect("/secrets");
      });

    }
  }
});
})


app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
})


app.post("/register", function(req, res) {
  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local", function(err, user) {
        if (err) {
          console.log(err);
        } else {
          if (user) {
            req.login(user, function(err) {
              res.redirect("/secrets");

            });

          } else {
            res.redirect("/login");
          }
        }
      })(req, res);
    }
  });
})

app.post("/login", function(req, res) {
  //check the DB to see if the username that was used to login exists in the DB
  User.findOne({
    username: req.body.username
  }, function(err, foundUser) {
    //if username is found in the database, create an object called "user" that will store the username and password
    //that was used to login
    if (foundUser) {
      const user = new User({
        username: req.body.username,
        password: req.body.password
      });
      //use the "user" object that was just created to check against the username and password in the database
      //in this case below, "user" will either return a "false" boolean value if it doesn't match, or it will
      //return the user found in the database
      passport.authenticate("local", function(err, user) {
        if (err) {
          console.log(err);
        } else {
          //this is the "user" returned from the passport.authenticate callback, which will be either
          //a false boolean value if no it didn't match the username and password or
          //a the user that was found, which would make it a truthy statement
          if (user) {
            //if true, then log the user in, else redirect to login page
            req.login(user, function(err) {
              res.redirect("/secrets");
            });
          } else {
            res.redirect("/login");
          }
        }
      })(req, res);
      //if no username is found at all, redirect to login page.
    } else {
      //user does not exists
      res.redirect("/login")
    }
  });
});

app.listen(3000, function() {
  console.log("server is running on port 3000");
})
