//jshint esversion:6
require('dotenv').config();
const express=require("express");
const bodyParser=require("body-parser");
const mongoose= require("mongoose");
const ejs=require("ejs");
const encrypt = require("mongoose-encryption");
const app=express();
const md5=require("md5");
const bcrypt = require('bcrypt');
const saltRounds = 10;

app.set('view engine', 'ejs');
mongoose.connect('mongodb://localhost:27017/userDB',{useNewUrlParser:true});
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

const userSchema=new mongoose.Schema({
  email: String,
  password: String
});
//userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]})
const User= new mongoose.model("User",userSchema);
 app.get("/",function(req,res){
   res.render("home.ejs");
 })

app.get("/login",function(req,res){
  res.render("login.ejs");
})

app.get("/register",function(req,res){
  res.render("register.ejs");
})

app.get("/secrets",function(req,res){
  res.render("secrets.ejs");
})

app.get("/submit",function(req,res){
  res.render("submit.ejs");
})
 app.post("/register",function(req,res){
   bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    const newUser=new User({
      email:req.body.username,
      password: hash
      });
      newUser.save(function(err){
        if(!err){
          console.log("User created");
          res.render("secrets.ejs");
        } else {
          console.log(err);
        }
      });

  });
})
 app.post("/login",function(req,res){
   const username=req.body.username;
   const password=req.body.password;
   User.findOne({email:username},function(err,foundUser){
     if(err){
       console.log(err);
     }else{
        if(foundUser.email===username){
          bcrypt.compare(password, foundUser.password, function(err, result) {
          if(result===true){
           res.render("secrets.ejs");
         }
        });

       }
     }
   });
 })

 app.listen(3000,function(){
   console.log("server is running on port 3000");
 })
