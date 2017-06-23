var express = require('express');
var router = express.Router();
var passport = require('passport')
var LocalStrategy = require('passport-local').Strategy

var User = require('../models/user')

/* GET users listing. */
router.get('/signin', function(req, res, next) {
  console.log(res.locals)
  res.render('signin');
});

router.post('/signin',
  passport.authenticate('local', {
    successRedirect: '/users/profile',
    failureRedirect: '/users/signin',
    failureFlash: true
  }),
  function(req, res) {
    res.redirect('/users/profile')
});

/* GET users listing. */
router.get('/signup', function(req, res, next) {
  res.render('signup', {errors: ''});
});

// Post Sign Up
router.post('/signup', function(req, res, next) {
  // Parse Info
  var username = req.body.username
  var password = req.body.password

  // Validation
  req.checkBody('username', 'Username is required').notEmpty()
  req.checkBody('password', 'Password is required').notEmpty()

  var errors = req.validationErrors();
  if(errors) {
    res.render('signup', {errors: errors})
  } else {
  //Create User
  var newUser = new User({
    username: username,
    password: password
  })
  User.createUser(newUser, function(err, user){
    if(err) throw err;
  })
  req.flash('success_msg', 'you are registered now log in')
  res.redirect('/users/signin')
  }
});

router.get('/profile', ensureAuthenticated, function(req, res, next) {
  console.log(req.user)
  res.render('profile', {
    user: req.user.username
  });
});

router.get('/logout', function(req, res, next) {
  req.logout()
  req.flash('success_msg', 'You are logged out')
  res.redirect('/users/signin')
})

module.exports = router;

function ensureAuthenticated(req, res, next){
  if(req.isAuthenticated()){
    return next();
  } else {
    req.flash('error_msg', 'you are not logged in')
    res.redirect('/users/signin')
  }
}

passport.use(new LocalStrategy(
  function(username, password, done) {
    User.findOne({ username: username }, function(err, user) {
      if (err) { return done(err); }
      if (!user) {
        return done(null, false, { message: 'Incorrect username.' });
      }
      User.comparePassword(password, user.password, function(err, isMatch){
        if(err) throw err
        if(isMatch) {
          return done(null, user)
        } else {
          return done(null, false, {message: 'Invalid password'})
        }
      })
    });
  }
));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});