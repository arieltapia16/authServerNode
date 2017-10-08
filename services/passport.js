const passport = require('passport');
const User = require('../models/user');
const config  = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

const localLogin = new LocalStrategy({usernameField: 'email'}, function(email, password, done){
  User.findOne({email: email}, function(err, user){
    if(err){ return done(err);}
    if(!user){ return done(null, false);}
  
    user.comparePasswords(password , function(err, isMatch){
      if(err){ return done(err)}
      if(!isMatch) { return done(null, false);}

      return done(null, user);
    } )    
  
  });
})

var jwtOptions = {}
jwtOptions.jwtFromRequest = ExtractJwt.fromHeader('authorization');
jwtOptions.secretOrKey = config.secret;

const verifyFunction = (payload, done) => {
  User.findById(payload.sub, function(err, user) {
    if (err) { return done(err, false) }

    if (user) {
      done(null, user);
    } else {
      done(null, false)
    }
  })
}


const jwtLogin = new JwtStrategy(jwtOptions, verifyFunction);

passport.use(jwtLogin); 
passport.use(localLogin); 