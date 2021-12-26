const LocalStrategy = require("passport-local").Strategy;
const { pool } = require("./dbConfig");
const bcrypt = require("bcrypt");

function initialize(passport) {
  console.log("Initialized");

  const authenticateUser = (email, password, done) => {
    console.log(email, password);
    pool.query(
      `SELECT * FROM users WHERE email = $1`,
      [email],
      (err, results) => {
        if (err) {
          throw err;
        }
        console.log(results.rows);

        if (results.rows.length > 0) {
          const user = results.rows[0];

          bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
              console.log(err);
            }
            if (isMatch) {
              return done(null, user);
            } else {
              //Şifre Yanlış
              return done(null, false, { message: "Password is incorrect" });
            }
          });
        } else {
          // No user
          return done(null, false, {
            message: "No user with that email address"
          });
        }
      }
    );
  };

  passport.use(
    new LocalStrategy(
      { usernameField: "email", passwordField: "password" },
      authenticateUser
    )
  );
  // kullanıcı ayrıntılarını oturum içinde saklar. serializeUser, 
  // kullanıcı nesnesinin hangi verilerinin oturumda depolanması gerektiğini 
  // belirler. serializeUser yönteminin sonucu, 
  // oturuma req.session.passport.user = {} olarak eklenir. 
  // Örneğin burada (kullanıcı kimliğini anahtar olarak 
  // sağladığımız için) req.session.passport.user = {id: 'xyz'} olacaktır.
  
  passport.serializeUser((user, done) => done(null, user.id));

  // deserializeUser'da bu anahtar, bellekteki dizi/veritabanı veya herhangi bir veri kaynağı ile eşleştirilir.
  // Getirilen nesne, istek nesnesine req.user olarak eklenir.

  passport.deserializeUser((id, done) => {
    pool.query(`SELECT * FROM users WHERE id = $1`, [id], (err, results) => {
      if (err) {
        return done(err);
      }
      console.log(`ID is ${results.rows[0].id}`);
      return done(null, results.rows[0]);
    });
  });
}

module.exports = initialize;
