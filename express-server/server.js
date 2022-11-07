const express = require('express');
const app = express();
const cors = require('cors');
const bcrypt = require('bcryptjs');

/* Middleware */
app.use(cors());
app.use(express.json()); /* Parse requests of content-type - application/json */
app.use(express.urlencoded({ extended: true })); /* Parse requests of content-type - application/x-www-form-urlencoded */

/* Routes */
/***************************************************/
/****************** Get all users ******************/
/***************************************************/
/* Thunder Client: GET http://localhost:5000/users */
const users = [];
app.get('/users', (req, res) => {
  res.json(users);
});

/***************************************************/
/********************* Sign up *********************/
/***************************************************/
/* Thunder Client: POST http://localhost:5000/users */
/* JSON: { "email": "unique@email.com", "password": "password123" } */
app.post('/users', async(req, res) => {
  try {
    /* Generate salt --> if two users have identical password, hashes will be different */
    /* Goal: Impossible to crack other identical password if one is cracked */
    const salt = await bcrypt.genSalt();
    /* Use salt and hash the password */
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    const user = { email: req.body.email, password: hashedPassword };
    users.push(user);
    res.status(201).send();
  } catch {
    res.status(500).send();
  }
});

/***************************************************/
/********************* Sign in *********************/
/***************************************************/
/* Thunder Client: POST http://localhost:5000/users/signin */
/* JSON: { "email": "unique@email.com", "password": "password123" } */
app.post('/users/signin', async(req, res) => {
  /* Compare an e-mail that was passed in vs. e-mails from the list of users */
  const user = users.find(user => req.body.email === user.email);
  /* If an e-mail does NOT exist in the list of users... */
  if (user == null) {
    /* ...return an error */
    return res.status(400).send('Incorrect e-mail.');
  }
  /* If an e-mail does exist in the list of users... */
  try {
    /* ...and if the password that was passed in is the same as password of that particular user from the list of users... */
    if (await bcrypt.compare(req.body.password, user.password)) {
      /* ...return a success */
      res.send('Success.');
    } else { /* ...but the password that was passed in is NOT the same as password of that particular user from the list of users... */
      /* ...return an error */
      return res.status(400).send('Incorrect password.');
    }
  } catch {
    res.status(500).send();
  }
});

/* Set port and listen for requests */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});