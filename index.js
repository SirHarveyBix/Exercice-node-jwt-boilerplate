/* eslint-disable no-unused-vars */
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const connection = require('./database');

const { SERVER_PORT, CLIENT_URL, JWT_AUTH_SECRET } = process.env;

const app = express();

app.use(
  cors({
    origin: CLIENT_URL,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Your code here!

app.post('/register', (request, response) => {
  const { email, password } = request.body;
  if (!email || !password) {
    response.status(400).send('Please specify both email and password');
  } else {
    // never did in synchronous way
    const hash = bcrypt.hashSync(password, 10);
    connection.query(
      'INSERT INTO user (email, password) VALUES (?,?)',
      [email, hash],
      (err, result) => {
        if (err) {
          // helped with solution
          response.status(400).send(err.message);
        } else {
          response.status(201).send({
            id: result.insertId,
            email,
            password: 'hidden',
          });
        }
      }
    );
  }
});

app.post('/login', (request, response) => {
  const { email, password } = request.body;
  if (!email || !password) {
    response.status(400).send('Please specify both email and password');
  } else {
    connection.query(
      'SELECT * FROM user WHERE email = ?',
      [email],
      (error, result) => {
        if (error) {
          response.status(500).send(error.message);
        } else if (result.length === 0) {
          response.status(403).send(`invalid email`);
        } else if (bcrypt.compareSync(password, result[0].password)) {
          const user = {
            id: result[0].id,
            email: result[0].email,
            password: 'hidden',
          };
          // i've got firsts step, but helped with solution.
          const token = jwt.sign({ id: user.id }, JWT_AUTH_SECRET, {
            expiresIn: 300,
          });
          response.send({ user, token });
        } else {
          response.status(403).send('Invalid password');
        }
      }
    );
  }
});

app.get('/users', (request, response) => {
  connection.query('SELECT * FROM user', (error, result) => {
    if (error) {
      response.status(500).send(error.message);
    }
    response.status(200).send(result);
  });
});

// Don't write anything below this line!
app.listen(SERVER_PORT, () => {
  console.log(`Server is running on port ${SERVER_PORT}.`);
});
