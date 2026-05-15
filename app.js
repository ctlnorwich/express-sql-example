import express, { json, urlencoded } from 'express';
import session from 'express-session';
import memorystore from 'memorystore';
import { DatabaseSync } from 'node:sqlite';
import { loadEnvFile } from 'node:process';
import { createHash, randomBytes } from 'node:crypto';

// Check if there is a .env file.
try {
  loadEnvFile();
} catch (e) {
  if (e.code !== 'ENOENT') {
    throw e;
  }
}

// Create our express app and store it in the 'app' variable
const app = express();
// Add memorystore to expire sessions
const MemoryStore = memorystore(session);

// Specify public directory for static assets (e.g. stylesheets)
app.use(express.static('public'))

// Middleware to parse form data from the forms in our .ejs files
app.use(urlencoded({ extended: false }));

// Use json middleware for API - testing only at the moment (not used for our .ejs templates)
app.use(json());

// Set EJS as templating engine to use with our views
app.set('view engine', 'ejs');

// Session middleware - generate a random secret for our session id
app.use(session({
  cookie: { maxAge: 86400000 },
  store: new MemoryStore({
    checkPeriod: 86400000 // prune expired entries every 24h
  }),
  resave: false,
  saveUninitialized: false,
  secret: randomBytes(32).toString('hex'),
}));

// Example middleware to check response headers (not needed - just for testing)
// app.use((req, res, next) => {
//     res.on('finish', () => {
//         console.log(`request url = ${req.originalUrl}`);
//         console.log(res.getHeaders());
//     });
//     next();
// });

// Construct our SQLite database instance using a file
const db = new DatabaseSync(process.env.DB_PATH || 'database.sqlite');

// MD5 encryption for our passwords
// ToDo: Change this to something more secure!
function md5(password) {
  return createHash('md5').update(password).digest('hex');
}

// Create users table if it doesn't exist - runs first time our app starts
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      password TEXT NOT NULL
    )
  `);
  console.log('Users table ready');
} catch (err) {
  console.error('Error creating table:', err.message);
  process.exit(1);
}

// Custom middleware for authentication - does the user have an active session?
function requireLogin(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

// ToDo: Ideally, move the controller and routing logic to different files to keep things clean!
// NOTE: You can only use the GET and POST http methods with HTML forms. This works (e.g. use POST to delete), but is not as clear.
// The more specific methods, PUT, PATCH and DELETE can be used by replacing an HTML form submission with JavaScript FormData and the Fetch API. 

// ROUTES WITH CONTROLLER LOGIC BELOW:

// @desc Render the login page
// @route GET /login
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

// @desc Login page form action to log in to the app
// @route POST /login
app.post('/login', (req, res) => {
  // Get email and password from the request body (sent via the form)
  const { email, password } = req.body;

  // If no email for password send error data to be displayed on the login page 
  if (!email || !password) {
    return res.render('login', { error: 'Email and password are required' });
  }

  // Try to match the login data with a database query.
  // If the user exists and the password is correct, create a user session and redirect to the home page
  try {
    const row = db.prepare('SELECT * FROM users WHERE email = ? AND password = ?').get(email, md5(password));
    if (!row) {
      return res.render('login', { error: 'Invalid email or password' });
    }
    req.session.userId = row.id;
    req.session.userName = row.name;
    res.redirect('/');
  } catch (err) {
    console.error(err);
    return res.status(500).send('Database error');
  }
});


// @desc Form action to log out of the app, destroy the user session and redirect back to login.
// @route POST /logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});


// @desc Get a list of users and display the main page - user must be logged in with a valid session!
// Note that the userName (current user's name) is retrieved from the current session data
// @route GET /
app.get('/', requireLogin, (req, res) => {
  try {
    const rows = db.prepare('SELECT id, name, email FROM users ORDER BY id DESC').all();
    res.render('index', { users: rows, userName: req.session.userName });
  } catch (err) {
    console.error(err);
    return res.status(500).send('Database error: ' + err);
  }
});


// @desc Get a list of users via the API
// @route GET /api
app.get('/api', (req, res) => {
  try {
    const rows = db.prepare('SELECT id, name, email FROM users ORDER BY id DESC').all();
    res.status(200).json({ users: rows });
  } catch (err) {
    console.error(err);
    return res.status(500).send('Database error');
  }
});


// @desc Add a single user
// @route POST /add
app.post('/add', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).send('Name, email, and password are required');
  }
  try {
    const hashedPassword = md5(password);
    // Note the question marks here - those anonymous parameters are replaced by the values of 'id, email and hashedPassword' in the run() method.
    db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)').run(name, email, hashedPassword);
    res.redirect('/');
  } catch (err) {
    console.error(err);
    return res.status(500).send('Database error');
  }
});


// @desc Add a single user via the API
// @route POST /api/add
app.post('/api/add', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({
      error: 'Name, email, and password are required',
    });
  }
  try {
    const hashedPassword = md5(password);
    const result = db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)').run(name, email, hashedPassword);
    return res.status(201).json({
      message: 'User created successfully',
      user: {
        id: result.lastInsertRowid,
        name,
        email,
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Database error' });
  }
});


// @desc Delete a single user - user must be logged in with a valid session!
// @route POST /delete/:id
app.post('/delete/:id', requireLogin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) {
    return res.status(400).send('Invalid ID');
  }
  try {
    // Note the question mark here - that anonymous parameter is replaced by the value of 'id' in the run() method.
    db.prepare('DELETE FROM users WHERE id = ?').run(id);
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  }
});

// If none of the above routes are hit, the server will end up running this middleware, which displays a basic 404 message.
// You could render an ejs template here instead.
app.use((req, res, next) => {
  res.status(404).send("<h1>404: Sorry, that resource doesn't exist!</h1>")
})

// IMPORTANT! The listen() method returns the Express server so you can run your app (defualts to running on port 3000)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
