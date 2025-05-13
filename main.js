const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const Joi = require('joi');
const { MongoClient } = require('mongodb');
require('dotenv').config()

const port = process.env.PORT || 3000;

const app = express();
app.set('view engine', 'ejs');

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)


/* secret information section */
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;

const node_session_secret = process.env.NODE_SESSION_SECRET;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
/* END secret section */

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@cluster0.czaddbl.mongodb.net/sessions`,
 	crypto: {
 		secret: mongodb_session_secret
 	}
 })

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

const uri = `mongodb+srv://${mongodb_user}:${mongodb_password}@cluster0.czaddbl.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri);
const userCollection = client.db(process.env.MONGODB_DATABASE).collection("users");

console.log("Connecting to database:", process.env.MONGODB_DATABASE);

app.get(['/', '/home'], (req, res) => {
    if (req.session.authenticated) {
        // User is authenticated, show welcome message
        res.render('home_loggedin.ejs', { name: req.session.name });
        return;

    } else {
        // User is not authenticated, show login and signup options
        // Login and Sign Up Step 1
        res.render('home_loggedout.ejs');
        return;
    }
});


app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
            res.status(500).send("Error logging out");
        } else {
            res.redirect('/home');
        }
    });
});

app.get('/signup', (req, res) => {
    res.render('signup');
});



app.get('/login', (req,res) => {
    res.render('login');
});


// allows us to use the session variable in all views
app.use((req, res, next) => {
    res.locals.name = req.session.name;
    next();
});

// Sign Up Step 3
app.post('/submitUser', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    // Joi validation schema
    const schema = Joi.object({
        name: Joi.string().alphanum().min(3).max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).max(30).required()
    });

    // Validate the input
    const validationResult = schema.validate({ name, email, password });

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send(`${validationResult.error.details[0].message}. <a href='/signup'>Try again</a>`);
        return;
    }

    try {

        // Check if user with same email already exists
        const existingUser = await userCollection.findOne({ email: email });
        if (existingUser) {
            res.send("Email is already registered. <a href='/signup'>Try again</a>");
            return;
        }

        // Hash password
        var hashedPassword = bcrypt.hashSync(password, saltRounds);

        // Insert user
        await userCollection.insertOne({
            name: name,
            email: email,
            password: hashedPassword,
            user_type: "user"
        });

        // Start session
        req.session.authenticated = true;
        req.session.name = name;
        req.session.cookie.maxAge = expireTime;

        res.render('home_loggedin', { name: req.session.name });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error registering user. Please try again.");
    } finally {
        console.log("User registered:", name);
    }
});



app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Validate input using Joi
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(6).max(30).required(),
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error) {
        return res.send(`${validationResult.error.details[0].message}. <a href='/login'>Try again</a>`);
    }

    try {
        const user = await userCollection.findOne({ email });
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.send("Invalid email or password. <a href='/login'>Try again</a>");
        }

        req.session.authenticated = true;
        req.session.email = email;
        req.session.name = user.name;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/home'); // Redirect to home after successful login
    } catch (err) {
        console.error(err);
        res.status(500).send("Error logging in. Please try again.");
    }
});


app.get('/members', (req, res) => {
    if (req.session.authenticated) {

        const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
        const randomImage = images[Math.floor(Math.random() * images.length)];

        res.render(`members`, {user: req.session.name, image: randomImage});
    } else {
        res.redirect('/home');
    }
});

app.get('/admin', async (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;
    }

    const currentUser = await userCollection.findOne({ email: req.session.email });
    if (!currentUser || currentUser.user_type !== "admin") {
        res.status(403).send("You are not authorized to view this page.");
        return;
    }

    const users = await userCollection.find({}).toArray();
    res.render('admin', { users, currentUserEmail: req.session.email });
});

app.get('/promote/:email', async (req, res) => {
    if (!req.session.authenticated) return res.redirect('/login');

    const currentUser = await userCollection.findOne({ email: req.session.email });
    if (!currentUser || currentUser.user_type !== "admin") {
        return res.status(403).send("Not authorized.");
    }

    const targetEmail = req.params.email;
    if (targetEmail === req.session.email) {
        return res.send("You can't change your own admin status.");
    }

    await userCollection.updateOne({ email: targetEmail }, { $set: { user_type: "admin" } });
    res.redirect('/admin');
});

app.get('/demote/:email', async (req, res) => {
    if (!req.session.authenticated) return res.redirect('/login');

    const currentUser = await userCollection.findOne({ email: req.session.email });
    if (!currentUser || currentUser.user_type !== "admin") {
        return res.status(403).send("Not authorized.");
    }

    const targetEmail = req.params.email;
    if (targetEmail === req.session.email) {
        return res.send("You can't change your own admin status.");
    }

    await userCollection.updateOne({ email: targetEmail }, { $set: { user_type: "user" } });
    res.redirect('/admin');
});




app.use(express.static(__dirname + "/public"));

app.use((req, res, next) => {
    res.status(404).send("Page not found - 404");
});

(async () => {
    try {
        await client.connect();
        console.log("Connected to MongoDB");

        app.listen(port, () => {
            console.log("Node application listening on port " + port);
        });
    } catch (err) {
        console.error("Failed to connect to MongoDB", err);
    }
})(); 