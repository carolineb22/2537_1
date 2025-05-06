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

const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)


/* secret information section */
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;

const node_session_secret = process.env.NODE_SESSION_SECRET;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
/* END secret section */

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@process.env.MONGODB_HOST/sessions`,
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

const uri = `mongodb+srv://${mongodb_user}:${mongodb_password}@process.env.MONGODB_HOST/?retryWrites=true&w=majority`;
const client = new MongoClient(uri);
const userCollection = client.db(process.env.MONGODB_DATABASE).collection("users");


app.get(['/', '/home'], (req, res) => {
    if (req.session.authenticated) {
        // User is authenticated, show welcome message
        res.send(`
            <h1>Hello, ${req.session.name}!</h1>
            <a href='/members'>Go to member's area</a><br>
            <a href='/logout'>Log out</a>
        `);
        return;

    } else {
        // User is not authenticated, show login and signup options
        // Login and Sign Up Step 1
        res.send(`
            <h1>Welcome to the site!</h1>
            <a href='/login'>Log in</a><br>
            <a href='/signup'>Sign up</a>
        `);
        return;
    }
});

app.get('/logout', (req,res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
            res.status(500).send("Error logging out");
        } else {
            res.redirect('/');
        }
    });
});


app.get('/signup', (req, res) => {
    var html = `
    <!-- Sign Up Step 2-->
    <h2>Create user</h2>
    <form action='/submitUser' method='post'>
        <input name='name' type='text' placeholder='name' required>
        <input name='email' type='email' placeholder='email' required>
        <input name='password' type='password' placeholder='password' required>
        <button type='submit'>Submit</button>
    </form>
    `;
    res.send(html);
});



app.get('/login', (req,res) => {
    var html = `
     <!-- Login Step 2-->
    log in
    <form action='/login' method='post'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
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
        await client.connect();

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
            password: hashedPassword
        });

        // Start session
        req.session.authenticated = true;
        req.session.name = name;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
    } catch (err) {
        console.error(err);
        res.status(500).send("Error registering user. Please try again.");
    } finally {
        await client.close();
    }
});



app.post('/login', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    // ✅ Joi validation schema
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(6).max(30).required()
    });

    // Validate user input
    const validationResult = schema.validate({ email, password });

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send(`${validationResult.error.details[0].message}. <a href='/login'>Try again</a>`);
        return;
    }

    try {
        await client.connect();

        const user = await userCollection.findOne({ email: email });
        if (!user) {
            res.send("Invalid email. <a href='/login'>Try again</a>");
            return;
        }

        if (!bcrypt.compareSync(password, user.password)) {
            res.send("Invalid password. <a href='/login'>Try again</a>");
            return;
        }

        req.session.authenticated = true;
        req.session.email = email;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');

    } catch (err) {
        console.error(err);
        res.status(500).send("Error logging in. Please try again.");
    } finally {
        await client.close();
    }
});

app.get('/members', (req, res) => {
    if (req.session.authenticated) {

        const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
        const randomImage = images[Math.floor(Math.random() * images.length)];

        res.send(`
            <h1>Hello ${req.session.name}!</h1>
            <img src='/${randomImage}' alt='Random Cat' style='width:250px;' />
            <br/>
            <a href='/logout'>Log out</a>
        `);
    } else {
        res.status(403).send("You are not authorized to view this page. <a href='/login'>Log in</a>");
    }
});



app.use(express.static(__dirname + "/public"));

app.use((req, res, next) => {
    res.status(404).send("Page not found - 404");
});

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 