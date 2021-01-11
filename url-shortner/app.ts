import express, { Application, Request, Response } from 'express';
import bodyParser from 'body-parser';
import { UniqueShortIdGeneratorService } from './src/services/UniqueShortIdGenerator.service';
import { mongodb, ObjectId, MongoClient } from 'mongodb';
import validUrl from 'valid-url';
import cors from 'cors';
import dns from 'dns';
import bycrypt from 'bcrypt';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import jwt from "jsonwebtoken";
import dotenv from 'dotenv';
import validator from 'validator';

// mongo db config
const app: Application = express();
const url: string = 'mongodb+srv://harsh:harsh123@cluster0.vjrm0.mongodb.net/<dbname>?retryWrites=true&w=majority';
const dbName: string = 'short_url';


//env
dotenv.config();

let origin = 'https://gallant-hypatia-caf2b6.netlify.app';

//middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors({
    origin: origin
}))


function authenticate(req, res, next) {
    if (req.headers.authorization) {

        jwt.verify(req.headers.authorization, process.env.JWT_TOKEN, function (err, data) {
            if (data) {
                if (data.userid) {
                    req.body.userid = data.userid
                    req.body.email = data.email
                    next()
                } else {
                    res.status(401).json({
                        message: "Not Authorized"
                    })
                }

            } else {
                res.status(400).json({
                    message: "Invalid Token"
                })
            }
        })
    } else {
        res.status(400).json({
            messsage: "No Token Present"
        })
    }
}

//validate the url, after validation shortern the url and send it to the user and save in the db
app.post('/shorten-url', authenticate, async (req: Request, res: Response) => {
    console.log(req.body);

    //create connection for client
    let connection = await MongoClient.connect(url, { useUnifiedTopology: true });
    try {
        // check if it is in valid url format
        if (validUrl.isUri(req.body.url)) {
            let url = new URL(req.body.url);

            //check if domain name exists
            dns.lookup(url.hostname, { all: true }, async (error, results) => {
                if (error) {
                    res.status(400).json({
                        message: 'Domain Does not exists',
                    });
                } else {
                    //shorten and insert the url in db
                    let url: string = req.body.url;
                    let db = connection.db(dbName);
                    let urlData = await db.collection('url').findOne({
                        $and: [{ url: url }, { userid: req.body.userid }]
                    });
                    if (urlData) {
                        res.json({
                            message: 'Shortern Url Already Exists',
                            data: urlData
                        });
                    } else {
                        let urlShortener: UniqueShortIdGeneratorService = new UniqueShortIdGeneratorService();
                        let shortUrl: string = urlShortener.generateUniqueId();
                        let urlData = {
                            url,
                            shortUrl,
                            clicks: 0,
                            userid: req.body.userid,
                            date: new Date()
                        };
                        await db.collection('url').insertOne(urlData);
                        res.json({
                            message: "Short url generated Successfully",
                            data: urlData,
                        });
                    }
                    await connection.close();
                }
            });

        } else {
            res.status(400).json({
                message: 'Please enter a valid Url'
            })
        }

    } catch (err) {
        console.log(err);
        res.status(401).json({
            message: 'Some Error Occured',
            data: err
        })
    }
})

// redirect url if the short url has valid url mapping
app.get('/redirect-url/:shortUrl', async (req: Request, res: Response) => {

    //create connection for client
    let connection = await MongoClient.connect(url, { useUnifiedTopology: true });
    try {

        //check url exists
        let db = connection.db(dbName);
        let urlData = await db.collection('url').findOne({
            shortUrl: req.params.shortUrl
        });
        console.log('urlData', urlData);
        if (urlData) {

            //update click count in db 
            await db.collection('url').updateOne({ _id: urlData._id }, { $set: { clicks: ++urlData.clicks } });
            res.json({
                message: "SuccessFully fetched Redirect Data",
                data: urlData,
            });
        } else {
            res.status(400).json({
                message: 'Invalid short url'
            })
        }
    } catch (err) {
        res.status(401).json({
            message: 'Some Error Occured',
            data: err
        })
    } finally {
        connection.close();
    }
})

// get all url details for the user
app.get('/url-data', authenticate, async (req: Request, res: Response) => {

    //create connection
    let connection = await MongoClient.connect(url, { useUnifiedTopology: true });
    try {

        // fetch all the url details
        let db = connection.db(dbName);
        let urlData = await db.collection('url').find({ userid: req.body.userid }).toArray();
        res.json({
            message: 'Url details fetched successfully',
            data: urlData
        })
    } catch (err) {
        res.status(401).json({
            message: 'Some Error Occured',
            data: err
        })
    } finally {
        connection.close();
    }
})

app.post('/login', async (req, res) => {
    let connection = await MongoClient.connect(url, { useUnifiedTopology: true });
    try {
        let db = connection.db(dbName);
        let user = await db.collection('users').findOne({ email: req.body.email });
        if (user.isActive) {
            let isUserAuthenticated = await bycrypt.compare(req.body.password, user.password);
            if (isUserAuthenticated) {
                let token = jwt.sign({ userid: user._id, email: user.email }, process.env.JWT_TOKEN, { expiresIn: "1h" });
                res.json({
                    message: 'User Authenticated Successfully',
                    token,
                    data: {
                        email: user.email
                    }
                })
            } else {
                res.status(400).json({
                    message: 'Password is wrong for the provided email',
                })
            }
        } else {
            res.status(400).json({
                message: 'Entered Email does not exists or is not activated',
            })
        }
    } catch (err) {
        console.log(err);
        res.status(400).json({
            message: 'Unable to login please enter valid credentials',
        })
    } finally {
        connection.close();
    }
});

app.post('/sign-up', async (req, res) => {
    let connection = await MongoClient.connect(url, { useUnifiedTopology: true });
    try {
        let db = connection.db(dbName);
        let salt = await bycrypt.genSalt(10);
        let hash = await bycrypt.hash(req.body.password, salt);
        req.body.password = hash;
        let user = await db.collection('users').findOne({ email: req.body.email });
        console.log(user);
        if (user) {
            res.status(400).json({
                message: 'Email id already registered',
            })
        } else if (!validator.isEmail(req.body.email)) {
            res.status(400).json({
                message: 'Invalid  Email, please enter a vaid email',
            })
        } else {
            let data = await db.collection('users').insertOne(
                {
                    email: req.body.email,
                    password: req.body.password,
                    firstName: req.body.firstName,
                    lastName: req.body.lastName,
                    isActive: false,
                });

            let mailBody = `<div>
                <h4> To activate the account please <a href="https://secure-login-url-shortner.herokuapp.com/activate-account/${data.ops[0]._id}/${req.body.email}">click here</a></h4>
            </div>`

            let mailSubject = 'Account Activation for Url shortner';
            sendMail(mailSubject, mailBody, req.body.email);
            res.json({
                message: `Mail has been sent to ${req.body.email} for activation`,
            })
        }

    } catch (err) {
        console.log(err);
        res.status(400).json({
            message: 'Unable to register please enter valid details',
        })
    } finally {
        connection.close();
    }
})

app.get('/activate-account/:userId/:email', async (req, res) => {
    let connection = await MongoClient.connect(url, { useUnifiedTopology: true });
    try {
        let db = connection.db(dbName);
        let token = jwt.sign({ userid: req.params.userId, email: req.params.email }, process.env.JWT_TOKEN, { expiresIn: "1h" });
        let updateInfo = await db.collection('users').updateOne({ _id: ObjectId(req.params.userId) }, { $set: { isActive: true } });
        if (updateInfo.modifiedCount > 0) {
            res.redirect(`${origin}/index.html?token=${token}`);
        }
    } catch (err) {
        console.log(err);
    } finally {
        connection.close();
    }
})

app.post('/forget-password', async (req, res) => {
    let connection = await MongoClient.connect(url, { useUnifiedTopology: true });
    try {
        let db = connection.db(dbName);
        let user = await db.collection('users').findOne({ email: req.body.email });

        if (user) {
            let token = await crypto.randomBytes(32).toString('hex');
            await db.collection('users').updateOne({ _id: ObjectId(user._id) }, { $set: { resetToken: token, resetTokenExpires: Date.now() + 300000 } });

            let mailBody = `<div>
                <h3>Reset Password</h3>
                <p>Please click the given link to reset your password <a target="_blank" href="${origin}/reset-password.html?key=${encodeURIComponent(token)}"> click here </a></p>
            </div>`

            sendMail("Reset password", mailBody, user.email);

            res.json({
                message: `Mail has been sent to ${user.email}</h4> with further instructions`,
            })
        } else {
            res.status(400).json({
                message: 'User not found',
            })
        }

    } catch (err) {
        console.log(err);
    } finally {
        connection.close()
    }
})


async function sendMail(mailSubject, mailBody, mailTo) {

    // create reusable transporter object using the default SMTP transport
    let transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 587,
        secure: false,
        auth: {
            user: 'pawarharsh21@gmail.com',
            pass: 'czpywvbthzaiemrn',
        },
    });

    // send mail with defined transport object
    let info = await transporter.sendMail({
        from: 'noreply@urlShortner.com',
        to: mailTo,
        subject: mailSubject,
        html: mailBody,
    });
}

app.put('/reset', async (req, res) => {
    console.log('reset', decodeURIComponent(req.body.token));
    let connection = await MongoClient.connect(url, { useUnifiedTopology: true });
    try {
        let db = connection.db(dbName);
        let user = await db.collection('users').find({ resetToken: decodeURI(req.body.token), resetTokenExpires: { $gt: Date.now() } }).toArray();
        console.log(user);
        if (user.length !== 0) {

            let salt = await bycrypt.genSalt(10);
            let password = await bycrypt.hash(req.body.password, salt);
            let updateInfo = await db.collection('users').updateOne({ _id: ObjectId(user[0]._id) }, { $set: { password: password } });

            if (updateInfo.modifiedCount > 0) {
                await db.collection('users').updateOne({ _id: ObjectId(user[0]._id) }, { $set: { resetToken: '', resetTokenExpires: '' } });

                sendMail("success reset", 'Password Reset Successfully', user[0].email);

                let token = jwt.sign({ userid: user[0]._id, email: user[0].email }, process.env.JWT_TOKEN, { expiresIn: "1h" });
                res.json({
                    message: "Password reset successfull check your mail for confirmation",
                    token,
                    data: {
                        email: user[0].email
                    }
                })
            }
        } else {
            res.status(400).json({
                message: "Failed to update password token invalid",
            })
        }
    } catch (err) {
        console.log(err);

    } finally {
        connection.close();
    }
})

app.get('/ping', authenticate, async (req, res) => {
    let connnection = await MongoClient.connect(url, { useUnifiedTopology: true });
    try {
        let db = connnection.db(dbName);
        let user = await db.collection('users').findOne({ _id: ObjectId(req.body.userid) });
        if (user) {
            res.json({
                message: "user is logged in",
                data: {
                    email: req.body.email,
                }
            })
        } else {
            res.status(400).json({
                message: "User Does not exists",
            })
        }
    } catch (err) {
        console.log(err);
    }
})

//listen on port
app.listen(process.env.PORT || 3000);
