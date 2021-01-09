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

// mongo db config
const app: Application = express();
const url: string = 'mongodb+srv://harsh:harsh123@cluster0.vjrm0.mongodb.net/<dbname>?retryWrites=true&w=majority';
const dbName: string = 'short_url';


//env
dotenv.config();

let origin = 'http://127.0.0.1:5500';

//middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors({
    origin: origin
}))


function authenticate(req, res, next) {
    // console.log(req.headers)
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
                            userid: req.body.userid
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
        console.log('userid', req.body.userid);
        console.log('shortUrl', req.params.shortUrl);
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
        console.log(req.body);
        let urlData = await db.collection('url').find({ userid: req.body.userid }).toArray();
        console.log(urlData);
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
        if (user) {
            let isUserAuthenticated = await bycrypt.compare(req.body.password, user.password);
            if (isUserAuthenticated) {
                console.log(process.env);
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
                message: 'Entered Email does not exists',
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
        } else {
            let data = await db.collection('users').insertOne({ email: req.body.email, password: req.body.password });
            console.log('data', data);
            console.log('data-ops', data.ops);
            console.log('data-insertedCount:', data.insertedCount);
            let token = jwt.sign({ userid: data.ops[0]._id, email: req.body.email }, process.env.JWT_TOKEN, { expiresIn: "1h" });
            res.json({
                message: 'User Registered Successfully',
                token,
                data: {
                    email: req.body.email
                }
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


app.post('/forget-password', async (req, res) => {
    let connection = await MongoClient.connect(url, { useUnifiedTopology: true });
    try {
        let db = connection.db(dbName);
        let user = await db.collection('users').findOne({ email: req.body.email });

        if (user) {
            // let token = await crypto.randomBytes(20);
            let urlShortener: UniqueShortIdGeneratorService = new UniqueShortIdGeneratorService();
            let token = urlShortener.generateUniqueId({ length: 9 });
            console.log(ObjectId(user._id));
            console.log('forgot', token);
            await db.collection('users').updateOne({ _id: ObjectId(user._id) }, { $set: { resetToken: token, resetTokenExpires: Date.now() + 300000 } });

            let mailBody = `<div>
                <h3>Reset Password</h3>
                <p>Please click the given link to reset your password <a target="_blank" href="${origin}/reset-password.html?key=${encodeURIComponent(token)}"> click here </a></p>
            </div>`

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
                to: req.body.email,
                subject: "Reset password",
                html: mailBody,
            });

            console.log("Message sent: %s", info.messageId);

            // Preview only available when sending through an Ethereal account
            console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));
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
                let transporter = await nodemailer.createTransport({
                    host: "smtp.gmail.com",
                    port: 587,
                    secure: false,
                    auth: {
                        user: 'pawarharsh21@gmail.com',
                        pass: 'czpywvbthzaiemrn',
                    },
                });

                // send mail with defined transport object
                await transporter.sendMail({
                    from: 'noreply@urlShortner.com',
                    to: user[0].email,
                    subject: "success reset",
                    html: 'Password Reset Successfully',
                });

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
    res.json({
        message: "user is logged in",
        data: {
            email: req.body.email,
            isUserLoggedIn: true,
        }
    })
})

//listen on port
app.listen(3000);