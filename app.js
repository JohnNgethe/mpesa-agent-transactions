const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const useragent = require("express-useragent");
const findOrCreate = require("mongoose-findorcreate");
const crypto = require("crypto");
const ejs = require("ejs");
const fs = require("fs");
const PDFDocument = require("pdfkit");

require("dotenv").config();

// Function to encrypt data
function encryptData(data) {
  const algorithm = "aes-256-cbc";
  const key = process.env.ENCRYPTION_KEY;
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(algorithm, Buffer.from(key, "hex"), iv);

  let encryptedData = cipher.update(data, "utf-8", "hex");
  encryptedData += cipher.final("hex");

  return {
    encryptedData,
    iv: iv.toString("hex"),
  };
}

// Function to decrypt data
function decryptData(encryptedData, iv) {
  const algorithm = "aes-256-cbc";
  const key = process.env.ENCRYPTION_KEY;

  const decipher = crypto.createDecipheriv(
    algorithm,
    Buffer.from(key, "hex"),
    Buffer.from(iv, "hex")
  );

  let decryptedData = decipher.update(encryptedData, "hex", "utf-8");
  decryptedData += decipher.final("utf-8");

  return decryptedData;
}

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection with mongoose
mongoose.connect(process.env.DB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
// Check MongoDB connection
const db = mongoose.connection;
db.on("error", (error) => console.error("MongoDB connection error:", error));
db.once("open", () => console.log("Connected to MongoDB successfully"));

// Schema
const userSchema = new mongoose.Schema({
  email: String,
  googleId: String,
  username: String,
  secret: String,
});

userSchema.plugin(findOrCreate);

const User = mongoose.model("user", userSchema);

const transactionSchema = new mongoose.Schema({
  transactionCode: String,
  name: String,
  nationalID: String, // Encrypted
  phoneNumber: String, // Encrypted
  transactionType: String,
  date: { type: Date, default: Date.now },
});

const Transaction = mongoose.model("Transaction", transactionSchema);

// Passport serialization and deserialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id)
    .exec()
    .then((user) => {
      done(null, user);
    })
    .catch((err) => {
      done(err, null);
    });
});

// Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/callback",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        { googleId: profile.id, email: profile.emails[0].value },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

// Login route
app.get(
  "/login",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Callback route after Google has authenticated the user
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    // Successful authentication, redirect to the home page
    res.redirect("/");
  }
);

// Logout route
app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

// Middleware to ensure that only authenticated users can access certain routes
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    res.redirect("/login"); // Redirect to the login page if not authenticated
  }
}

// Routes

// Home route
app.get("/", ensureAuthenticated, (req, res) => {
  res.render("index", { user: req.user });
});

// Transaction form route
app.get("/transaction", ensureAuthenticated, (req, res) => {
  res.render("transaction", { user: req.user }); // Pass the user variable to the view
});

// Handle transaction form submission
app.post("/transaction", ensureAuthenticated, async (req, res) => {
  const { transactionCode, name, nationalID, phoneNumber, transactionType } =
    req.body;

  // Encrypt sensitive data
  const encryptedNationalID = encryptData(nationalID);
  const encryptedPhoneNumber = encryptData(phoneNumber);

  const newTransaction = new Transaction({
    transactionCode,
    name,
    nationalID: encryptedNationalID.encryptedData,
    phoneNumber: encryptedPhoneNumber.encryptedData,
    transactionType,
  });

  try {
    await newTransaction.save();
    res.redirect("/");
  } catch (error) {
    res.status(500).send("Error saving transaction");
  }
});

// Download transactions route
app.get("/download", ensureAuthenticated, async (req, res) => {
  try {
    let { startDate, endDate } = req.query;

    // If start date is not provided, set it to yesterday
    if (!startDate) {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      startDate = yesterday.toISOString().split("T")[0]; // Format as 'YYYY-MM-DD'
    }

    // If end date is not provided, set it to today
    if (!endDate) {
      endDate = new Date().toISOString().split("T")[0]; // Format as 'YYYY-MM-DD'
    }

    const transactions = await Transaction.find({
      date: { $gte: startDate, $lte: endDate },
    });

    // Decrypt sensitive data before sending it to the user
    const decryptedTransactions = transactions.map((transaction) => ({
      transactionCode: transaction.transactionCode,
      name: transaction.name,
      nationalID: decryptData(transaction.nationalID, transaction.date),
      phoneNumber: decryptData(transaction.phoneNumber, transaction.date),
      transactionType: transaction.transactionType,
      date: transaction.date,
    }));

    // Create a PDF document
    const doc = new PDFDocument();
    doc.pipe(fs.createWriteStream("transactions.pdf"));

    // Add content to the PDF
    doc
      .fontSize(12)
      .text(`M-Pesa Transactions From ${startDate} to ${endDate}`, {
        align: "center",
      })
      .moveDown();

    // Create a table header
    const tableHeaders = [
      "Transaction Code",
      "Name",
      "National ID",
      "Phone Number",
      "Transaction Type",
      "Date",
    ];
    const tableData = [tableHeaders];

    // Add transactions to the table
    decryptedTransactions.forEach((transaction) => {
      const rowData = [
        transaction.transactionCode,
        transaction.name,
        transaction.nationalID,
        transaction.phoneNumber,
        transaction.transactionType,
        transaction.date.toString(),
      ];

      // Add each row to the table
      doc.text(rowData.join("\t"), { align: "center" }).moveDown();
    });

    // Finalize the PDF
    doc.end();

    // Send the PDF file as a download
    if (fs.existsSync("transactions.pdf")) {
      res.download("transactions.pdf", "transactions.pdf", (err) => {
        if (err) {
          res.status(500).send("Error downloading transactions");
        }
        // Delete the generated PDF file after sending
        fs.unlinkSync("transactions.pdf");
      });
    } else {
      res.status(404).send("PDF file not found");
    }
  } catch (error) {
    res.status(500).send("Error downloading transactions");
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
