import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const PORT = 4000;
const mongoURL = "mongodb://localhost:27017";
const dbName = "quirknotes";

//connect to mongodb
let db;

async function connectToMongo() {
  const client = new MongoClient(mongoURL);
  try {
    await client.connect();
    console.log("Connected to MongoDB");

    db = client.db(dbName);
  } catch (error) {
    console.error("error connecting to MongoDB:", error);
  }
}

connectToMongo();

// Open Port
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

// Collections to manage
const COLLECTIONS = {
  notes: "notes",
  users: "users",
};

// Register a new user
app.post("/registerUser", express.json(), async (req, res) => {
  try {
    const { username, password } = req.body;

    // Basic body request check
    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password both needed to register." });
    }

    // Checking if username does not already exist in database
    const userCollection = db.collection(COLLECTIONS.users);
    const existingUser = await userCollection.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: "Username already exists." });
    }

    // Creating hashed password (search up bcrypt online for more info)
    // and storing user info in database
    const hashedPassword = await bcrypt.hash(password, 10);
    await userCollection.insertOne({
      username,
      password: hashedPassword,
    });

    // Returning JSON Web Token (search JWT for more explanation)
    const token = jwt.sign({ username }, "secret-key", { expiresIn: "1h" });
    res.status(201).json({ response: "User registered successfully.", token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Log in an existing user
app.post("/loginUser", express.json(), async (req, res) => {
  try {
    const { username, password } = req.body;

    // Basic body request check
    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password both needed to login." });
    }

    // Find username in database
    const userCollection = db.collection(COLLECTIONS.users);
    const user = await userCollection.findOne({ username });

    // Validate user against hashed password in database
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign({ username }, "secret-key", { expiresIn: "1h" });

      // Send JSON Web Token to valid user
      res.json({ response: "User logged in succesfully.", token: token }); //Implicitly status 200
    } else {
      res.status(401).json({ error: "Authentication failed." });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Post a note belonging to the user
app.post("/postNote", express.json(), async (req, res) => {
  try {
    // Basic body request check
    const { title, content } = req.body;
    if (!title || !content) {
      return res
        .status(400)
        .json({ error: "Title and content are both required." });
    }

    // Verify the JWT from the request headers
    const token = req.headers.authorization.split(" ")[1];
    jwt.verify(token, "secret-key", async (err, decoded) => {
      if (err) {
        return res.status(401).send("Unauthorized.");
      }

      // Send note to database
      const collection = db.collection(COLLECTIONS.notes);
      const result = await collection.insertOne({
        title,
        content,
        username: decoded.username,
      });
      res.json({
        response: "Note added succesfully.",
        insertedId: result.insertedId,
      });
    });
  } catch (error) {
    res.status(500)
      .json({ error: error.message });
  }
});
// Retrieve a note belonging to the user
app.get("/getNote/:noteId", express.json(), async (req, res) => {
  try {
    // Basic param checking
    const noteId = req.params.noteId;
    if (!ObjectId.isValid(noteId)) {
      return res.status(400)
        .json({ error: "Invalid note ID." });
    }

    // Verify the JWT from the request headers
    const token = req.headers.authorization.split(" ")[1];
    jwt.verify(token, "secret-key", async (err, decoded) => {
      if (err) {
        return res.status(401).send("Unauthorized.");
      }

      // Find note with given ID
      const collection = db.collection(COLLECTIONS.notes);
      const data = await collection.findOne({
        username: decoded.username,
        _id: new ObjectId(noteId),
      });
      console.log(decoded.username);
      if (!data) {
        return res
          .status(404)
          .json({ error: "Unable to find note with given ID." });
      }
      res.json({ response: data });
    });
  } catch (error) {
    res.status(500)
      .json({ error: error.message });
  }
});

//get all notes
app.get("/getAllNotes", express.json(), async (req, res) => {
  try {

    //Verify JWT from request headers
    const token = req.headers.authorization.split(" ")[1];
    jwt.verify(token, "secret-key", async (err, decoded) => {
      if (err) {
        return res.status(401).send("Unauthorized.");
      }

      // Find notes with logged in user
      const collection = db.collection(COLLECTIONS.notes);
      const data = await collection.find({
        username: decoded.username,
      }).toArray();
      //console.log(decoded.username);
      if (!data) {
        return res
          .status(404)
          .json({ error: "Unable to get all notes" });
      }
      res
        .status(200)
        .json({ response: data });
    });

  } catch (error) {
    res.status(500)
      .json({ error: error.message });
  }

});

//delete a note
app.delete("/deleteNote/:noteID", express.json(), async (req, res) => {
  try {
    //check note id param
    const noteID = req.params.noteID;
    if (!ObjectId.isValid(noteID)) {
      return res.status(400)
        .json({ error: "Bad request in relation to the :noteId URL parameter" });
    }
    const token = req.headers.authorization.split(" ")[1];
    jwt.verify(token, "secret-key", async (err, decoded) => {
      if (err) {
        return res.status(401).send("Unauthorized.");
      }

      const collection = db.collection(COLLECTIONS.notes);

      const data = await collection.deleteOne({
        username: decoded.username,
        _id: new ObjectId(noteID)
      })
      if (data.acknowledged && data.deletedCount == 1) {
        return res.status(200)
          .json({ response: `Document with ID ${noteID} properly deleted.` });
      }
      else {
        return res.status(404).json({ error: `Note with ID ${noteID} belonging to the user not found` });
      }

    });
  } catch (error) {
    res.status(500)
      .json({ error: error.message })
  }

});

//patch request
app.patch("/editNote/:noteID", express.json(), async (req, res) => {
  try {
    //check note ID
    const noteID = req.params.noteID;
    if (!ObjectId.isValid(noteID)) {
      return res.status(400)
        .json({ error: "Bad request in relation to the :noteId URL parameter" });
    }

    // Basic body request check
    const { title, content } = req.body;
    if (!title && !content) {
      return res
        .status(400)
        .json({ error: "Title or content is required." });
    }

    const token = req.headers.authorization.split(" ")[1];
    jwt.verify(token, "secret-key", async (err, decoded) => {
      if (err) {
        return res.status(401).send("Unauthorized.");
      }

      const collection = db.collection(COLLECTIONS.notes);

      var data = {}
      if (title) {
        data = { ...data, title }
      }
      if (content) {
        data = { ...data, content }
      }
      const ogDoc = await collection.findOneAndUpdate({ _id: new ObjectId(noteID), username: decoded.username }, { $set: data });

      if (!ogDoc) {
        return res.status(404).json({ error: `Note with ID ${noteID} belonging to the user ${decoded.username} not found` });
      }

      return res.status(200).json({ response: "Note edited successfully" });


    })


  } catch (error) {
    res.status(500).json({ error: error.message })
  }
});