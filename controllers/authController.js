const usersDB = {
  users: require("../model/users.json"),
  setUsers: function (data) {
    this.users = data;
  },
};
const bcrypt = require("bcrypt");

const jwt = require("jsonwebtoken");
require("dotenv").config();
const fsPromises = require("fs").promises; // no Mongo or db tech integrated
const path = require("path");

const handleLogin = async (req, res) => {
  const { user, pwd } = req.body;
  if (!user || !pwd)
    return res
      .status(400)
      .json({ message: "Username and password are required." });
  const foundUser = usersDB.users.find((person) => person.username === user);
  if (!foundUser) return res.sendStatus(401); //Unauthorized
  // evaluate password
  const match = await bcrypt.compare(pwd, foundUser.password);
  if (match) {
    // create JWTs
    const accessToken = jwt.sign(
        { "username": foundUser.username },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '30s'}
    )
    const refershToken = jwt.sign(
        { "username": foundUser.username },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '1d'}
    )
    // save refersh token for current user to DB so that the user can log out 
    const otherUsers = usersDB.users.filter(person => person.username !== foundUser.username)
    const currentUser = {...foundUser, refershToken}
    usersDB.setUsers([...otherUsers], currentUser)
    await fsPromises.writeFile(
        path.join(__dirname, '..', 'model', 'users.json'),
        JSON.stringify(usersDB.users)
    )
    // send tokens: the RT should be in HTTPOnly cookie
        res.cookie('jwt', refershToken, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 })// this is in miliseconds, so one day
        res.json({ accessToken })

    res.json({ success: `User ${user} is logged in!` });
  } else {
    res.sendStatus(401);
  }
};

module.exports = { handleLogin };
