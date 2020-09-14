const bcrypt = require('bcryptjs')

module.exports = {
  register: async (req, res) => {
    /*
    TODO get email, password from req.body
    TODO check if user already exists. If they do, reject request
    TODO salt and hash password
    TODO create the user in the db
    TODO put the user on session
    TODO send confirmation
    */
    const db = req.app.get('db')
    //destructure values from db
    const { email, password } = req.body

    // See if user exists in the db
    const [user] = await db.check_user([email]) // [user] allows us to pull off the first item of the array

    //If they exist, reject the request
    if (user) {
      return res.status(409).send('user already exists')
    }

    //salt and hash the password
    const salt = bcrypt.genSaltSync(10)
    const hash = bcrypt.hashSync(password, salt)

    //Create the user in the db
    const [newUser] = await db.register_user([email, hash])

    //Put new user on session
    req.session.user = newUser

    //? Send confirmation email

    //Send confirmation
    res.status(200).send(req.session.user)


  },
  login: async (req, res) => {
    //TODO get email and password from req.body
    //TODO see if the user exists. If they don't, reject the request
    //TODO Compare password and hash. if there is a mismatch, reject the request
    //TODO Put the user on session
    //TODO send confirmation

    const db = req.app.get('db')
    // destructure email and password from req.body
    const { email, password } = req.body

    //check if user exists
    const [existingUser] = await db.check_user([email])
    //if they don't reject request
    if (!existingUser) {
      return res.status(404).send('User not found')
    }

    //Compare password and hash
    const isAuthenticated = bcrypt.compareSync(password, existingUser.hash)

    //If there is a mismatch, reject the request
    if (!isAuthenticated) {
      return res.status(403).send('Incorrect email or password')
    }

    delete existingUser.hash

    //Put user on session
    req.session.user = existingUser

    //Send confirmation
    res.status(200).send(req.session.user)
  },
  logout: (req, res) => {
    req.session.destroy()
    res.sendStatus(200) //use this then you don't really have content to send back
  },
  getUser: (req, res) => {
    //TODO Get user from session

    if (req.session.user) {
      res.status(200).send(req.session.user)
    } else {
      res.status(400).send('No session found')
    }

  },
}
