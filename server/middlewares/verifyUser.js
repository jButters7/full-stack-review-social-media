module.exports = (req, res, next) => {
  if (req.session.user) {
    next()
  } else {
    res.status(401).send('Please log in to perform this action')
  }
}