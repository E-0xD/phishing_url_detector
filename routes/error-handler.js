module.exports = (deps) => {
  // Error-handling middleware (signature with 4 args)
  return (err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).render('error', {
      title: 'Error',
      error: err?.message || String(err)
    });
  };
};