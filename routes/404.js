module.exports = (deps) => {
  // 404 handler middleware
  return (req, res) => {
    res.status(404).render('404', {
      title: '404 - Page Not Found'
    });
  };
};