if (location.search.includes("failed")) document.getElementById("err").style.display = "block";
// Plain HTTP from another machine: the password and the session travel unencrypted (#97).
if (location.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]"].includes(location.hostname))
  document.getElementById("insecure").hidden = false;
