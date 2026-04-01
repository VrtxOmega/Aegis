const fs = require('fs');

function getProjects() {
  return new Promise((resolve) => {
    fs.readdirSync('C:\Users\rlope\projects').forEach(file => {
      resolve(`C:\Users\rlope\projects\${file}`);
    });
  });
}

module.exports = getProjects;