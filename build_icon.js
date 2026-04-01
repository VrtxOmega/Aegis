const pngToIco = require('png-to-ico');
const fs = require('fs');
const path = require('path');

const input = path.join(__dirname, 'src', 'assets', 'icon.png');
const output = path.join(__dirname, 'src', 'assets', 'icon.ico');

pngToIco(input)
    .then(buf => {
        fs.writeFileSync(output, buf);
        console.log('ICO created:', output);
    })
    .catch(err => {
        console.error('ICO conversion failed:', err);
    });
