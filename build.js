
const fs = require('fs');
const path = require('path');

// Simple CSS minifier
function minifyCSS(css) {
  return css
    .replace(/\/\*[\s\S]*?\*\//g, '') // Remove comments
    .replace(/\s+/g, ' ') // Replace multiple spaces with single space
    .replace(/;\s*}/g, '}') // Remove semicolon before closing brace
    .replace(/\s*{\s*/g, '{') // Remove spaces around opening brace
    .replace(/}\s*/g, '}') // Remove spaces after closing brace
    .replace(/;\s*/g, ';') // Remove spaces after semicolon
    .trim();
}

// Simple JS minifier (basic)
function minifyJS(js) {
  return js
    .replace(/\/\*[\s\S]*?\*\//g, '') // Remove block comments
    .replace(/\/\/.*$/gm, '') // Remove line comments
    .replace(/\s+/g, ' ') // Replace multiple spaces with single space
    .replace(/\s*([{}();,=+\-*\/])\s*/g, '$1') // Remove spaces around operators
    .trim();
}

// Minify CSS
const cssContent = fs.readFileSync('style.css', 'utf8');
const minifiedCSS = minifyCSS(cssContent);
fs.writeFileSync('style.min.css', minifiedCSS);

// Minify JavaScript files
const jsFiles = ['script.js', 'secure-logger.js', 'secure-ban-system.js'];
jsFiles.forEach(file => {
  if (fs.existsSync(file)) {
    const jsContent = fs.readFileSync(file, 'utf8');
    const minifiedJS = minifyJS(jsContent);
    const minFileName = file.replace('.js', '.min.js');
    fs.writeFileSync(minFileName, minifiedJS);
  }
});

console.log('✅ Assets minified successfully!');
console.log('- style.css → style.min.css');
console.log('- script.js → script.min.js');
console.log('- secure-logger.js → secure-logger.min.js');
console.log('- secure-ban-system.js → secure-ban-system.min.js');
