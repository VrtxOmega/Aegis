const fetch = require('node-fetch');

async function getWeather() {
  const response = await fetch('https://wttr.in/?format=j1');
  const data = await response.json();
  return { temperature: data.current_condition[0].temp_C, condition: data.current_condition[0].weatherDesc[0].value };}

module.exports = getWeather;