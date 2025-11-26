require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

app.get('/auth/login', (req, res) => {
  if (!CLIENT_ID) return res.status(500).send('GITHUB_CLIENT_ID not configured');
  const state = crypto.randomBytes(16).toString('hex');
  res.cookie('oauth_state', state, { httpOnly: true, sameSite: 'lax' });
  const redirect = `https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(BASE_URL + '/auth/callback')}&scope=read:user%20user:email&state=${state}`;
  res.redirect(redirect);
});

app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  const cookieState = req.cookies.oauth_state;
  if (!state || !cookieState || state !== cookieState) {
    return res.status(400).send('Invalid or missing state');
  }
  try {
    const tokenResp = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      redirect_uri: `${BASE_URL}/auth/callback`,
      state
    }, {
      headers: { Accept: 'application/json' }
    });
    const access_token = tokenResp.data.access_token;
    if (!access_token) return res.status(400).send('No access token received');
    const userResp = await axios.get('https://api.github.com/user', {
      headers: { Authorization: `token ${access_token}`, 'User-Agent': 'my-portfolio-app' }
    });
    const user = userResp.data;
    res.send(`<!doctype html><html><head><meta charset="utf-8"><title>Logged In</title></head><body><h1>Logged in as ${user.login}</h1><p>Name: ${user.name || 'n/a'}</p><p><img src="${user.avatar_url}" width="100" alt="avatar"></p><p><a href="/">Return to site</a></p></body></html>`);
  } catch (err) {
    console.error(err.response && err.response.data || err.message);
    res.status(500).send('OAuth exchange failed');
  }
});

app.listen(PORT, () => console.log(`Server running on ${BASE_URL}`));
