in App.js 
-----------
for kaeDaung football club Project

import the followings.........

import {userSelector} from "./football_project/playerList/backendCall/userSlice";
import IndexKaeDaungFootballClub from "./football_project/playerList/IndexKaeDaungFootballClub";

run this code 
<IndexKaeDaungFootballClub/>

in config/database.js
==============
change this database : db: 'mongodb://localhost:27017/kaedaung_football_club'

in app.js
----------
these code are need !

app.use('/api/users', usersRouter);
  app.use('/api/kaeDaung/footballClub', FootballRouter);
  app.use('/api/kaeDaung/manager', contactManagerRouter);
  app.use('/api/kaeDaung/playerReview', auth.verifyUserToken, PlayerReviewRouter);
  
  let usersRouter = require('./routes/users');
  let FootballRouter = require('./routes/footballClub');
  let contactManagerRouter = require('./routes/contactManagerRoute');
  let PlayerReviewRouter = require('./routes/playerReview');
