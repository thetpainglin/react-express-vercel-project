let createError = require('http-errors');
let express = require('express');
let path = require('path');
let cookieParser = require('cookie-parser');
let logger = require('morgan');
const cors = require('cors');

const mongoose = require('mongoose');
const {db} = require('./config/database');

let auth = require('./middleWare/auth');
let indexRouter = require('./routes/index');


let productRouter = require('./Ecomerce_Project/route/productRouter');
let bannerRouter = require('./Ecomerce_Project/route/bannerRouter');

//const {entry} = require("react-circle-slider/webpack.config");

var app = express();

app.use(cors(
        {
          origin: 'https://react-frontend-api.vercel.app',
          methods: ["POST","GET"],
          credentials: true
        }
));

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');


app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

mongoose.connect(db,{
  useNewUrlParser : true,
  useUnifiedTopology : true,
}).then(()=>console.log("Mongodb connected!")).catch(err => console.log(err));


app.use('/', indexRouter);

app.use('/api/products', productRouter);
app.use('/api/banner', bannerRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
