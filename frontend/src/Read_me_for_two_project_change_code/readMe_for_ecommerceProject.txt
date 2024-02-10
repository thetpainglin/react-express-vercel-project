in App.js
------------

import EcomerceProjectIndex from "./ecomerce/EcomerceProjectIndex";
import TestCode from "./ecomerce/TestCode";
import allCodeTest from "./TestCode/AllCodeTest";
import ReducerDemo from "./TestCode/ReducerDemo";

if you error , run this test code first!

<TestCode/> , and then

<EcomerceProjectIndex/>

in config/database.js
---------------------------
db: 'mongodb://localhost:27017/ecommerce_project'

in app.js
-----------

let productRouter = require('./Ecomerce_Project/route/productRouter');
  let bannerRouter = require('./Ecomerce_Project/route/bannerRouter');
  
  app.use('/api/products', productRouter);
  app.use('/api/banner', bannerRouter);
