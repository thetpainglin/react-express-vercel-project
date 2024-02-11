let jwt = require('jsonwebtoken');
const {config} = require("../config/Config");

const verifyUserToken = (req,res,next)=>{

    res.setHeader('Access-Control-Allow-Credentials', true)
  res.setHeader('Access-Control-Allow-Origin', '*')
  // another common pattern
  // res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT')
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  )
    
    let token = req.headers.authorization;
    if(!token) return res.status(401).send("Access Denied/ Unauthorized request");

    try{

        token = token.split(' ')[1];  //remove barer from string
        console.log("token => ",token);
        if(token == 'null' || !token) return res.status(401).send("Unauthorized access");

        let verifiedUser = jwt.verify(token , config.TOKEN_SECRET);
        if(!verifiedUser) return res.status(401).send('Unauthorized access');

        req.user = verifiedUser;
        next();


    }catch (e) {
        console.log(e);
        res.status(400).send("Invalid Token");
    }

}

module.exports = {
    verifyUserToken,
}
