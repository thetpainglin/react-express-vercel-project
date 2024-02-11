let jwt = require('jsonwebtoken');
const {config} = require("../config/Config");

const verifyUserToken = (req,res,next)=>{
    
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
