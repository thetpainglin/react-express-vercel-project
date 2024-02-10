const userService = require('../Services/userService');
const {config} = require("../config/Config");
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const registerUser = async function(req, res, next){

    let username = req.body['username'];
    let password = req.body['password'];

    try{
        console.log("user ",req.body );

        let user =await userService.register(username,password);
        //res.status(200).send({token});
        let payload = {id : user._id};
        let token = jwt.sign(payload , config.TOKEN_SECRET);
         res.status(200).send({token});
    }
    catch (e) {
        console.log("error => ",e)
         res.status(400).json({message : "User already existed"});
    }
}

const login = async (req,res,next)=>{

    try{
        let username = req.body['username'];
        let password = req.body['password'];

        let user = await userService.login(username,password);
        let payload = {id : user._id};
        let token = jwt.sign(payload, config.TOKEN_SECRET);
        res.status(200).send({token});
    }
   catch (e) {
       console.log('error =>',e);
       res.status(404).send({message : "Invalid user"})
   }

}

const getAllUser = async function(req , res , next){
    //let data = req.params.userId;
   // console.log("userId => ",data);
    try{
        let user =await userService.getAllUser();
        if(!user) throw Error("No User");
        res.status(200).json(user);
    }
    catch(e){
        console.log("error ",e);
        await res.status(400).json({msg : "No found user"});
    }
};


module.exports = {
    registerUser,
   getAllUser,
    login,
}