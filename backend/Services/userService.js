const User = require('../model/users');
const bcrypt = require("bcryptjs");

const register = async (username , passwords)=>{
    console.log("user service")
    let salt = await bcrypt.genSalt(10);
    let hashPassword = await bcrypt.hash(passwords,salt);

    let user = new User({
        username : username ,
        password : hashPassword,
    });
    console.log("user ",user );
    return user.save();
   /* user.save((err , registerUser )=>{
        if(err){
            console.log(err);
            res.status(400).send({message : "User already existed!"});
        }else{
            //create payload then Generate an access token
            let payload = {id : registerUser._id};
            const token = jwt.sign(payload , config.TOKEN_SECRET);
            res.status(200).send({token});
        }
    });*/
}

const login = async (username , pass )=>{

    console.log("username ",username," password ",pass)
    let filter = {
        username : username,
    }
    let user =await User.findOne(filter);
    console.log("user data => ",user)

    if(user){
        console.log("user.password ",user.password," password => ",pass);
        let validPass = await bcrypt.compare(pass , user.password);
        console.log("valid password => ",validPass);
        if(validPass){
            return user;
        }
         else   throw Error("Invalid user or password")

    }


}

const getAllUser = async ()=>{
    console.log("user => ",User.find());
    return User.findOne();
};

module.exports = {
    getAllUser,
    register,
    login,
}