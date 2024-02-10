const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const FootballSchema = new Schema({
    name: {
        type : String,
        required : true,
    },
    image : {
        type : String,
        required : true,
    },
    father: {
        type : String,
        required : true,
    },
    mother: {
        type : String,
        required : true,
    },
    age: {
        type : Number,
        required : true,
    },
    address: {
        type : String ,
        required : true,
    },
    assistant : {
        type : Number,
    },
    goals : {
        type : Number
    },
    height : {
        type : String
    },
    position : {
        type : String
    }
});
module.exports = mongoose.model('kaeDaung',FootballSchema);