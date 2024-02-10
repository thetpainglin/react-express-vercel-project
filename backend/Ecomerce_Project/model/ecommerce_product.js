const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const ecommerceProject = new Schema({

    name: {
        type : String,
        required : true,
    },
    image : {
        type : String,
        required : true,
    },
    images : {
        type : Array,
        required : true,
    },
    price : {
        type : Number,
        required : true,
    },
    quantity : {
        type : Number,
        required : true,
    },
    details : {
        type : String,
        required : true,
    }

});
module.exports = mongoose.model('Ecommerce',ecommerceProject);