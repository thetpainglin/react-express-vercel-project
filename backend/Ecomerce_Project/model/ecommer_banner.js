const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const ecommerceBanner = new Schema({
    banner : {
        type : Schema.ObjectId,
        ref : 'Ecommerce'
    },
    image : {
        type : String,
        required : true,
    },
    ButtonText : {
        type : String,
        required : true,
    },
    product : {
        type : String,
        required : true,
    },
    Desc : {
        type : String,
        required : true,
    },
    SmallText : {
        type : String,
        required : true,
    },
    MidText : {
        type : String,
        required : true,
    },
    LargeText1 : {
        type : String,
        required : true,
    },
    LargeText2 : {
        type : String,
        required : true,
    },
    Discount : {
        type : String,
        required : true,
    },
    saleTime : {
        type : String,
        required : true,
    },

});
module.exports = mongoose.model('EcommerceBanner',ecommerceBanner);