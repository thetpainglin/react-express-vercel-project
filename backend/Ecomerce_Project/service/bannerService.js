
const EcommerceBanner = require("../model/ecommer_banner");
const mongoose = require("mongoose");

const getAllBanner = async function(){
    console.log("ecommerce all product => ",EcommerceBanner)
    return EcommerceBanner.find().populate('banner');
}

const newBanner = async function(banners){
    console.log("ecommerce new product => ",EcommerceBanner)

    let newProduct = new EcommerceBanner({
        banner : mongoose.Types.ObjectId(banners.banner),
        image : banners.image,
        Desc : banners.Desc,
        saleTime : banners.saleTime,
        ButtonText : banners.ButtonText,
        product : banners.product,
        SmallText : banners.SmallText,
        MidText : banners.MidText,
        LargeText1 : banners.LargeText1,
        LargeText2 : banners.LargeText2,
        Discount : banners.Discount
    });

    return newProduct.save();
}

module.exports = {
    getAllBanner,
    newBanner,
}