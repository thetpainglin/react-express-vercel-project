
const Ecommerce = require("../model/ecommerce_product");

const getAllProducts = async function(){
    console.log("ecommerce all product => ",Ecommerce)
    return Ecommerce.find();
}

const newProduct = async function(products){
    console.log("ecommerce new product => ",Ecommerce)
    let product = new Ecommerce(products);
    return product.save();
}

const updateProduct = async function(productId , product){
    return Ecommerce.findByIdAndUpdate(productId,product,{new : true});
}

module.exports = {
    getAllProducts,
    newProduct,
    updateProduct,
}