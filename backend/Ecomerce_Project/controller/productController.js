const productService = require('../service/productService');


let getAllProducts = async function (req, res, next){
    try {
        console.log("getAllPlayer => ",req);
        let product = await productService.getAllProducts();
        if(!product) throw Error('No Player');
        console.log("data => ",product)
        await res.status(200).json(product);
    }
    catch (e){
        await res.status(400).json({msg : e});
    }

}

let newProduct = async function (req, res, next){
    try {

        let body = req.body;
        console.log("body => ",body);
        let product = await productService.newProduct(body);
        if(!product) throw Error('No product');
        console.log("data => ",product)
        await res.status(200).json(product);
    }
    catch (e){
        await res.status(400).json({msg : e});
    }

}

let updateProduct = async function (req, res, next){
    try {

        let productId = req.params['productId'];
        let body = req.body;
        console.log("body => ",productId);
        let product = await productService.updateProduct(productId , body);
        if(!product) throw Error('No product');
        console.log("data => ",product)
        await res.status(200).json(product);
    }
    catch (e){
        await res.status(400).json({msg : e});
    }

}

module.exports = {
    getAllProducts,
    newProduct,
    updateProduct,
}