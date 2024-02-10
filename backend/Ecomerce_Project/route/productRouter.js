let express = require("express");
let router = express.Router();
let productController = require('../controller/productController');

router.get('/',productController.getAllProducts);
router.post('/',productController.newProduct);
router.put('/:productId',productController.updateProduct)

module.exports = router
