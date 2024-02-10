let express = require("express");
let router = express.Router();
let bannerController = require('../controller/bannerController');

router.get('/',bannerController.getAllBanner);
router.post('/',bannerController.newBanner);

module.exports = router
