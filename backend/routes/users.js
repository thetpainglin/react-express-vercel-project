const express = require('express');
const router = express.Router();
const controller = require('../Controller/userController');

router.get('/', controller.getAllUser);
router.post('/login',controller.login);
router.post('/',controller.registerUser);
/* GET users listing. */



module.exports = router;
