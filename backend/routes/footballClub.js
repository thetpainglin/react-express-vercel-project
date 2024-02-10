var express = require("express");
var router = express.Router();
let footballController = require('../Controller/footballController');

router.get('/',footballController.getAllPlayer);
router.get('/:playerId',footballController.searchById);
router.get('/playerName/:name',footballController.searchByName);
router.post('/',footballController.NewPlayer);
router.put('/:playerId',footballController.playerUpdate);
router.delete('/:playerId',footballController.deletePlayer);


module.exports = router
