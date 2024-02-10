const express = require("express");
const router = express.Router();
const playerReview = require('../Controller/playerReviewController');

router.get('/',playerReview.getAllPlayerReview);
router.get('/:nameId',playerReview.getPlayerById);
router.get('/player/:playerId',playerReview.getReviewByPlayerId);
router.post('/',playerReview.playerReviewCreate);
router.delete('/:playerId',playerReview.deletePlayerReview);
router.put('/:playerId',playerReview.editPlayerReview);

module.exports = router;