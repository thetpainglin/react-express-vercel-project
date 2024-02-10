const PlayerReviewService = require('../model/playerReview');
const mongoose = require("mongoose");

let getAllPlayerReview = async ()=>{
    return PlayerReviewService.find().populate('player');
}

let getPlayerById = async (nameId)=>{
    return PlayerReviewService.findById(nameId).populate('player');
}

let getReviewByPlayerId = async (nameId)=>{
    return PlayerReviewService.find({player:nameId}).populate('player');
}

let NewPlayerReview = async (playerData)=>{
    let NewReview = new PlayerReviewService({
        player : mongoose.Types.ObjectId(playerData.player),
        playerRating : playerData.playerRating,
        playerScore : playerData.playerScore,
    });
    console.log("mongoose.Types => ",mongoose.Types);
    return NewReview.save();
}

let deletePlayerReview = async (nameId)=>{
    return PlayerReviewService.findByIdAndDelete(nameId);
}

const editPlayerReview = async function(playerId , player){
    return PlayerReviewService.findByIdAndUpdate(playerId,player,{new : true});
}


module.exports = {
    getAllPlayerReview,
    NewPlayerReview,
    getPlayerById,
    getReviewByPlayerId,
    deletePlayerReview,
    editPlayerReview,
}
