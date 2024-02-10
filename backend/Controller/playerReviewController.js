const playerReviewController = require('../Services/playerReviewService');

let getAllPlayerReview = async (req,res,next)=>{
    console.log("getAllPlayerReview => ");
    try{
        let playerReview = await playerReviewController.getAllPlayerReview();
        if(!playerReview) throw Error("No Review");
        await res.status(200).json(playerReview);
    }
    catch (e) {
        await res.status(400).json({msg : e});
    }
}

let getPlayerById = async (req, res, next)=>{
    console.log("getAllPlayerReview => ");
    try{
        let id = req.params["nameId"];
        let playerReview = await playerReviewController.getPlayerById(id);
        if(!playerReview) throw Error("No Review");
        await res.status(200).json(playerReview);
    }
    catch (e) {
        await res.status(400).json({msg : e});
    }
}

let getReviewByPlayerId = async (req, res, next)=>{
    try{
        let id = req.params["playerId"];
        let playerReview = await playerReviewController.getReviewByPlayerId(id);
        if(!playerReview) throw Error("No Review");
        await res.status(200).json(playerReview);
    }
    catch (e) {
        await res.status(400).json({msg : e});
    }
}

let playerReviewCreate = async (req, res, next)=>{
    console.log("req body => ",req.body);
    try{
        let body = req.body;
        let review = await playerReviewController.NewPlayerReview(body);
        if(!review) throw Error("No Review");
        await res.status(200).json(review);
    }
    catch (e) {
        await res.status(400).json({msg : e});
    }
}

let deletePlayerReview = async (req, res, next)=>{
    console.log("req body => ",req.params);
    try{
        let playerId = req.params["playerId"];
        let review = await playerReviewController.deletePlayerReview(playerId);
        if(!review) throw Error("No Delete!");
        await res.status(200).json(review);
    }
    catch (e) {
        await res.status(400).json({msg : e});
    }
}

let editPlayerReview = async (req, res, next)=>{
    console.log("req body => ",req.params);
    try{
        let playerId = req.params["playerId"];
        let playerReview = req.body;
        let review = await playerReviewController.editPlayerReview(playerId , playerReview);
        if(!review) throw Error("No edit player!");
        await res.status(200).json(review);
    }
    catch (e) {
        await res.status(400).json({msg : e});
    }
}

module.exports = {
    playerReviewCreate,
    getAllPlayerReview,
    getPlayerById,
    getReviewByPlayerId,
    deletePlayerReview,
    editPlayerReview,
}