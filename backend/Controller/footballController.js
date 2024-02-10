const footballService = require('../Services/footballService');


let getAllPlayer = async function (req, res, next){
    try {
        console.log("getAllPlayer => ",req);
        let kaeDaung = await footballService.getAllPlayer();
        if(!kaeDaung) throw Error('No Player');
        console.log("data => ",kaeDaung)
        return await res.status(200).json(kaeDaung);
    }
    catch (e){
        await res.status(400).json({msg : e});
    }
}

let searchById = async function(req,res,next){
    console.log("req => ",req.params);

    try{
        const id = req.params["playerId"];
        let player = await footballService.getOnePlayer(id);
        if(!player) throw Error("No Player");
         await res.status(200).json(player);

    }catch (e){
        await res.status(400).json({msg : e});
    }
}

const searchByName = async function(req,res,next){
    console.log("name => ",req.params["name"]);
    try{
        let name = req.params["name"];
        let player = await footballService.searchByName(name);
        if(!player) throw Error("No Player");
         await res.status(200).json(player);
    }catch (e) {
         await res.status(400).json({msg : e});
    }
}

let NewPlayer = async function(req,res,next){
    try{
        const body = req.body;
        const footballClub =await footballService.NewPlayer(body);
        if(!footballClub) throw Error("Cannot created");
        await res.status(201).json(footballClub);

    }catch (e) {
        await res.status(400).json({message : e})
    }
}

const playerUpdate = async function(req,res,next){
    try{
        const id = req.params["playerId"];
        const updateData = req.body;
        console.log("updata data => ",updateData);
        const update =await footballService.PlayerUpdate(id,updateData,{new : true});
        if(!update) throw Error("No Update");
        await res.status(200).json(update);
    }
    catch (e) {
        await res.status(400).json({msg : e})
    }
}

const deletePlayer = async function(req,res,next){
    console.log("name => ",req.params["playerId"]);
    try{
        let playerId = req.params['playerId'];
        let player = await footballService.deletePlayer(playerId);
        if(!player) throw Error("No Player");
        await res.status(200).json(player);
    }catch (e) {
        await res.status(400).json({msg : e});
    }
}

module.exports = {
    getAllPlayer,
    searchById,
    searchByName,
    NewPlayer,
    playerUpdate,
    deletePlayer,
}