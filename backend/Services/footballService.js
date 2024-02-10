let kaeDaung = require("../model/kaedaung");


/*
Mock json
********
return  [
          {
              name : "Thet Paing Lin",
              age : 25,
              address : "Kani TownShip , Kae Daung Village"
          },
          {
              name : "Aung Kyaw Moe ",
              age : 22,
              address: "Kani TownShip , Kae Daung Village"
          }
      ];
*/
const getAllPlayer = async function(){
    console.log("kaeDaung => ",kaeDaung)
    return kaeDaung.find();
}

const getOnePlayer = async function(id){
    return kaeDaung.findById(id);
}

const searchByName = async function(player){
     return kaeDaung.find({
        name : {$regex :player , $options : 'i'}
    });
}

const NewPlayer = async function(body){
    const newPlayer = new kaeDaung(body);
    return newPlayer.save();
}

const PlayerUpdate = async function(getId , player){
    return kaeDaung.findByIdAndUpdate(getId,player,{new : true});
}

const deletePlayer = async function(playerId){
    return kaeDaung.findByIdAndDelete(playerId);
}

module.exports = {
    getAllPlayer,
    getOnePlayer,
    searchByName,
    NewPlayer,
    PlayerUpdate,
    deletePlayer,
}