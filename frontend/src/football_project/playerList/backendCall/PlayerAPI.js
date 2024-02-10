import {API_URL} from "../../../setting/API";
import axios from "../../../setting/our_axios";

//kaeDaung/footballClub

const API = API_URL+"kaeDaung/footballClub/";

export function getAllPlayer(){
    console.log("api => ",API);
    return axios.get(API);  //MAY BE PROMISE
}

export function AddNewPlayer(playerData){
    console.log("api => ",API);
    return axios.post(API,playerData);  //MAY BE PROMISE
}

export function getUpdatePlayer(updatePlayer){
    console.log("api => ",API);
    return axios.put(API+`${updatePlayer._id}`,updatePlayer);  //MAY BE PROMISE
}

export function deletePlayer(playerId){
    console.log("api => ",API);
    return axios.delete(API+`${playerId}`);  //MAY BE PROMISE
}
