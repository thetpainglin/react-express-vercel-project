import {API_URL} from "../../../setting/API";
import axios from "../../../setting/our_axios";

const API = API_URL+"kaeDaung/playerReview";

export function playerReview(){
    console.log("player Review => ",API);
    return axios.get(API);  //MAY BE PROMISE
}

export function playerReviewById(playerId){
    console.log("api => ",API);
    return axios.get(API+`/player/${playerId}`);  //MAY BE PROMISE
}
export function getPlayerReview(playerData){
    console.log("api => ",API);
    return axios.post(API,playerData);  //MAY BE PROMISE
}
export function deletePlayerReview(playerId){
    console.log("api => ",API);
    return axios.delete(API+`/${playerId}`);  //MAY BE PROMISE
}
export function editPlayerReview(reviewPlayer){
    console.log("api => ",API);
    return axios.put(API+`/${reviewPlayer._id}`,reviewPlayer);  //MAY BE PROMISE
}

