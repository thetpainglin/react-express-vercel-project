import {API_URL} from "../../../setting/API";
import axios from "../../../setting/our_axios";

//kaeDaung/footballClub

const API = API_URL+"users/login";

export function login(username , password){
    console.log("api username password => ",API,username , password);
    return axios.post(API, {
        username,
        password
    });
}
