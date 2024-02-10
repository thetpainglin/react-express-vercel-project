import {API_URL} from "../../setting/API";
import axios from "../../setting/our_axios";

//products/ in ecommerce

const API = API_URL+"banner/";

export function getAllBanner(){
    console.log("getAllBanner calling !" , API);
    return axios.get(API);
}
