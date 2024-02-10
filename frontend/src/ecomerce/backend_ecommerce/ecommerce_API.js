import {API_URL} from "../../setting/API";
import axios from "../../setting/our_axios";

//products/ in ecommerce

const API = API_URL+"products/";

export function getAllProducts(){
    return axios.get(API);
}
