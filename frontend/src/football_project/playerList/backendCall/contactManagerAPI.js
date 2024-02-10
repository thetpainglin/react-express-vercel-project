import {API_URL} from "../../../setting/API";
import axios from "../../../setting/our_axios";

const API = API_URL+"KaeDaung/manager";

export function getAllContact(){
    return axios.get(API);
}
export function addNewContact(contacts){
    return axios.post(API, contacts);
}

export function editContactManager(contacts){
    return axios.put(API+`/${contacts._id}`, contacts);
}

export function deleteContactManager(contactId){
    return axios.delete(API+`/${contactId}`);
}