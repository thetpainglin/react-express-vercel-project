import {API_URL} from "./API";
const axios = require('axios');
axios.defaults.headers.post['Content-Type'] = 'application/json';
axios.defaults.headers.post['Access-Control-Allow-Origin'] = '*';
axios.defaults.headers.get['Access-Control-Allow-Origin'] = '*';
let store;

export const injectStore = (st)=>{
    store = st;
}
/*
axios.interceptors.request.use(async function(config){
        //console.log("API request store => ",store.getState());
        const authUser = store.getState().auth;
        console.log("api request auth user => ",authUser);

        if(authUser.token){
            config.headers.Authorization = 'Bearer '+authUser.token;
        }
        return  config;
    },function (error){
        console.log("Axios interceptor error => ",error);
        return error;
    }
)
*/
export default axios;
