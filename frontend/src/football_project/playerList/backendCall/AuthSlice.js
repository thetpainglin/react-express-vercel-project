import {createAsyncThunk, createSlice} from "@reduxjs/toolkit";
import {login} from "./AuthAPI";

const initialState = {
    token : null
}

export const apiLogin = createAsyncThunk(
    'auth/login',
    async (users)=>{
        console.log("users => ",users);
        const response = await login(users.username , users.password);
        console.log("response data" , response.data);
        return response.data;
    }
)

const  AuthSlice = createSlice({
    name : "auth",
    initialState ,
    reducers : {
        logout : (state) => {
            state.token = undefined;
        }
    }
    , extraReducers : (builder)=>{
                        builder.addCase(apiLogin.fulfilled , (state , action)=>{
                            console.log("api login token data => ",action.payload);
                            if(action.payload.token){
                                state.token =  action.payload.token
                            }

                        })
}
});
export const {logout } = AuthSlice.actions;
export const selectAuth = (state)=> state.auth;
export default AuthSlice.reducer;