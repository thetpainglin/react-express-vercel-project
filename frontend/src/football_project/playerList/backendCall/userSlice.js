import {createSlice} from "@reduxjs/toolkit";

const userSlice = createSlice({
    name : "user",
    initialState : {
        user : "",
    },
    reducers : {
        checkUser : (state , action) => {
            state.user = action.payload.username;
        }
    }

})

export const {checkUser} = userSlice.actions;
export const userSelector = state => state.user.user;

export default userSlice.reducer;