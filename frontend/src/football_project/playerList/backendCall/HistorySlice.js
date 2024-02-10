import {createSlice} from "@reduxjs/toolkit";

const HistorySlice = createSlice({
    name : "comment",
    initialState : {
        comments : [] ,
        player : "",
    },
    reducers : {
        commentToAdd : (state , action) => {
            state.comments = [...state.comments , action.payload];
        }
    }

})

export const {commentToAdd} = HistorySlice.actions;
export const commentSelector = state => state.comment.comments;

export default HistorySlice.reducer;