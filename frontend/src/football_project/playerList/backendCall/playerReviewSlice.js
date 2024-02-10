import {createAsyncThunk, createSlice} from "@reduxjs/toolkit";
import {playerReviewById, getPlayerReview, deletePlayerReview, editPlayerReview} from "./playerReviewAPI";

export const APIPlayerReviewById = createAsyncThunk(
    'playerReview/playerReviewById',
    async (playerId)=>{
        console.log("api all get player");
        const response = await playerReviewById(playerId);

        return response.data;
    });

export const APIGetPlayerReview = createAsyncThunk(
    'playerReview/getPLayerReview',
    async (player)=>{
        const response = await getPlayerReview(player);

        return response.data;
    })

export const apiDeletePlayerReview = createAsyncThunk(
    'playerReview/deletePlayerReview',
    async (player)=>{
        const response = await deletePlayerReview(player);

        return response.data;
    })

export const apiEditPlayerReview = createAsyncThunk(
    'playerReview/editPlayerReview',
    async (reviewPlayer)=>{
        const response = await editPlayerReview(reviewPlayer);

        return response.data;
    })


export const playerReviewSlice = createSlice({
    name : 'playerReview',
    initialState : {
        playerReviews : []
    },
    reducers : {

    },
    extraReducers : (builder)=>{
                    builder.addCase(APIPlayerReviewById.fulfilled,(state , action)=>{
                            //console.log("player review by id => ",action.payload);
                            state.playerReviews = action.payload;
                            })
                        .addCase(APIGetPlayerReview.fulfilled,(state , action)=>{
                            console.log("player review  => ",action.payload);
                            state.playerReviews = [...state.playerReviews,action.payload];
                        })
                        .addCase(apiEditPlayerReview.fulfilled,(state , action)=>{
                            console.log("player edit review  => ",action.payload);
                            state.playerReviews = state.playerReviews.map(review => review._id === action.payload._id ? action.payload : review)
                        })
                        .addCase(apiDeletePlayerReview.fulfilled,(state , action)=>{
                            console.log("player review  => ",action.payload);
                            state.playerReviews = state.playerReviews.filter(review=>review._id != action.payload._id)
                        })
    }
})

export const selectReviewByPlayerId = (state,playerId)=> {
    console.log("state in player review slice ",state," player Id => ",playerId);
    return state.playerReview.playerReviews.filter(result => result.player._id === playerId)
};

export default playerReviewSlice.reducer;