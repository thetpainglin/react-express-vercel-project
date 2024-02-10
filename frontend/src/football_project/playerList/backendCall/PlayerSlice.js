import {createAsyncThunk, createSlice} from "@reduxjs/toolkit";
import {AddNewPlayer, deletePlayer, getAllPlayer, getUpdatePlayer} from "./PlayerAPI";

export const apiGetAllPlayer = createAsyncThunk(
    'kaeDaungPlayer/getAllPlayer',
    async ()=>{
        const response = await getAllPlayer();
        console.log('get all player ',response.data);
        return response.data;
    }
)

export const apiAddNewPlayer = createAsyncThunk(
    'kaeDaungPlayer/AddNewPlayer',
    async (playerData)=>{
        const response = await AddNewPlayer(playerData);
        console.log('add new player => ',response.data);
        return response.data;
    }
)

export const apiUpdatePlayer = createAsyncThunk(
    'kaeDaungPlayer/getUpdatePlayer',
    async (updatePLayer)=>{
        const response = await getUpdatePlayer(updatePLayer);
        console.log('update Player ',response.data);
        return response.data;
    }
)

export const apiDeletePlayer = createAsyncThunk(
    'kaeDaungPlayer/deletePlayer',
    async (playerId)=>{
        const response = await deletePlayer(playerId);
        console.log('delete palyer => ',response.data);
        return response.data;
    }
)

export const PlayerSlice = createSlice({
    name : 'kaeDaungPlayer',
    initialState : {
        players : []
    },
    reducers : {

    },
    extraReducers : ((builder) =>{
        builder.addCase(apiGetAllPlayer.fulfilled,(state,action)=>{
            console.log("action payload ",action.payload);
            state.players = action.payload;
        })
            .addCase(apiAddNewPlayer.fulfilled,(state,action)=>{
                console.log("calling apiNewAddPlayer => ",action.payload);
                state.players = [...state.players , action.payload];
            })
            .addCase(apiUpdatePlayer.fulfilled,(state,action)=>{
                console.log("calling apiUpdate => ",action.payload);
                state.players = state.players.map(playerData => playerData._id === action.payload._id ? action.payload : playerData );
            })
            .addCase(apiDeletePlayer.fulfilled,(state,action)=>{
                console.log("calling apiUpdatePlayer => ",action.payload);
                state.players = state.players.filter((players)=>players._id != action.payload._id)
            })

    })
})

export const selectPlayer = (state,playerId)=>state.kaeDaungPlayer.players.filter(player => player._id == playerId)[0];
export const AllPlayerSelect = state => state.kaeDaungPlayer.players;

export default PlayerSlice.reducer;