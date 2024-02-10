import {createAsyncThunk, createSlice} from "@reduxjs/toolkit";
import {getAllBanner} from "./banner_API";


export const apiGetAllBanner = createAsyncThunk(
    'bannerProduct/getAllBanner',
    async ()=>{
        const response = await getAllBanner();
        console.log("get all banner in backend => ",response.data);
        return response.data;
    }
)

const banner_reducer = createSlice({
    name : "bannerProduct",
    initialState : {
        banners : []
    },
    reducers : {

    },
    extraReducers : (builder) => {
        builder.addCase(apiGetAllBanner.fulfilled,(state,action)=>{
            state.banners = action.payload;
        })
    }
});

export const allBanner = state => state.bannerProduct.banners;

export default banner_reducer.reducer;