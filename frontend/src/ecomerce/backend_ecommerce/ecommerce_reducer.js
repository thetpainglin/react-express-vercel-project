import {createAsyncThunk, createSlice} from "@reduxjs/toolkit";
import {getAllProducts} from "./ecommerce_API";


export const apiGetAllProducts = createAsyncThunk(
    'ecommerce/getAllProducts',
    async ()=>{
        const response = await getAllProducts();
        console.log("get all product => ",response.data);
        return response.data;
    }
)

const ecommerce_reducer = createSlice({
    name : "ecommerce",
    initialState : {
        products : []
    },
    reducers : {

    },
    extraReducers : (builder) => {
        builder.addCase(apiGetAllProducts.fulfilled,(state,action)=>{
            console.log("api get all product in reducer ",state , " action => ",action);
            state.products = action.payload;
        })
    }
});

export const allEcommerceProducts = state => state.ecommerce.products;

export const productSelector = (state,productId) => {
    console.log("product id => ",productId);
    console.log("state => ",state);
    return state.ecommerce.products.filter(product => product._id === productId)[0]
};

export default ecommerce_reducer.reducer;