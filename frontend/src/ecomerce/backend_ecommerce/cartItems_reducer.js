import {createSlice} from "@reduxjs/toolkit";

const cartItems_reducer = createSlice({
    name : "cart",
    initialState : {
        cartItems : [],
    },
    reducers : {
        addCartItem : (state,action)=> {
            console.log("action payload in add cart item ",action.payload);
            state.cartItems = [...state.cartItems, action.payload]
        },
        updateCartItem : (state , action)=>{
            console.log("action in updateCartItem => ",action.payload);
          state.cartItems = state.cartItems.map(item =>
               item._id === action.payload._id ? action.payload : item
          );
        },
        removeCartItem : (state,action)=>{
            state.cartItems = state.cartItems.filter((cart)=>cart._id !== action.payload._id)
        },
    }
});
export const allCartItems = state => state.cart.cartItems;

export const {addCartItem,updateCartItem,removeCartItem} = cartItems_reducer.actions;

export const checkItem = (state , product )=> {
    console.log("state in checkItem =>  ",state.cart.cartItems);
    return state.cart.cartItems.filter(items => items._id === product._id )[0]
};


export default cartItems_reducer.reducer;