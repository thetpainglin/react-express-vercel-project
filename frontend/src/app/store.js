import { configureStore } from '@reduxjs/toolkit';

import kaeDaungPlayReducer from "../football_project/playerList/backendCall/PlayerSlice";
import historyReducer from "../football_project/playerList/backendCall/HistorySlice";
import authReducer from "../football_project/playerList/backendCall/AuthSlice";
import userReducer from "../football_project/playerList/backendCall/userSlice";
import playerReviewReducer from "../football_project/playerList/backendCall/playerReviewSlice";
import contactManagerReducer from "../football_project/playerList/backendCall/contactManagerSlice";

/*ecommerce project */

import ecommerceReducer from "../ecomerce/backend_ecommerce/ecommerce_reducer";
import cartItems_reducer from "../ecomerce/backend_ecommerce/cartItems_reducer";
import banner_reducer from "../ecomerce/backend_ecommerce/banner_reducer";

export const store = configureStore({
  reducer: {

    kaeDaungPlayer : kaeDaungPlayReducer,
    playerReview : playerReviewReducer,
    comment : historyReducer,
    auth : authReducer,
    user : userReducer,
    contact : contactManagerReducer,

    ecommerce : ecommerceReducer,
    cart : cartItems_reducer,
    bannerProduct : banner_reducer,
  }

});
