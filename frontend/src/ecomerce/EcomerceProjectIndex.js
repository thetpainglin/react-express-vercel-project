import Layout from "./component/Layout";
import ProductDetails from "./page/ProductDetails";
import {Route, Routes} from "react-router-dom";
import Success from "./component/Success";
import React from "react";
import {useState} from "react";
import './ecomerce.css';
import Cart from "./component/Cart";

export default function EcomerceProjectIndex(){

    let [showCartData , setShowCart] = useState(false);
    let showCart = ()=>setShowCart(true);
    let closeCart = ()=> setShowCart(false);

    return (
        <div>



            <Routes>

                <Route path="/" element={<Layout showCartData={showCartData} showCart={showCart} closeCart={closeCart}/>}>

                </Route>
                <Route path="/products/:productId" element={<ProductDetails showCart={showCart}/>}/>
                <Route path="/products/cart" element={<Cart/>}/>
                <Route path="/products/success" element={<Success/>}/>

            </Routes>

        </div>
    )
}