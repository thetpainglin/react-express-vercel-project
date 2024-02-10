
import Navbar from "./Navbar";
import Footer from "./Footer";
import Home from "../Home";
import {useState,useEffect} from "react";
import {useDispatch, useSelector} from "react-redux";
import {allEcommerceProducts, apiGetAllProducts} from "../backend_ecommerce/ecommerce_reducer";

export default function Layout(props){

    let showCartData = props.showCartData;
    let showCart = props.showCart;
    let closeCart = props.closeCart;

    let products = useSelector(allEcommerceProducts);
    let dispatch = useDispatch();
    useEffect(()=>{
        dispatch(apiGetAllProducts());
    },[]);



    console.log("product in layout layer ,", products);

    return (
        <div className="layout">

                <title>JS Mastery Store</title>
            <header>
                <Navbar showCart={showCart} closeCart={closeCart} showCartData={showCartData}/>
            </header>
            <main className="main-container">
                <Home showCart={showCart} product={products}/>
            </main>
            <footer>
                <Footer/>
            </footer>
        </div>
    )
}