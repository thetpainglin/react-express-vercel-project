import "./ecomerce.css";
import HeroBanner from "./component/HeroBanner";
import FooterBanner from "./component/FooterBanner";
import Product from "./component/Product";

import {useDispatch, useSelector} from "react-redux";
import {useEffect} from "react";
import {allBanner, apiGetAllBanner} from "./backend_ecommerce/banner_reducer";

export default function Home(props){

    let products = props.product;
    let dispatch = useDispatch();
    let getAllBanner = useSelector(allBanner);

    useEffect(()=>{
        dispatch(apiGetAllBanner());
    },[]);
    console.log("all banner => ",getAllBanner);

    return (
        <>
           <HeroBanner bannerData={getAllBanner}/>
           <div className="products-heading">
               <h2>Best Selling Products</h2>
               <p>Speakers of many variations</p>
           </div>

            <div className="products-container">

                {
                    products.map(product => <Product key={product._id} product={product}/>)
                }

            </div>

            <FooterBanner footerBannerData={getAllBanner}/>
        </>
    )
}