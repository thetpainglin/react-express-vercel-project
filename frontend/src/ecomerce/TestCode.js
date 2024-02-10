import {useDispatch, useSelector} from "react-redux";
import {useEffect} from "react";
import {allEcommerceProducts, apiGetAllProducts} from "./backend_ecommerce/ecommerce_reducer";
import {allBanner, apiGetAllBanner} from "./backend_ecommerce/banner_reducer";

export default function TestCode(){
    let dispatch = useDispatch();
    let selector = useSelector(allEcommerceProducts);
    let bannerSelector = useSelector(allBanner);

    useEffect(()=>{
        dispatch(apiGetAllProducts());
        dispatch(apiGetAllBanner());
    },[]);

    console.log("all product => ",selector);
    console.log("all banner ",bannerSelector);
    return (
        <>
        Test Code
        </>
    )
}