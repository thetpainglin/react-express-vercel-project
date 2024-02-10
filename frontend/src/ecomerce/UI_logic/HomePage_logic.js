import {useDispatch, useSelector} from "react-redux";
import {useEffect} from "react";
import {allEcommerceProducts, apiGetAllProducts} from "../backend_ecommerce/ecommerce_reducer";
import Product from "../component/Product";

export default function HomePage_logic(){

    let dispatch = useDispatch();

    let products = useSelector(allEcommerceProducts);


    useEffect(()=>{
        dispatch(apiGetAllProducts());
    },[]);
    return (
        <>

            {
                products.map(product => <Product key={product._id} product={product}/>)
            }

        </>
    )
}