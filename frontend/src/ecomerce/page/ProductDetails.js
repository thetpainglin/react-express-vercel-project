
import {AiFillStar, AiOutlineMinus, AiOutlinePlus, AiOutlineStar} from "react-icons/ai";
import {useDispatch, useSelector} from "react-redux";
import {useContext, useEffect, useState} from "react";
import {useNavigate, useParams} from "react-router-dom";
import {allEcommerceProducts, apiGetAllProducts, productSelector} from "../backend_ecommerce/ecommerce_reducer";
import {
    addCartItem, allCartItems,
    checkItem, updateCartItem,
} from "../backend_ecommerce/cartItems_reducer";

import context from '../component/Layout';
import Cart from "../component/Cart";

export default function ProductDetails(props){
    let showCart = props.showCart;

    let dispatch = useDispatch();
    let params = useParams();
    let product = useSelector((state) => productSelector(state,params.productId));
    let [index , setIndex ] = useState(0);

    let allProduct = useSelector(allEcommerceProducts);
    let allCartItem = useSelector(allCartItems);

    let [qty , setQty ] = useState(1);
    let navigate = useNavigate();
    console.log("quantity in state => ",qty);

    let check = useSelector((state) => checkItem(state,product));
    console.log("all cart item  => ",allCartItem);

    console.log("product with Id => ",product);
    console.log("params => ",params);
    console.log("all product => ",allProduct);

    useEffect(()=>{
        dispatch(apiGetAllProducts());
    },[]);

    let addCartHandler = (data)=>{
        console.log("product data => ",data);
            let newProduct = {
                _id : data._id,
                name : data.name,
                image : data.image,
                images : data.images,
                price : data.price,
                quantity : qty,
                details : data.details,
            }

        {
            check ? dispatch(updateCartItem(newProduct)): dispatch(addCartItem(newProduct));
        }


    }

    let buyNowHandler = (data)=>{
        console.log("buy now item => ",data);
        let newProduct = {
            _id : data._id,
            name : data.name,
            image : data.image,
            images : data.images,
            price : data.price,
            quantity : qty,
            details : data.details,
        }

        {
            check ? dispatch(updateCartItem(newProduct)): dispatch(addCartItem(newProduct));
        }
       showCart();
        navigate(`/`);
    }

    let productImageHandler = (productData)=>{
        console.log("product data => ",productData);
        navigate(`/products/${productData._id}`);
    }

    return (
        <div>
            <div className="product-detail-container">
                <div>
                    <div className="image-container">
                        {
                            <img src={product.images[index]} width={100} height={100} className="product-detail-image"/>

                        }
                    </div>

                    <div className="small-images-container">

                        {
                            /*selected-image in className for selected image*/
                             product.images.map(
                                (data,index)=><img src={data}
                                                   width={50}
                                                   height={50}
                                                   alt="no photo"
                                                   className="small-image"
                                                    onMouseEnter={()=>setIndex(index)}/>)
                        }

                    </div>

                </div>

                <div className="product-detail-desc">

                        <h2  style={{color: "#324d67" , fontSize: "40px",
                            fontWeight: "800"}}>{product.name}</h2>

                    <div className="reviews">
                        <div>
                            <AiFillStar/>
                            <AiFillStar/>
                            <AiFillStar/>
                            <AiOutlineStar/>
                            <AiOutlineStar/>
                        </div>
                        <p>(20)</p>
                    </div>
                    <h4>Details : </h4>
                    <p>{product.details}</p>
                    <p className="price">${product.price}</p>
                    <div className="quantity">
                        <h3>Quantity:</h3>
                        <p className="quantity-desc">
                            <span className="minus"
                                  onClick={()=>setQty((data)=>data <= 1 ? 1 : data -1)}><AiOutlineMinus/></span>
                            <span className="num" >{qty}</span>
                            <span className="plus" onClick={()=>setQty((data)=>data + 1)}><AiOutlinePlus/></span>
                        </p>
                    </div>
                    <div className="buttons">
                        <button type="button" className="add-to-cart" onClick={()=>addCartHandler(product)}>Add to Cart</button>
                        <button type="button" className="buy-now" onClick={()=>buyNowHandler(product)}>
                            Buy Now
                        </button>
                    </div>
                </div>
            </div>

            <div className="maylike-products-wrapper">
                <h2>You may also like</h2>
                <div className="marquee">
                    <div className="maylike-products-container track">

                        {
                            /*Loop in Product Details*/
                            allProduct.map(pro => <img src={pro.image}
                                                       width={150}
                                                       height={150}
                                                       className="product-image"
                                                       onClick={()=>productImageHandler(pro)}/>)
                        }

                    </div>
                </div>
            </div>
        </div>
    )
}