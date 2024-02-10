import {AiOutlineLeft, AiOutlineMinus, AiOutlinePlus, AiOutlineShoppingCart} from "react-icons/ai";
import {useEffect, useState} from "react";
import {TiDeleteOutline} from "react-icons/ti";
import {useDispatch, useSelector} from "react-redux";
import {allCartItems, removeCartItem, updateCartItem} from "../backend_ecommerce/cartItems_reducer";
import {useNavigate} from "react-router-dom";
import '../ecomerce.css';
import '../../App.css';
export default function Cart(props){

    let closeCart = props.closeCart;
    let cartItems = useSelector(allCartItems);
    let dispatch = useDispatch();
    let navigate = useNavigate();

        let totalPrice;
        if(cartItems.length){
            let totalCart = cartItems.map(item => item ? item.price * item.quantity : 0);
             totalPrice = totalCart.reduce((a,b) => a + b);

        }else  totalPrice = 0;


    let decrementHandler = (item)=>{

        let newCartProduct = {
            _id : item._id,
            name : item.name,
            image : item.image,
            images : item.images,
            price : item.price,
            quantity : item.quantity <= 1 ? 1 : item.quantity - 1,
            details : item.details,
        }
        console.log("new cart product => ",newCartProduct);
        dispatch(updateCartItem(newCartProduct))

    }
    let incrementHandler = (item)=>{
        let newCartProduct = {
            _id : item._id,
            name : item.name,
            image : item.image,
            images : item.images,
            price : item.price,
            quantity : item.quantity + 1,
            details : item.details,
        }
        console.log("new cart product => ",newCartProduct);
        dispatch(updateCartItem(newCartProduct))

    }

    let deleteHandler = (item)=>{
        console.log("delete item!");
        dispatch(removeCartItem(item));
    }

    let toDetailProduct = (item)=>{
        console.log("details product !");
        navigate(`/products/${item._id}`);
    }

    let handleSucces = ()=>{
        navigate(`products/success`);
        //cartItems = [];
        //closeCart = false;
    }

    let emptyHandler = ()=>{
        console.log("empty handler called ")
        navigate(`/`);
    }

    return (
        <div className="cart-wrapper">
                <div className="cart-container">
                    <button type="button" className="cart-heading" onClick={closeCart}>
                        <AiOutlineLeft/>
                        <span className="heading">Your Cart</span>
                        <span className="cart-num-items">({cartItems.length} items)</span>
                    </button>

                    {cartItems.length < 1 &&(
                        <div className="empty-cart">
                            <AiOutlineShoppingCart size={150}/>
                            <h3>Your shopping bag is empty</h3>
                            <button type="button" className="btn" onClick={emptyHandler}>
                                Continue Shopping
                            </button>
                        </div>)}


                    <div className="product-container">
                        {cartItems.length >=1 &&
                            cartItems?.map((item,index) =>(

                        <div className="product" key={index} >
                            <img className="cart-product-image" src={item.image} width={50} height={50} alt="no photo" onClick={()=>toDetailProduct(item)}/>
                            <div className="item-desc">
                                <div className="flex top">
                                    <h6>{item.name}</h6>
                                    <h5>${item.price}</h5>
                                </div>
                                <div className="flex bottom">
                                    <div>
                                        <p className="quantity-desc">
                                        <span className="minus" >
                                            <AiOutlineMinus  onClick={()=>decrementHandler(item)}/>
                                        </span>
                                            <span className="num" >
                                            {item.quantity}
                                        </span>
                                            <span className="plus"  >
                                            <AiOutlinePlus onClick={()=>incrementHandler(item)}/>
                                        </span>
                                        </p>
                                    </div>
                                    <button type="button" className="remove-item" onClick={()=>deleteHandler(item)}>
                                        <TiDeleteOutline/>
                                    </button>
                                </div>
                            </div>
                        </div>
                            ))
                        }

                    </div>

                    {cartItems.length >= 1 &&
                    <div className="cart-bottom" style={{marginTop : '25px'}}>
                        <div className="total">
                            <h3 style={{color: "#324d67" , fontSize: "20px",
                                fontWeight: "700"}}>Subtotal :</h3>
                            <h3 style={{color: "#324d67" , fontSize: "20px",
                                fontWeight: "700"}}>$ {totalPrice}</h3>
                        </div>
                        <div className="btn-container" style={{marginTop : '5px',marginBottom : '5px'}}>
                            <button type="button" className="btn button" onClick={handleSucces}>
                                Continue with payment
                            </button>
                        </div>
                    </div>
                        }

                </div>

        </div>
    )
}