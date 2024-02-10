import {FontAwesomeIcon} from "@fortawesome/react-fontawesome";
import {faShoppingBag} from "@fortawesome/free-solid-svg-icons";
import Cart from "./Cart";
import {useSelector} from "react-redux";
import {allCartItems} from "../backend_ecommerce/cartItems_reducer";


export default function Navbar(props){

    let cartItemLength = useSelector( allCartItems);
    console.log("cart item => ",cartItemLength);

    let showCart = props.showCart;
    let closeCart = props.closeCart;
    let origin = props.showCartData;
    return (
        <div className="navbar-container">
            <p className="logo" style={{color: "#324d67" , fontSize: "20px",
                fontWeight: "800"}}>
                Need a job !
            </p>
            <button type="button" className="cart-icon"
                    onClick={showCart}>
                <FontAwesomeIcon icon={faShoppingBag}/>
            </button>
            <span className="cart-item-qty">{cartItemLength ? cartItemLength.length : 0}</span>

            {origin &&  <Cart closeCart={closeCart}/>}
        </div>
    )
}