
import {useNavigate} from "react-router-dom";
import ProductDetails from "../page/ProductDetails";


export default function Product(props){

    let product = props.product;
    let navigate = useNavigate();



    let detailHandler = (product)=>{
        console.log("detail handler !");
        navigate(`/products/${product._id}`)
    }

    return (
        <div>
            <div className="product-card" onClick={()=> detailHandler(product)}>
                <img src={product.image} alt="no photo" width={150} height={150} className="product-image"/>
                <p className="product-name">{product.name}</p>
                <p className="product-price">${product.price}</p>
            </div>
        </div>
    )
}