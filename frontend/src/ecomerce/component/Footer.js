import {FontAwesomeIcon} from "@fortawesome/react-fontawesome";
import {faShoppingBag} from "@fortawesome/free-solid-svg-icons";
import {AiFillFacebook, AiFillInstagram, AiOutlineTwitter} from "react-icons/ai";


export default function Footer(){
    return (
        <div className="footer-container">
            <p>2022 JSM Headphones All rights reserverd</p>
            <p className="icons">
                < AiFillInstagram/>
                <AiOutlineTwitter/>
                <AiFillFacebook/>

            </p>
        </div>
    )
}