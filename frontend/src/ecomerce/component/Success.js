import {BsBagCheckFill} from "react-icons/bs";
import {useNavigate} from "react-router-dom";

export default function Success(){
    let navigate = useNavigate();

    let backToHome = ()=>{
        navigate(`/`);
    }

    return (
        <div className="success-wrapper">
            <div className="success">
                <p className="icon">
                    <BsBagCheckFill/>
                </p>
                <h2>Thank you for your order !</h2>
                <p className="email-msg">Check your email inbox for the receipt.</p>
                <p className="description">
                    If you have any question , please email
                    <a className="email" href="mailto:order@example.com">
                        order@example.com
                    </a>
                </p>
                < button type="button" width="300px" className="btn" onClick={backToHome}>
                    Continue Shopping
                </button>
            </div>
        </div>
    )
}