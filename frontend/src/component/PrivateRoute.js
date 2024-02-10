import * as PropTypes from "prop-types";
import {Navigate} from "react-router-dom"
export default function PrivateRoute({
                                         children,
                                         redirectTo,
    isAuth,
    path,...props
                                     }){
    console.log("is auth ",isAuth , " redirectTo ",redirectTo);
    return isAuth  ? children : <Navigate to={redirectTo}/>
}