import * as Yup from "yup";
import {useLocation, useNavigate} from "react-router-dom";
import {useDispatch} from "react-redux";
import {Formik,Form,Field} from "formik";
import {apiLogin} from "./backendCall/AuthSlice";
import {useEffect, useState} from "react";
import  {useAuthentication} from "./backendCall/authService";
import  {checkUser} from "./backendCall/userSlice";
import {apiGetAllPlayer} from "./backendCall/PlayerSlice";
import {FontAwesomeIcon} from "@fortawesome/react-fontawesome";
import {faClipboardCheck, faClipboardUser, faContactBook, faMale, faPesoSign} from "@fortawesome/free-solid-svg-icons";

const LoginSchema = Yup.object().shape({
    username : Yup.string()
        .required('required !'),
    password : Yup.string()
        .required('Required !'),
});

export default function LoginPage(){
    let navigate = useNavigate();
    let auth = useAuthentication();
    const dispatch = useDispatch();
    const [user , setUser] = useState();

    let {search} = useLocation();
    let redirectTo = "/";
    if(search && search.indexOf("=") !=-1){
        redirectTo = search.substring(search.indexOf("=")+1);
    }

    console.log("login page redirect to => ",redirectTo);
    console.log("user => ",user);

    useEffect(()=>{
        console.log("Run effect");
        if(auth){
            console.log("auth => ",auth);
            console.log("Check");
            dispatch(checkUser(user));
            navigate(redirectTo);
            console.log("After navigation")

        }
    });

    let initValues = {
        username : "",
        password : "",
    }
    /*
    * in formik form
    * type="text" style={{textAlign : "center" , marginTop : 20 , marginBottom : 20 , border : "burlywood"}}
    * */

    return (
        <div className="login-page text-center float-center" >
        <Formik initialValues={initValues} onSubmit={
            (values) => {
                setUser(values);
                console.log("login data => ",values);

                    dispatch(apiLogin(values))


            }
        }>
            {
                ({values ,
                errors,
                touched,
                handleChange,
                handleBlur,
                handleSubmit}) => (

                    <Form className="text-center">
                        <label style={{marginTop : 180}}>Username</label>

                        <div className="input-group pt-4 py-0 justify-content-center mb-4">
                            <span className="input-group-text">
                                <FontAwesomeIcon icon={faClipboardUser}/>
                            </span>
                        <input className="font-control border border-1 border-white"
                                style={{borderRadius  : 5 , borderInlineColor : "black"}}
                               placeholder="username"
                               id="username"
                                name="username"
                                onChange={handleChange}
                                onBlur={handleBlur}
                                value={values.username}/>
                        </div>

                        <label>Password </label>


                        <div className="input-group pt-4 py-0 justify-content-center mb-4">
                            <span className="input-group-text">
                                <FontAwesomeIcon icon={faClipboardCheck}/>
                            </span>
                        <input className="font-control border border-1 border-white"
                               style={{borderRadius  : 5 , borderInlineColor : "black"}}
                               id="password"
                               placeholder="Password"
                               name="password"
                               onChange={handleChange}
                               onBlur={handleBlur}
                               value={values.password}/>
                        </div>

                        {
                            errors.password && touched.password ? (
                                <div className="alert alert-danger">{errors.password}</div>
                            ) : null
                        }

                        <button type="submit" className="btn btn-primary" style={{marginTop : 15 , marginBottom : 175}}>Login</button>

                    </Form>
                )
            }
        </Formik>
        </div>
    )
}