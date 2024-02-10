import {useDispatch} from "react-redux";
import {logout} from "./backendCall/AuthSlice";
import Swal from "sweetalert2";

export default function LoginOutPage(){
    let dispatch = useDispatch();
    let logoutHandler = ()=>{
        console.log("logout ");
        Swal.fire({
            title : 'Logout Account',
            text : 'Are you sure to logout your account ?',
            icon : 'warning',
            showCancelButton : true,
            confirmButtonText : 'LogOut',
            cancelButtonText : 'Cancel'
            }).then(result=>{
            if(result.isConfirmed){
                Swal.fire({
                        title : 'LogOut!',
                        html : 'Success LogOut !',
                        icon : 'success'
                    }
                )
                dispatch(logout());
            }
        })

    }

    return (
        <div className={"container border border-1 border-red w-75 mx-auto p-5 background"}
             style={{marginTop : 150 , borderRadius : 10}}>
            <ul className="list-group ml-3" style={{textAlign : "center" , marginBottom : 20}}>
                <li className="player-title my-5 py-5">

                    <button className="btn btn-primary preText text-white mb-2"
                            onClick={logoutHandler}>
                        Logout
                    </button>
                    <div className="text-muted text-color">Are you sure to logOut ?</div>
                </li>
            </ul>

        </div>
    )
}