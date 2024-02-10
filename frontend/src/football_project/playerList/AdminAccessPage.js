import logo from "./image/PlayerLogo.jpg";
import Swal from "sweetalert2";
import {apiDeletePlayer, apiUpdatePlayer} from "./backendCall/PlayerSlice";
import {useDispatch} from "react-redux";
import {getUpdatePlayer} from "./backendCall/PlayerAPI";

export default function AdminAccessPage(props){
    const player = props.player;
    const editClick = props.editClick;
    let dispatch = useDispatch();
    let {handleShow} = props;

    let btnEditClickHandler = ()=>{

        editClick(player);
        console.log("edit click => ",player);
    }

    const btnDeleteClick = ()=>{
        Swal.fire({
            title : 'Delete Player',
            text : 'Are you sure to delete this player ?',
            icon : 'warning',
            showCancelButton : true,
            confirmButtonText : 'Delete',
            cancelButtonText : 'Cancel'
        }).then(result=>{
            if(result.isConfirmed){
                Swal.fire({
                        title : 'Delete!',
                        html : 'Success delete !',
                        icon : 'success'
                    }
                )
                dispatch(apiDeletePlayer(player._id));
            }
        })
    }



    return (
        <div className="card mb-3" style={{width : 250} } onClick={()=>{console.log("Clicked card!")}}>
            <img className="card-img-top" style={{width : 250,height : 150 , alignItems : "center"}} src={player.image} alt={"Card image cap"}/><hr/>
            <div className="card-body">
                <h5 className="preText card-title">{player.name}</h5>
                <div className="d-grid gap-1">
                    <button className="btn btn-primary preText text-white" type="button" onClick={btnDeleteClick}>Delete</button>
                    <button className="btn btn-primary preText text-white" type="button" onClick={btnEditClickHandler}>Edit</button>
                </div>
            </div>

        </div>
    )
}