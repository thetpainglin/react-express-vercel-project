import AdminAccessPage from "./AdminAccessPage";
import {useDispatch, useSelector} from "react-redux";
import {AllPlayerSelect, apiUpdatePlayer} from "./backendCall/PlayerSlice";
import logo from "./image/AddPlayerLogo.jpg";
import {useState,useEffect} from "react";
import {Modal,Button} from "react-bootstrap";
import PlayerForm from "./PlayerForm";

export default function AdminPage(){
    const AllPlayer = useSelector(AllPlayerSelect);
    const dispatch = useDispatch();
    let [show , setShow] = useState(false);
    const handleShow = ()=>setShow(true);
    const handleClose = ()=>setShow(false);
    const [updatePlayer , setUpdatePlayer] = useState("");

    const btnNewPlayer = ()=>{
        console.log("new player adding ");
        setUpdatePlayer("");
        handleShow();

    }



    const btnUpdataClick = (player)=>{
        console.log("btn update clicked ! => ",player);
        setUpdatePlayer(player);
        handleShow();
        let updateData = {

        }
        //dispatch(apiUpdatePlayer(player));

    }


    return (
        <div className="background" style={{marginTop : 30 }}>
            <Modal show={show} onHide={handleClose} >
                <Modal.Header closeButton className="bg-dark">
                    <Modal.Title className="player-title" style={{textAlign : "center" , color : "#fff"}}>{updatePlayer ? "Update Player" : "Add New Player"}</Modal.Title>
                </Modal.Header>
                <Modal.Body className="border w-100 mx-auto p-2 " style={{backgroundColor : "rgba(239,243,138,0.68)" , borderRadius : 5}}>
                <PlayerForm handleClose={handleClose} updatePlayer={updatePlayer}/>
                </Modal.Body>
                <Modal.Footer className="bg-dark">
                    <h5 className="text-muted float-center">Insert player as you like to your team </h5>
                </Modal.Footer>
            </Modal>

        <div className="container">



            <div className="row ">
                <div className="col mt-5">

                        <div className="card mb-3"  style={{width : 250 , cursor : "pointer"} } onClick={btnNewPlayer}>

                            <img className="card-img-top" style={{width : 250,height : 200 , alignItems : "center"}} src={logo} alt={"Card image cap"}/>

                            <div className="card-body">
                                <h5 className="card-title text-color fs-5">Add New Player</h5>

                            </div>
                        </div>


                </div>

                {
                    AllPlayer.map((player , index) => {
                    return (
                        <div className="col mt-5">
                            <AdminAccessPage key={index}
                                             player={player}
                                             handleShow={handleShow}
                                             editClick={btnUpdataClick}/>
                        </div>
                    )
                } )}

            </div>

        </div>
        </div>
    )
}