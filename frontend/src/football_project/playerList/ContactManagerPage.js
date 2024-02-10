import player from "./image/PlayerLogo.jpg";
import {FontAwesomeIcon} from "@fortawesome/react-fontawesome";
import {faTrashCan, faPencilAlt, faUser, faMailBulk, faPhone, faAddressBook} from "@fortawesome/free-solid-svg-icons";
import {useDispatch} from "react-redux";
import { apiDeleteContactManager, apiEditContactManager} from "./backendCall/contactManagerSlice";
import Swal from "sweetalert2";
import {Button, Modal} from "react-bootstrap";
import {useState} from "react";
import {useNavigate} from "react-router-dom";
export default function ContactManagerPage(props){

    let contact = props.contact;
    let dispatch = useDispatch();

    let [show , setShow] = useState(false);
    let handleShow = ()=> setShow(true);
    let handleClose = ()=>setShow(false);

    const [name , setName] = useState("");
    const [email,setEmail] = useState("");
    const [phone , setPhone] = useState("");
    const [address , setAddress] = useState("");
    const navigate = useNavigate();

    let btnEditShow = ()=>{
        setName(contact.name);
        setEmail(contact.email);
        setPhone(contact.phoneNo);
        setAddress(contact.address);
        handleShow();
    }

    let deleteContact = ()=>{
        console.log("delete clicked => ",contact);
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
                dispatch(apiDeleteContactManager(contact._id));
            }
        })
    }

    const btnEditClick = ()=>{
        let contacts = {
            _id : contact._id,
            name : name,
            email : email,
            phoneNo : phone,
            address : address
        }
        dispatch(apiEditContactManager(contacts));
        handleClose();
    }

    const detailManager = ()=>{
        console.log("detail manager => ");
        navigate(`${contact._id}`);
    }

    return (
        <div className="card mb-3" style={{maxWidth:"750px"}} >
            <div className="row g-0">
                <div className="col-md-4">
                    <img src={player} style={{width : "180px" , height : "160px" }}
                         alt={"No Photo"} />
                </div>
                <div className="col-md-8">
                    <div className="card-body" style={{ cursor : "pointer" , borderBottom : "1px solid grayLight"}} onClick={detailManager}>
                        <h5 className="card-title preText">manager :
                            <strong className="page-title text-color">{contact.name}</strong>
                        </h5>
                        <p className="card-text preText">email : {contact.email}</p>
                    </div><hr/>
                    <FontAwesomeIcon className="awesomeIcon text-#ffee44" icon={faTrashCan} onClick={deleteContact}/>
                    &nbsp;&nbsp;&nbsp;&nbsp;
                    <FontAwesomeIcon className="awesomeIcon text-gray" icon={faPencilAlt} onClick={btnEditShow}/>
                    &nbsp;&nbsp;&nbsp;&nbsp;

                </div>
            </div>

            <Modal show={show} onHide={handleClose} >
                <Modal.Header closeButton style={{backgroundColor : "ghostwhite"}}>
                    <Modal.Title className="text-color" style={{textAlign : "center"}}>
                        Update Contact </Modal.Title>
                </Modal.Header>
                <Modal.Body  style={{backgroundColor : "rgba(28, 60, 79, 0.98)" , color : "#fff"}}>
                    <div className="input-group pt-4 pb-3">
                            <span className="input-group-text">
                                <FontAwesomeIcon icon={faUser}/>
                            </span>
                        <input type={"text"} value={name}
                               placeholder="name"
                               onChange={(event) => setName(event.target.value)}/>
                    </div>

                    <div className="input-group pt-4 pb-3">
                            <span className="input-group-text">
                                <FontAwesomeIcon icon={faMailBulk}/>
                            </span>
                        <input type={"text"} value={email}
                               placeholder="don't forget @"
                               onChange={(event) => setEmail(event.target.value)}/>
                    </div>
                    <div className="input-group pt-4 pb-3">
                            <span className="input-group-text">
                                <FontAwesomeIcon icon={faPhone}/>
                            </span>
                        <input type={"text"} value={phone}
                               placeholder="phone number"
                               onChange={(event) => setPhone(event.target.value)}/>
                    </div>

                    <div className="input-group pt-4 pb-3">
                            <span className="input-group-text">
                                <FontAwesomeIcon icon={faAddressBook}/>
                            </span>
                        <input type={"text"} value={address}
                               placeholder="enter address"
                               onChange={(event) => setAddress(event.target.value)}/>
                    </div>
                </Modal.Body>
                <Modal.Footer>
                    <Button className="text-color fs-6 text-white" type="button" variant="secondary" onClick={handleClose}>Close</Button>
                    <Button className="text-color fs-6 text-white" type="submit" variant="primary" onClick={btnEditClick}>Update</Button>
                </Modal.Footer>
            </Modal>

        </div>
    )
}