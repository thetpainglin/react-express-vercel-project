import ContactManagerPage from "./ContactManagerPage";
import {useDispatch, useSelector} from "react-redux";
import {apiGetAllContant, allContact, apiAddNewContact, apiEditContactManager} from "./backendCall/contactManagerSlice";
import {useEffect, useState} from "react";
import {Button, Modal} from "react-bootstrap";
import ReactStars from "react-rating-stars-component";
import {FontAwesomeIcon} from "@fortawesome/react-fontawesome";
import {faAddressBook, faMailBulk, faPhone, faUser} from "@fortawesome/free-solid-svg-icons";

export default function ContactManager(){
    let dispatch = useDispatch();
    let [show , setShow] = useState(false);

    const [name , setName] = useState("");
    const [email,setEmail] = useState("");
    const [phone , setPhone] = useState("");
    const [address , setAddress] = useState("");

    const [contacts,setContacts] = useState({});

    const handleClose = ()=>setShow(false);
    const handleShow = ()=>setShow(true);

    let contactSelector = useSelector(allContact);
    console.log("contact selector => ",contactSelector);
    useEffect(()=>{
        dispatch(apiGetAllContant());
    },[]);

    let saveManager = ()=>{
        setName("");
        setEmail("");
        setPhone("");
        setAddress("");
        handleShow();
    }

    const btnAddContact = ()=>{
        let contacts = {
            name : name,
            email : email,
            phoneNo : phone,
            address : address
        }
        dispatch(apiAddNewContact(contacts));
        handleClose();
    }

    {/*
        let contactManagerEditClick = (contact) => {
            handleShow();
            setContacts(contact);
            console.log("contact edit click => ", contact);
            dispatch(apiEditContactManager(contact));
        }
    */}

    return (
        <div className="background page-size">
            <div className="w-75 mx-auto p-2">
                <h2 className="player-title" style={{color : "#f9ab00"}}>Contact Manager</h2>
                <button className="btn  btn-warning c-white d-block preText text-white" onClick={saveManager}>Add new Manager</button>
            {
                contactSelector.map(contact => <ContactManagerPage key={contact._id}
                                                                   contact={contact}
                                                                                    />)
            }
            </div>

            <Modal show={show} onHide={handleClose} >
                <Modal.Header closeButton style={{backgroundColor : "ghostwhite"}}>
                    <Modal.Title style={{textAlign : "center"}}>
                        Add new Manager</Modal.Title>
                </Modal.Header>
                <Modal.Body style={{backgroundColor : "rgba(28, 60, 79, 0.98)" , color : "#fff"}}>

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
                    <Button type="button" variant="secondary" onClick={handleClose}>Close</Button>
                    <Button type="submit" variant="primary" onClick={btnAddContact}>Save</Button>
                </Modal.Footer>
            </Modal>
        </div>
    )
}