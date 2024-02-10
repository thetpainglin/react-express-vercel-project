import {FontAwesomeIcon} from "@fortawesome/react-fontawesome";
import {faPencilAlt, faTrashCan} from "@fortawesome/free-solid-svg-icons";
import {useSelector} from "react-redux";
import {contactSelect} from "./backendCall/contactManagerSlice";
import {useParams} from "react-router-dom";
import ContactManagerDetailUI from "./ContactManagerDetailUI";

function ContactManagerDetailLogic(props){
    let params = useParams();
    console.log("contant Id => ",params);
    let contact = useSelector(state => contactSelect(state,params.contactId));
    console.log(contact);
    return (
        <div className="page-size">
            <div className="container background">
                <div className="row col-md-15">
                    <h2 className="login-page text-white my-3">Contact Manager Details</h2>
            {
                contact.map(data => <ContactManagerDetailUI key={data._id} contact={data}/>)
            }
                </div>
            </div>
        </div>
    )
}

export default ContactManagerDetailLogic;