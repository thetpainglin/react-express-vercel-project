export default function ContactManagerDetailUI(props){
    let contact = props.contact;
    return (
        <div className="container ">
                <ul className="list-group mx-3"
                    style={{textAlign : "center" , marginBottom : 20}}>
                    <li className="list-group-item mt-2">Need Image in ContactManagerDetailUI</li>
                    <li className="list-group-item my-2 text-color fs-5">
                        manager name &nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp;
                        {contact.name}
                    </li>
                    <li className="list-group-item text-color fs-5">
                        email&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp;
                        {contact.email}
                    </li>
                    <li className="list-group-item my-2 text-color fs-5">
                        phone no&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp;
                        {contact.phoneNo}
                    </li>
                    <li className="list-group-item text-color fs-5">
                        address&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp;
                        {contact.address}
                    </li>
                </ul>
        </div>
    )
}