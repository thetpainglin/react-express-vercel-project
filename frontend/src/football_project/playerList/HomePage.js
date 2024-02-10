import "./PlayerDetail.css";
import ContactManager from "./ContactManager";
import {useNavigate} from "react-router-dom";

const HomePage = ()=>{
    const navigate = useNavigate();
    const btnContactClick = ()=>{
        console.log("navigate => ",navigate("/contact"));
    }

    return (
        <div style={{marginTop : 30 , backgroundColor : "rgba(28, 60, 79, 0.98)"}}>
            <div className={"container mb-5 mt-5 border border-1 border-red w-75 mx-auto p-5 "}>
                <ul className="list-group ml-3" style={{textAlign : "center" , marginBottom : 20}}>

                    <li className="list-group-item player-title my-2 pb-5 "
                        style={{color : "#fff" , borderBottom : "1px solid #fff"
                            ,backgroundColor : "rgba(28, 60, 79, 0.98)"}}>Kae Daung Football Club</li>

                    <p className="m-5 bg-white p-5 text-color fs-6" >
                        <h3 className="player-title bg-white py-3 mb-5"
                            style={{borderBottom : "1px solid gray"}}>
                            History Of The Team
                        </h3>
                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;In march 21/ 2022 , we created <strong>"Kae Daung FootBall Club"</strong> in our village , Kani TownShip.
                        This is KaeDaung Youth team sponsored by <mark><i><strong>GaBar Tun Company</strong></i></mark>.
                        <br/><br/>
                        As friendly matches ,
                        our team played 3 matches.
                        <br/>
                        In first match ,
                        we played with Pagin team. We lost 3-2.But , we played again in our village .
                        <br/>we won 4-2.<br/><br/>
                        At last match , we played again Kin team. We won 9-5.

                        We can say this is not bad for this result .

                        Unfortunately , after we played three matches, we paused to play awhile.<br/>
                        But , we will continue one day ....
                        </p>

                    <li className="list-group-item player-title my-2 pb-5"
                        style={{color : "#fff" ,
                            borderBottom : "1px solid #fff",
                            backgroundColor : "rgba(28, 60, 79, 0.98)"}}>
                       <button className="btn btn-primary preText text-white" onClick={btnContactClick}>content us</button>
                    </li>

                </ul>

            </div>
        </div>
    )
};

export default HomePage;