import DetailListPage from "./DetailListPage";
import {useNavigate, useParams} from "react-router-dom";
import {useDispatch, useSelector} from "react-redux";
import {selectPlayer} from "./backendCall/PlayerSlice";
import "bootstrap/dist/css/bootstrap.min.css";
import React from "react";
import {FontAwesomeIcon} from "@fortawesome/react-fontawesome";
import {faFutbol, faFutbolBall, faShoePrints, faSoccerBall} from "@fortawesome/free-solid-svg-icons";

const  PlayerDetail=(props) =>{
    const player = props.player;
     let navigate = useNavigate();
     const dispatch = useDispatch();

    const btnDetailClick = ()=>{
        navigate(`/kaedaung/players/${player._id}`)
    }


    return<div style={{backgroundColor : "rgba(28, 60, 79, 0.98)"}}>

            {
                /*<div className="row" style={{color: "darkslateblue"}}>
                    <div className="col">Player Name</div>
                    <div className="col">Age</div>
                    <div className="col">Goals</div>
                    <div className="col">Assistant</div>
                    <div className="col" style={{marginLeft: 20, marginRight: 20}}>Details</div>
                </div>
                */}
        <div className={"container pt-4 pb-1"}>
        <div className="row" style={{backgroundColor : "whitesmoke" , color : "saddlebrown"}}>

        <div className="col boxes box-1 text-color fs-6" style={{marginTop : 10}}>
                {player.name}
        </div>

            <span className="col my-3 p-0 ml-2" >
                <h7 className="bg-primary p-2 preText" style={{borderRadius : 100 , color : "#fff"}}>
                    {player.position}
                </h7>

            </span>


        <div className="col boxes box-2" style={{marginTop : 10}}>
            <h7 className="bg-primary p-2 mt-2 preText" style={{borderRadius : 100 , color : "#fff"}}>
                {player.age}
            </h7>
        </div>

        <div className="col boxes box-3" style={{marginTop : 10}}>
            <h7 className="bg-warning p-2 m-1 preText" style={{borderRadius : 100 , color : "#fff"}}>
                {player.goals}

            </h7>
            <FontAwesomeIcon icon={faSoccerBall}/>
        </div>
        <div className="col " style={{marginTop : 10}}>
            <h7 className="bg-info p-2 preText" style={{borderRadius : 100 , color : "#fff"}}>
                {player.assistant}
            </h7>
            <FontAwesomeIcon icon={faShoePrints} />
        </div>

        <button type={"button"} onClick={btnDetailClick} className={"col btn btn-primary preText text-white"} style={{marginTop : 10,marginLeft : 10,marginRight : 10}}>Details</button>
        </div>
        </div>
    </div>
}
export default PlayerDetail