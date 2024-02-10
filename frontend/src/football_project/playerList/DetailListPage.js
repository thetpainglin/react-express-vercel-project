import {useParams} from "react-router-dom";
import {useDispatch, useSelector} from "react-redux";
import {selectPlayer} from "./backendCall/PlayerSlice";
import AllPlayerList from "./AllPlayerList";

import img62919ac195ba9bc93a745917 from "./image/LogoFootball.png";
import {useEffect} from "react";
import {APIPlayerReviewById, selectReviewByPlayerId} from "./backendCall/playerReviewSlice";

const DetailListPage = ()=>{
    let params = useParams();

    let dispatch = useDispatch();
    const playerCall = useSelector(state=>selectPlayer(state,params.playerId));
    let data = `img${playerCall._id}`;
    console.log("data ",typeof data, " data ",data);

    const playerReview = useSelector(state=>selectReviewByPlayerId(state, params.playerId));

    useEffect(()=>{
        dispatch(APIPlayerReviewById(params.playerId));
    },[])
    console.log("params id => ",params.playerId);
    console.log("player review data => ",playerReview);
    return (
        <div className="container background" >
            <img src={img62919ac195ba9bc93a745917} style={{backgroundSize : 3 , width : 30 , height : 30 , borderRadius : 20}} href="#" alt="No Logo"/>

            <AllPlayerList player={playerCall} review={playerReview}/>
        </div>
    )
}

export default DetailListPage;