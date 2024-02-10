import "./MoviePreview.css";
import {useEffect} from "react";
import {useDispatch, useSelector} from "react-redux";
import {apiGetAllPlayer, selectPlayer} from "./backendCall/PlayerSlice";
import PlayerDetails from "./PlayerDetails";
import {useParams} from "react-router-dom";
import {userSelector} from "./backendCall/userSlice";
import AdminPage from "./AdminPage";
import AdminAccessPage from "./AdminAccessPage";
//connect with link to router



const PlayerList = ()=>{
    const dispatch = useDispatch();
    const params = useParams();
    useEffect(()=>{
        dispatch(apiGetAllPlayer());
    },[])

        /*
        const playerList = [
            {
                id: 1,
                name: "Ronaldo",
                age: 33,
                address: "Portugal"
            },
            {
                id: 2,
                name: "Messi",
                age: 32,
                address: "Argentina"
            },
            {
                id: 3,
                name: "Neymar",
                age: 29,
                address: "Brazil"
            }, {
                id: 4,
                name: "Mbappe",
                age: 21,
                address: "Kae Daung"
            }
        ]
        */
    const playerList = useSelector((state)=>state.kaeDaungPlayer);
    const getUser = useSelector(userSelector);
    console.log("get user in userSlice => ",getUser);

    console.log("player list => ",playerList.players);
    //playerList.players.sort((a,b)=>a.age-b.age);
    return (
        <div style={{marginTop : 20}}>
            <div className="container" >

                <div className="row background player-data pt-4" style={{color: "#fff",fontSize : 20 }}>
                    <div className="col">Player Name</div>
                    <div className="col">Position</div>
                    <div className="col">Age</div>
                    <div className="col">Goals</div>
                    <div className="col">Assistant</div>
                    <div className="col" style={{marginLeft : 20 , marginRight : 20}}>Details</div>
                </div>

            </div>
            {
                playerList.players.map(player => {
                return (
                            <PlayerDetails key={player._id} player={player}/>
            )}
            )}
        </div>
    )
}
export default PlayerList;