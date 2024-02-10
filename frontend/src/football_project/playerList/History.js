import {useDispatch, useSelector} from "react-redux";
import {useEffect} from "react";
import {AllPlayerSelect, selectPlayer} from "./backendCall/PlayerSlice";
import {useParams} from "react-router-dom";
import "./PlayerDetail.css";

const History = ()=>{

    let commentData = useSelector(state=>state.comment.comments);
    const AllPlayer = useSelector( AllPlayerSelect);
    const {playerId} = useParams();
    console.log("comment data ",commentData);
    console.log("Player Selector ",AllPlayer)
    /*
    * {
                playerId == AllPlayer._id && <div>{

                AllPlayer.map(player => <div>{player.name}</div>)
            }</div>
            }
    * */

    return (
        <div style={{marginTop : 68, paddingTop : 6 , backgroundColor : "rgba(28, 60, 79, 0.98)" , paddingBottom : 4}}>


            {
                commentData ?
                commentData.map(data=><div className={"container mb-3 mt-2  w-50 mx-auto p-3 "}
                                           style={{backgroundColor : "whitesmoke" ,fontSize : 10 , borderRadius : 10}}>
                    <span className="btn btn-secondary border border-1 border-dark w-20 my-3 py-4"
                            style={{borderRadius : 100 }}>
                        comment for<br/>
                        {
                            data.player
                        }
                    </span>
                    <div className="list-group">

                    <div className="list-group-item player-title"
                         style={{fontSize : 20 , marginLeft : 100}}>
                        <span className="text-muted">Comment :</span>
                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
                        {data.comment}
                    </div>
                    </div>
                </div>)
                    :
                    <div className={"container mb-3 mt-2  w-50 mx-auto p-3 "}
                         style={{backgroundColor : "whitesmoke" ,fontSize : 10 , borderRadius : 10}}>
                    No comment Player data
                    </div>
            }

        </div>
    )
}
export default History;