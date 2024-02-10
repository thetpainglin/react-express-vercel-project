
import "./PlayerDetail.css"
import {useState} from "react";
import {useDispatch, useSelector} from "react-redux";
import {useEffect} from "react";
import {commentToAdd} from "./backendCall/HistorySlice";
import {Button, Modal} from "react-bootstrap";
import PLayerReviewPage from "./PLayerReviewPage";
import ReactStars from "react-rating-stars-component";
import {getPlayerReview} from "./backendCall/playerReviewAPI";
import {APIGetPlayerReview} from "./backendCall/playerReviewSlice";
import {useParams} from "react-router-dom";

const AllPlayerList = ({player,review})=>{
    console.log("All player calling in all player list => ",player);
    console.log("player review in all player list => ",review);
    console.log("image id => ",`img_${player._id}`);

    const [comment , setComment] = useState("");
    const [show , setShow] = useState(false);
    const [rating , setRating] = useState(0);
    const params = useParams();

    const handleShow = ()=>setShow(true);
    const handleClose = ()=>setShow(false);
    const commentSelector = useSelector(state => state.comment.comments)

    /*---code for comment to history page--*/
    const dispatch = useDispatch();

    //console.log("comment => ",commentSelector);

    //rating Change
    const ratingChanged = (newRating)=>{
        setRating(newRating);
    }
    //console.log('rating => ',rating);

    const SaveBtnInModal = ()=>{
        let commentData = {
            comment : comment,
            player : player.name,
        }
        dispatch(commentToAdd(commentData));
        let reviewForBackend = {
            player : params.playerId,
            playerRating : rating ,
            playerScore : comment,
        }

        dispatch(APIGetPlayerReview(reviewForBackend));
        handleClose();
    }


    return (
        <div className={"container my-5 border border-1 border-red w-75 mx-auto p-5 "}
             style={{backgroundColor : "ghostwhite" , justifyContent : "center"}}>
            <div className="row background " >
                <h2 className="player-title" style={{color : "#fff"}}>PLayer Details</h2>
                <ul className="list-group ml-3 fs-6 " style={{textAlign : "center" , marginBottom : 20}}>
                    <li className="list-group-item preText">
                        <img className="card-img-top" style={{width : 250,height : 150 , alignItems : "center"}} src={player.image} alt={"Card image cap"}/>
                    </li>
                    <li className="list-group-item my-2 text-color">Player Name &nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp; {player.name}</li>
                    <li className="list-group-item text-color">Age&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp; {player.age}</li>
                    <li className="list-group-item my-2 text-color">Height&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp; {player.height}</li>
                    <li className="list-group-item text-color">Goals&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp; {player.goals}</li>
                    <li className="list-group-item my-2 text-color">Assists&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp; {player.assistant}</li>
                    <li className="list-group-item mb-2 text-color">Position&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp; {player.position}</li>
                </ul>

            </div>
            <hr/>
            <div>
                <h2 className="player-title">Personal Info</h2>
                    <ul className="list-group ml-3" style={{textAlign : "center" , marginBottom : 20}}>
                        <li className="list-group-item my-2 preText">Father Name &nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp; {player.father}</li>
                        <li className="list-group-item preText">Mother Name&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp; {player.mother}</li>
                        <li className="list-group-item my-2 preText">Address&nbsp;&nbsp;&nbsp;&nbsp;:&nbsp;&nbsp;&nbsp;&nbsp; {player.address}</li>

                    </ul>
            </div>
            <div className={"container mb-5 mt-5 border border-1 border-red w-75 mx-auto p-5 bg-white"}>
                <h3 className="comment pb-3 bg-white text-color" style={{borderBottom : "2px solid gray" }}>Comment on the Player</h3>
                {/*Review Data*/}
                    {
                        review.map(review=><PLayerReviewPage key={review._id} review={review}/>)
                    }
                <button type="button" className="comment btn btn-primary float-end my-20" onClick={handleShow}>comment</button>
            </div>
            <Modal show={show} onHide={handleClose} >
                <Modal.Header closeButton style={{backgroundColor : "ghostwhite"}}>
                    <Modal.Title style={{textAlign : "center"}}>Comment</Modal.Title>
                </Modal.Header>
                <Modal.Body style={{backgroundColor : "rgba(28, 60, 79, 0.98)" , color : "#fff"}}>
                    Rating :
                    <ReactStars
                        count={10}
                        value={rating}
                        size={24}
                        activeColor="#ffd700"
                        onChange={ratingChanged}
                    />

                    <input type={"text"} value={comment}
                           placeholder="comment on player"
                           onChange={(event) => setComment(event.target.value)}/>
                </Modal.Body>
                <Modal.Footer>
                    <Button type="button" variant="secondary" onClick={handleClose}>Close</Button>
                    <Button type="submit" variant="primary" onClick={SaveBtnInModal}>Save</Button>
                </Modal.Footer>
            </Modal>

        </div>
    )
}

export default AllPlayerList;