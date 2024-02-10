import ReactStars from "react-rating-stars-component/dist/react-stars";
import {FontAwesomeIcon} from "@fortawesome/react-fontawesome";
import {faTrashCan , faPencilAlt} from "@fortawesome/free-solid-svg-icons";
import Swal from "sweetalert2";
import {apiDeletePlayerReview, apiEditPlayerReview} from "./backendCall/playerReviewSlice";
import {useDispatch} from "react-redux";
import {useState} from "react";
import {Button, Modal} from "react-bootstrap";

export default function PLayerReviewPage(props){
    let review = props.review;
    let dispatch = useDispatch();
    let [show,setShow]= useState(false);
    let [rating , setRating] = useState("");
    let [comment , setComment] = useState("");

    let handleShow = ()=>{
        setShow(true);
    }
    let handleClose = ()=>{
        setShow(false);
    }
   // console.log("review in player Review Page => ",review);

    let deleteReviewClick = ()=>{
        console.log("review delete review clicked => ",review._id);
        Swal.fire({
            title : 'Delete Review',
            text : 'Are you sure to delete your review ?',
            icon : 'warning',
            showCancelButton : true,
            confirmButtonText : 'Delete',
            cancelButtonText : 'Cancel'
        }).then(result=>{
            if(result.isConfirmed){
                Swal.fire({
                        title : 'Delete!',
                        html : 'Success Delete !',
                        icon : 'success'
                    }
                )
                dispatch(apiDeletePlayerReview(review._id));
            }
        })
    }

    const ratingChanged = ()=>{
        setRating(review.playerRating);
    }

    const editReviewClick =()=>{
        console.log("btn edit review ",review);
        setRating(review.playerRating);
        setComment(review.playerScore);
        handleShow()
    }

    const btnEditReview = ()=>{

        let saveReviewData = {
            _id : review._id,
            player : review.player._id,
            playerRating: rating,
            playerScore : comment
        }
        console.log("save review data => ",saveReviewData);
        dispatch(apiEditPlayerReview(saveReviewData));
        handleClose();
    }


    return (
        <div>
        <div className="mt-3" style={{justifyContent : "center" , display : "flex"}}>
            <ReactStars
                        count={10}
                        value={review.playerRating}
                        edit={false}
                        size={24}
                        activeColor="#ffd700"
                        />
        </div>
            <br/>
            <div>
                <ul className="comment list-group mb-4" >
                    <li className="list-group-item mb-20" >
                        <div className="text-muted">Review For The Player</div>
                        <div className="text-color fs-6 text-#fad255">{review.playerScore}<br/>
                        <FontAwesomeIcon className="awesomeIcon" icon={faPencilAlt} onClick={editReviewClick} />
                            &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
                            <FontAwesomeIcon className="awesomeIcon" icon={faTrashCan} onClick={deleteReviewClick}/>
                        </div>


                    </li>
                </ul>
            </div>

            <Modal show={show} onHide={handleClose} >
                <Modal.Header closeButton style={{backgroundColor : "ghostwhite"}}>
                    <Modal.Title style={{textAlign : "center"}}>Update Review</Modal.Title>
                </Modal.Header>
                <Modal.Body style={{backgroundColor : "rgba(28, 60, 79, 0.98)" , color : "#fff"}}>
                    Rating :
                    <ReactStars
                        count={10}
                        value={rating}
                        edit={true}
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
                    <Button type="submit" variant="primary" onClick={btnEditReview}>Save</Button>
                </Modal.Footer>
            </Modal>

        </div>
    )
}