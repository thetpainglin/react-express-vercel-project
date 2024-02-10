import {Formik, Form , Field} from "formik";
import {apiLogin} from "./backendCall/AuthSlice";
import {AddNewPlayer} from "./backendCall/PlayerAPI";
import {useDispatch} from "react-redux";
import "./PlayerDetail.css";
import {apiAddNewPlayer, apiUpdatePlayer} from "./backendCall/PlayerSlice";

export default function PlayerForm(props){

    let {handleClose} = props;
    const updatePlayer = props.updatePlayer;

    let dispatch = useDispatch();
    let initValues = {
        _id : updatePlayer._id ? updatePlayer._id : null,
        name : updatePlayer.name ? updatePlayer.name : "",
        image : updatePlayer.image ? updatePlayer.image : "",
        father : updatePlayer.father ? updatePlayer.father : "",
        mother : updatePlayer.mother ? updatePlayer.mother : "",
        age : updatePlayer.age ? updatePlayer.age : "",
        assistant : updatePlayer.assistant ? updatePlayer.assistant : "",
        goals : updatePlayer.goals ? updatePlayer.goals : "",
        height : updatePlayer.height ? updatePlayer.height : "",
        position : updatePlayer.position ? updatePlayer.position : "",
        address : updatePlayer.address ? updatePlayer.address : "",

    }
    console.log("update player => ",updatePlayer);
    return (
        <div >
            <Formik initialValues={initValues} onSubmit={
                values => {
                    console.log("values ",values);
                    if(updatePlayer){
                        dispatch(apiUpdatePlayer(values))
                    }
                    else{
                        dispatch(apiAddNewPlayer(values));
                    }

                    handleClose();
                }
            }>
                {
                    ({values ,
                         errors,
                         touched,
                         handleChange,
                         handleBlur,
                         handleSubmit}) => (

                        <Form>
                            <div className="input-group pt-4 py-0">
                            <span className="input-group-text">Player name</span>
                            <input type="text" className="form-control"
                                   id="name"
                                   placeholder="Enter new player name"
                                   name="name"
                                   onChange={handleChange}
                                   onBlur={handleBlur}
                                   value={values.name}
                                    />

                            {
                                errors.username && touched.username ? (
                                    <div className="alert alert-danger">{errors.username}</div>
                                ) : null
                            }
                            </div>

                            <div className="input-group mt-5 mb-3 py-0">
                                <span className=" input-group-text">Image</span>
                                <span className=" input-group-text opacity-0.5 danger">This is my weak for not choosing file images!</span>
                                <input type="text" className="form-control"
                                       id="image"
                                       placeholder="Please write /football_images/player_1.png"
                                       name="image"
                                       onChange={handleChange}
                                       onBlur={handleBlur}
                                       value={values.image}/>
                            </div>

                            <div className="input-group mt-5 mb-3 py-0">
                                <span className=" input-group-text">Father name</span>
                            <input type="text" className="form-control"
                                   id="father"
                                   placeholder="Enter father name"
                                   name="father"
                                   onChange={handleChange}
                                   onBlur={handleBlur}
                                   value={values.father}/>
                            </div>

                            <div className="input-group mt-5 mb-3 py-0">
                                <span className="input-group-text">Mother name</span>
                            <input type="text" className="form-control"
                                   id="mother"
                                   placeholder="Enter mother name"
                                   name="mother"
                                   onChange={handleChange}
                                   onBlur={handleBlur}
                                   value={values.mother}/>
                            </div>

                            <div className="input-group mt-5 mb-3 py-0">
                                <span className="input-group-text">Age</span>
                            <input type="text" className="form-control"
                                   id="age"
                                   placeholder="Enter age"
                                   name="age"
                                   onChange={handleChange}
                                   onBlur={handleBlur}
                                   value={values.age}/>
                            </div>

                            <div className="input-group mt-5 mb-3 py-0">
                                <span className="input-group-text">Assistant</span>
                            <input type="text" className="form-control"
                                   id="assistant"
                                   placeholder="Enter Assistant"
                                   name="assistant"
                                   onChange={handleChange}
                                   onBlur={handleBlur}
                                   value={values.assistant}/>
                            </div>

                            <div className="input-group mt-5 mb-3 py-0">
                                <span className="input-group-text">Goals</span>
                            <input type="text" className="form-control"
                                   id="goals"
                                   placeholder="Enter Goals"
                                   name="goals"
                                   onChange={handleChange}
                                   onBlur={handleBlur}
                                   value={values.goals}/>
                            </div>

                            <div className="input-group mt-5 mb-3 py-0">
                                <span className="input-group-text">Height</span>
                                <input type="text" className="form-control"
                                       id="height"
                                       placeholder="Enter height"
                                       name="height"
                                       onChange={handleChange}
                                       onBlur={handleBlur}
                                       value={values.height}/>
                            </div>

                            <div className="input-group mt-5 mb-3 py-0">
                                <span className="input-group-text">Position</span>
                                <input type="text" className="form-control"
                                       id="position"
                                       placeholder="Enter position"
                                       name="position"
                                       onChange={handleChange}
                                       onBlur={handleBlur}
                                       value={values.position}/>
                            </div>

                            <div className="input-group mt-5">
                                <span className="input-group-text">Address</span>
                            <input type="text" className="form-control"
                                   id="address"
                                   placeholder="Enter Address"
                                   name="address"
                                   onChange={handleChange}
                                   onBlur={handleBlur}
                                   value={values.address}/>
                            </div>

                            <hr/>

                            <button type="submit" className="btn btn-primary mt-2 mb-3 float-end" >
                                {updatePlayer ? "Update Player" : "Save"}
                            </button>

                            <button type="button"
                                    className="btn btn-danger mt-2 mb-3 mx-3 float-end"
                                    onClick={handleClose}>
                                Cancel
                            </button>

                        </Form>
                    )
                }
            </Formik>
        </div>
    )
}