import React from "react";
import "bootstrap/dist/css/bootstrap.min.css";
import Logo from "../football_project/playerList/image/LogoFootball.png";
import {Link, Route, Routes} from "react-router-dom";
import "../App.css";
import {useAuthentication} from "../football_project/playerList/backendCall/authService";
import {FontAwesomeIcon} from "@fortawesome/react-fontawesome";
import {faBars} from "@fortawesome/free-solid-svg-icons"
import {useSelector} from "react-redux";
import {commentSelector} from "../football_project/playerList/backendCall/HistorySlice";

const Navbar = ()=>{
    /*<button className="navbar-toggler" type="button" data-toggle="collapse"
                        data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent"
                        aria-expanded="false" aria-label="Toggle navigation">
                    <span className="navbar-toggler-icon">Hi</span>
                </button>*/
    let comment = useSelector(commentSelector);
    console.log("comment length => ",comment);
    const notification = ()=>{

    }

    return (
            <nav className="navbar navbar-expand-lg navbar-light fixed-top bg-info">
                <div className="container">
                    <button className="navbar-toggler" type="button" data-bs-toggle="collapse"
                            data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent"
                            role="button"
                            data-toggle="collapse"
                            aria-expanded="false" aria-label="Toggle navigation">
                        <FontAwesomeIcon icon={faBars} style={{color : "#fff"}}/>
                    </button>
                <div className="collapse navbar-collapse" id="navbarSupportedContent">

                    <ul className="navbar-nav ml-auto preText">
                        <li className="nav-item active">
                            <img style={{width:80 , height : 50}} src={Logo} alt="No Photo"/>
                        </li>
                        <li className="nav-item active">
                            <Link className="nav-link pt-2" to="/">Home</Link>
                        </li>

                        <li className="nav-item active">
                            <Link className="nav-link pt-2" to="/kaedaung/players/">KaeDaungPlayer</Link>
                        </li>

                        <li className="nav-item">
                            <Link className="nav-link pt-2" to="/admin">Admin</Link>
                        </li>
                        <li className="nav-item" onClick={notification}>
                                <Link className="nav-link pt-2" to="/history">
                                    <div className="position-relative">
                                        Inbox
                                    <span className="inbox position-absolute top-0 start-100 translate-middle
                                                  bage rounded-pill bg-danger px-2"
                                                  >
                                            {comment.length}
                                        </span>

                                    </div>
                                </Link>
                        </li>
                        {
                          !useAuthentication() &&  <li className="nav-item">
                                <Link className="nav-link pt-2" to="/login?redirectTo=/">Login</Link>
                            </li>
                        }
                        {
                            useAuthentication() &&
                            <li className="nav-item">
                                <Link className="nav-link pt-2" to="/logout">LogOut</Link>
                            </li>
                        }

                    </ul>
                </div>
                </div>
            </nav>
    )
}

export default Navbar;