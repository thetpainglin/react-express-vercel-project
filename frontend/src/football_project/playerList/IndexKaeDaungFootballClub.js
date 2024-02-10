import { Outlet, Route, Routes, } from "react-router-dom";
import './PlayerDetail.css';
import LoginPage from "./LoginPage";
import History from "./History";
import Navbar from "../../component/Navbar";
import DetailListPage from "./DetailListPage";
import AdminPage from "./AdminPage";
import PrivateRoute from "../../component/PrivateRoute";
import {useAuthentication} from "./backendCall/authService";
import NoRoute from "./NoRoute";
import HomePage from "./HomePage";
import LoginOutPage from "./LoginOutPage";
import ContactManager from "./ContactManager";
import ContactManagerDetailLogic from "./ContactManagerDetailLogic";
import PlayerListPage from "./PlayerListPage";

function IndexKaeDaungFootballClub(){
    return (
        <>
            <Navbar/>
            <Outlet/>


            <Routes>
                <Route path="/" element={<HomePage/>}/>

                <Route path="/kaedaung/players/:playerId/" element={
                    <PrivateRoute
                        redirectTo={"/login?redirectTo=/kaedaung/players/"}
                        isAuth={useAuthentication()}>
                        <DetailListPage/>
                    </PrivateRoute>
                }>
                </Route>
                <Route path="/admin" element={
                    <PrivateRoute
                        redirectTo={"/login?redirectTo=/admin"}
                        isAuth={useAuthentication()}>
                        <AdminPage/>
                    </PrivateRoute>
                }/>
                <Route path="/history" element={<History/>}/>
                <Route path="/login" element={<LoginPage/>}/>
                <Route path="/logout" element={<LoginOutPage/>}/>
                <Route path="/contact" element={<ContactManager/>}/>
                <Route path="/contact/:contactId" element={<ContactManagerDetailLogic/>}/>

                <Route path="*" element={<NoRoute/>}/>

                <Route path="/kaedaung/players" element={

                    <PlayerListPage/>

                }>
                </Route>
            </Routes>
        </>
    )
}

export default IndexKaeDaungFootballClub;