function CommentCodeInApp(){
    return (
        <>
            {/*<nav
            style={{
                borderBottom: "solid 1px",
                paddingBottom: "1rem",
                textAlign: "center"
            }}
        >
            <Link to="/invoices">Invoices</Link> | {" "}
            <Link to="/expenses">Expenses</Link> | {" "}
            <Link to="/kaedaung/players">KaeDaungPlayer</Link> | {" "}
            <Link to="/users">LoadingUser</Link> | {" "}
            <Link to="/users/2?data=Hello">Custom</Link>
        </nav>
            <Outlet/>
            <button type={"button"}
            className={"btn btn-primary"}
            onClick={btnOnClick}>
            Go to Users
            </button>

            <nav
                style={{
                    borderBottom: "solid 1px",
                    paddingBottom: "1rem",
                    textAlign: "center"
                }}>
                <Link to="/movie-list">movie List</Link>
            </nav>
            <Outlet/>

            <nav style={{
            borderBottom: "solid 1px",
            paddingBottom: "1rem",
            textAlign: "center",
            backgroundColor : "darkslateblue",
            color : "whiteSmoke"
        }} >
            <Link to="/kaedaung/players/" style={{color : "white"}}>KaeDaungPlayer</Link> | {" "}
        </nav>

        ----Navbar nav css use---
        <Navbar/>

        ---real code -----

         <nav style={{
            borderBottom: "solid 1px",
            paddingBottom: "1rem",
            textAlign: "center",
            backgroundColor : "darkslateblue",
            color : "whiteSmoke"
        }} >
            <Link to="/kaedaung/players/" style={
                {color : "white",
                textDecorationStyle : false,


                }
            }>KaeDaungPlayer</Link> | {" "}
        </nav>
        <Outlet />


        <PrivateRoute redirectTo={"/login?redirectTo=/kaedaung/players/:playerId"}
                                  isAuth={useAuthentication()}>
                                  </PrivateRoute>


        Real Project football kaeDaung club
        <Real KaeDaung football club>

            <Navbar/>
            <Outlet/>


            <Routes>
            <Route path="/" element={<HomePage/>}></Route>
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

            </Real KaeDaung football club>
            */}

        </>
    )
};
export default CommentCodeInApp;