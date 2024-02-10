import {useSelector} from "react-redux";
import {selectAuth} from "./AuthSlice";

export default function useAuth(){
    let authUser = useSelector(selectAuth);
    console.log("use Auth user " , authUser)
    return authUser;
}

export function useAuthentication(){
    let authUser = useAuth();
    return authUser.token;
}

