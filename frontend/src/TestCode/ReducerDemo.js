import React, {useState, useReducer, useEffect} from "react";
const initialState = {
    items : ['one']
}

function reducer(state , action ){
    console.log("action => ",action);
    switch (action.type){
        case 'Add' : return {
            items : [...state.items , action.payload]
        }
    }

}

const ReducerDemo = ()=>{
    let [state , dispatch ] = useReducer(reducer , initialState );
    useEffect(()=>{
        dispatch({type : "Add", payload : {items : "Two"}})
    },[])
    console.log("state => ",state);
    return (
        <>
        Reducer Demo
        </>
    )
}
export default ReducerDemo;