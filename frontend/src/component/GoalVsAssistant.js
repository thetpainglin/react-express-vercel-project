import React , {useReducer} from "react";

function initialState(data){
    console.log("data ",data);
    return {goal : 1};
}

function reducer(state , action){
    console.log("state in reducer => ", state);
    console.log("action in reducer => ",action);
    switch (action.type){
        case 'reset' : return  {goal : action.goal};
        case 'increment' : return {goal : state.goal + 1};
        case 'decrement' : return {goal : state.goal - 1};
        default : throw new Error();
    }
}

const GoalVsAssistant = ({goals})=>{
    const [state,dispatch] = useReducer(reducer , goals,initialState);
    return (
        <div>
    <button onClick={()=>dispatch({type : 'reset',payload : initialState,goal : 0})}>Reset</button>
    <button onClick={()=>dispatch({type:'increment'})}>+</button>
    <span> { state.goal }</span>
    <button onClick={()=>dispatch({type:'decrement'})}>-</button>
        </div>
    );
}

export default GoalVsAssistant;