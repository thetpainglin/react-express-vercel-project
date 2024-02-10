import {createAsyncThunk, createSlice} from "@reduxjs/toolkit";
import {addNewContact, deleteContactManager, editContactManager, getAllContact} from "./contactManagerAPI";

export const apiGetAllContant = createAsyncThunk(
    'contact/getAllContact',
    async ()=>{
        const response = await getAllContact();
        return response.data;
    }
)
export const apiAddNewContact = createAsyncThunk(
    'contact/addNewContact',
    async (contacts)=>{
        const response = await addNewContact(contacts);
        return response.data;
    }
)

export const apiEditContactManager = createAsyncThunk(
    'contact/editContactManager',
    async (contacts)=>{
        const response = await editContactManager(contacts);
        return response.data;
    }
)

export const apiDeleteContactManager = createAsyncThunk(
    'contact/deleteContactManager',
    async (contactId)=>{
        const response = await deleteContactManager(contactId);
        return response.data;
    }
)
const contactManagerSlice = createSlice({
    name : "contact",
    initialState : {
        contacts : []
    },
    reducers : {

    },
    extraReducers : (builder) => {
        builder.addCase(apiGetAllContant.fulfilled,(state,action)=>{
            state.contacts = action.payload;
        })
            .addCase(apiAddNewContact.fulfilled,(state,action)=>{
                state.contacts = [...state.contacts,action.payload];
            })
            .addCase(apiEditContactManager.fulfilled,(state,action)=>{
                state.contacts = state.contacts.map(contact => contact._id === action.payload._id ? action.payload : contact);
            })
            .addCase(apiDeleteContactManager.fulfilled,(state,action)=>{
                state.contacts = state.contacts.filter(contact => contact._id != action.payload._id );
            })
    }
});

export const allContact = state => state.contact.contacts;

export const contactSelect = (state,contactId) => {
    console.log("contactID => ",contactId);
    console.log("state => ",state);
    return state.contact.contacts.filter(contact => contact._id === contactId)
};

export default contactManagerSlice.reducer;