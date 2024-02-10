let contactManager = require("../model/contantManager");

const getAllContact =async ()=>{
    return contactManager.find();
}

const newContactManager =async (contact)=>{
    const manager = new contactManager(contact);
    return manager.save();
}
const updateManager =async (contactId,contact)=>{
    return contactManager.findByIdAndUpdate(contactId,contact,{new : true});
}
const deleteManager =async (contactId)=>{
    return contactManager.findByIdAndDelete(contactId);
}

module.exports = {
    getAllContact,
    newContactManager,
    updateManager,
    deleteManager,
}