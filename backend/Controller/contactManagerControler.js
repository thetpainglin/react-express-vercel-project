let contactManagerService = require("../Services/contactManagerService");

const getAllContacts =async function(req,res,next){
    try{

        const contactManager = await contactManagerService.getAllContact();
        if(!contactManager) throw Error("No contact");
        await res.status(200).json(contactManager);
    }
    catch (e){
        await res.status(400).json({msg : e})
    }
}
const newContactAdd =async function(req,res,next){
    try{
        let body = req.body;
        console.log("body data => ",body);
        const contactManager = await contactManagerService.newContactManager(body);
        if(!contactManager) throw Error("No contact");
        await res.status(200).json(contactManager);
    }
    catch (e){
        await res.status(400).json({msg : e})
    }
}
const updateContact = async function(req,res,next){
    try{
        let contactId = req.params["contactId"];
        let contact = req.body;
        console.log("contact => ",contact);
        const contactManager = await contactManagerService.updateManager(contactId,contact);
        if(!contactManager) throw Error("No update Contact");
        await res.status(200).json(contactManager);

    }catch (e) {
        await res.status(400).json({msg : e})
    }
}
const deleteContact = async function(req,res,next){
    try{
        let contactId = req.params['contactId'];
        const contactManager = await contactManagerService.deleteManager(contactId);
        if(!contactManager) throw Error("No update Contact");
        await res.status(200).json(contactManager);

    }catch (e) {
        await res.status(400).json({msg : e})
    }
}

module.exports = {
    getAllContacts,
    newContactAdd,
    updateContact,
    deleteContact
}