let express = require("express");
let router = express.Router();
let contactManager = require('../Controller/contactManagerControler');

router.post('/',contactManager.newContactAdd);
router.get('/',contactManager.getAllContacts);
router.put('/:contactId',contactManager.updateContact);
router.delete('/:contactId',contactManager.deleteContact);

module.exports = router;
