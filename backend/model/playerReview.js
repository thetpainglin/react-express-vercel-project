const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const PlayerSchema = new Schema({
    player : {
        type: Schema.ObjectId,
        ref: 'kaeDaung',
    },
    playerRating : {
        type : Number,
        required : true
    },
    playerScore : {
        type : String,
        required : true,
    }

});

module.exports = mongoose.model('playerReview',PlayerSchema);