const mongoose = require('mongoose');

const commentSchema = new mongoose.Schema({
    caseId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: "Case", 
        required: true },
    username: { 
        type: String, 
        required: true 
    },
    email: { 
        type: String, 
        required: true 
    },
    comment: { 
        type: String, 
        required: true 
    },
    parentCommentId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: "Comment" 
    },
    replies: [{ 
        type: mongoose.Schema.Types.ObjectId, 
        ref: "Comment" 
    }],
}, { 
    timestamps: true 
});
  
const Comment = mongoose.model('Comment', commentSchema);

module.exports = Comment;
