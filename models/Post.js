const mongoose = require("mongoose");

const postSchema = new mongoose.Schema(
  {
    primaryImage: { type: String, required: true },
    images: [{ type: String }],
    title: { type: String, required: true },
    category: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Category",
      required: true,
    },
    content: { type: String, required: true },
    description: { type: String, required: true },
    tag: {
      type: [{ type: String }],
      validate: {
        validator: function(v) {
          return v.length > 0;
        },
        message: 'At least one tag is required.'
      }
    },   
    postedBy: { type: String, default: "Admin" },
    videos: [{ type: String }],
  },
  { timestamps: true }
);

const Post = mongoose.model("Post", postSchema);

module.exports = Post;
