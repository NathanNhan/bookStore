import mongoose from 'mongoose';

const userSchema = mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: false,
    },
    isAdmin : {
        type: Boolean,
        required: false
    }
  },
  {
    timestamps: true,
  }
);

export const User = mongoose.model('User', userSchema);