import express from 'express';
import { User } from '../models/userModel.js';
import bcrypt from 'bcrypt';
import  jwt  from 'jsonwebtoken';
const userRouter = express.Router();

let refresTokens = [];


const generateAccessToken = (user) => {
   return jwt.sign(
    { id: user._id, isAdmin: user.isAdmin },
    'mySecretKey', {
      expiresIn: "30s"
    }
  );
}

const generateRefreshToken = (user) => {
    return jwt.sign(
        { id: user._id, isAdmin: user.isAdmin },
        'myRefreshkey'
      );
}


userRouter.post('/register', async (req,res, next) => {
    try {
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(req.body.password, salt);
        const newUser = new User({
          ...req.body,
          password: hash,
        });
    
        await newUser.save();
        res.status(200).send("User has been created.");
      } catch (err) {
        next(err);
      }
});



userRouter.post('/login', async (req,res, next) => {
    try {
        const user = await User.findOne({ username: req.body.username });
        if (!user) return next(createError(404, "User not found!"));
    
        const isPasswordCorrect = await bcrypt.compare(
          req.body.password,
          user.password
        );
        if (!isPasswordCorrect)
          return next(createError(400, "Wrong password or username!"));
    
        const token =  generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);
        refresTokens.push(refreshToken);
        console.log(token);
        console.log(refreshToken);
        const { password, isAdmin, ...otherDetails } = user._doc;
        res
          .cookie("access_token", token, {
            httpOnly: true,
          })
          .status(200)
          .json({ details: { ...otherDetails }, isAdmin });
      } catch (err) {
        next(err);
      }
})


userRouter.post("/refresh", (req, res) => {
    //take the refresh token from the user
    const refreshToken = req.body.token;
  
    //send error if there is no token or it's invalid
    if (!refreshToken) return res.status(401).json("You are not authenticated!");
    if (!refresTokens.includes(refreshToken)) {
      return res.status(403).json("Refresh token is not valid!");
    }
    jwt.verify(refreshToken, "myRefreshkey", (err, user) => {
      err && console.log(err);
      refresTokens = refresTokens.filter((token) => token !== refreshToken);
  
      const newAccessToken = generateAccessToken(user);
      const newRefreshToken = generateRefreshToken(user);
  
      refresTokens.push(newRefreshToken);
  
      res.status(200).json({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      });
    });
  
    //if everything is ok, create new access token, refresh token and send to user
  });

  // Xác thực token
  


  export default userRouter;
