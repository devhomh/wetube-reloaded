import express from "express";
import {
  edit,
  logout,
  see,
  startGithubLogin,
  finishGithubLogin,
  changePassword,
} from "../controllers/userControllers";
import { protectorMiddleware, publicOnlyMiddleware } from "../middlewares";

const userRouter = express.Router();

userRouter.get("/logout", protectorMiddleware, logout);
userRouter.route("/edit").all(protectorMiddleware).get(edit).post(edit);
userRouter
  .route("/change-password")
  .all(protectorMiddleware)
  .get(changePassword)
  .post(changePassword);
userRouter.get("/github/start", publicOnlyMiddleware, startGithubLogin);
userRouter.get("/github/finish", publicOnlyMiddleware, finishGithubLogin);
userRouter.get("/:id", see);

export default userRouter;
