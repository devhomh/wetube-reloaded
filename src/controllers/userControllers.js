import User from "../models/User";
import bcrypt from "bcrypt";

export const getJoin = (req, res) =>
  res.render("users/join", { pageTitle: "Join" });

export const postJoin = async (req, res) => {
  const { name, username, email, password, password2, location } = req.body;
  const pageTitle = "join";
  if (password !== password2) {
    return res.status(400).render("users/join", {
      pageTitle,
      errorMessage: "Password confirmation does not match.",
    });
  }
  const exists = await User.exists({ $or: [{ username }, { email }] });
  if (exists) {
    return res.status(400).render("users/join", {
      pageTitle,
      errorMessage: "This username/email is already taken.",
    });
  }
  try {
    await User.create({
      name,
      username,
      email,
      password,
      location,
    });
    res.redirect("/login");
  } catch (error) {
    return res.status(400).render("users/join", {
      pageTitle: "Join",
      errorMessage: error._message,
    });
  }
};

export const getLogin = (req, res) =>
  res.render("users/login", { pageTitle: "Login" });

export const postLogin = async (req, res) => {
  const { username, password } = req.body;
  const pageTitle = "Login";
  const user = await User.findOne({ username, socialOnly: false });
  if (!user) {
    return res.status(400).render("users/login", {
      pageTitle,
      errorMessage: "An account with this username does not exists.",
    });
  }
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    return res.status(400).render("users/login", {
      pageTitle,
      errorMessage: "Wrong password",
    });
  }
  req.session.loggedIn = true;
  req.session.user = user;
  return res.redirect("/");
};

export const startGithubLogin = (req, res) => {
  const baseUrl = "http://github.com/login/oauth/authorize";
  const config = {
    client_id: process.env.GH_CLIENT,
    allow_signup: false,
    scope: "read:user user:email",
  };
  const params = new URLSearchParams(config).toString();
  const finalUrl = `${baseUrl}?${params}`;
  return res.redirect(finalUrl);
};

export const finishGithubLogin = async (req, res) => {
  const baseUrl = "http://github.com/login/oauth/access_token";
  const config = {
    client_id: process.env.GH_CLIENT,
    client_secret: process.env.GH_SECRET,
    code: req.query.code,
  };
  const params = new URLSearchParams(config).toString();
  const finalUrl = `${baseUrl}?${params}`;
  const tokenRequest = await (
    await fetch(finalUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
      },
    })
  ).json();
  if ("access_token" in tokenRequest) {
    const { access_token } = tokenRequest;
    const apiUrl = "http://api.github.com";
    const userData = await (
      await fetch(`${apiUrl}/user`, {
        headers: {
          Authorization: `token ${access_token}`,
        },
      })
    ).json();
    const emailData = await (
      await fetch(`${apiUrl}/user/emails`, {
        headers: {
          Authorization: `token ${access_token}`,
        },
      })
    ).json();
    const emailObj = emailData.find(
      (email) => email.primary === true && email.verified === true
    );
    if (!emailObj) {
      // set notification
      return res.redirect("/login");
    }
    let user = await User.findOne({ email: emailObj.email });
    if (!user) {
      user = await User.create({
        name: userData.name,
        username: userData.login,
        avatarUrl: userData.avatar_url,
        email: emailObj.email,
        password: "",
        socialOnly: true,
        location: userData.location,
      });
    }
    req.session.loggedIn = true;
    req.session.user = user;
    return res.redirect("/");
  } else {
    return res.redirect("/login");
  }
};

export const logout = (req, res) => {
  req.session.destroy();
  return res.redirect("/");
};

export const edit = async (req, res) => {
  const pageTitle = "Edit Profile";
  if (req.method === "GET") {
    return res.render("users/edit-profile", { pageTitle });
  }
  if (req.method === "POST") {
    const {
      session: {
        user: { _id, avatarUrl },
      },
      body: { name, email, username, location },
      file,
    } = req;
    const existEmail = await User.findOne({ email });
    const existUsername = await User.findOne({ username });
    if (
      (existEmail !== null && existEmail._id != _id) ||
      (existUsername !== null && existUsername._id != _id)
    ) {
      return res.status(400).render("users/edit-profile", {
        pageTitle,
        errorMessage: "This email/username already exists.",
      });
    }
    const isCloudtype = process.env.NODE_ENV === "production";
    const updatedUser = await User.findByIdAndUpdate(
      _id,
      {
        avatarUrl: file ? (isCloudtype ? file.location : file.path) : avatarUrl,
        name,
        email,
        username,
        location,
      },
      { new: true }
    );
    req.session.user = updatedUser;
    return res.redirect("/users/edit");
  }
};

export const changePassword = async (req, res) => {
  const pageTitle = "Change Password";
  if (req.method === "GET") {
    if (req.session.user.socialOnly === true) {
      req.flash("error", "Can't change password.");
      return res.redirect("/");
    }
    return res.render("users/change-password", {
      pageTitle,
    });
  }
  if (req.method === "POST") {
    const {
      session: {
        user: { _id, password },
      },
      body: { old, newPassword, newPasswordConfirmation },
    } = req;
    const ok = await bcrypt.compare(old, password);
    if (!ok) {
      return res.status(400).render("users/change-password", {
        pageTitle,
        errorMessage: "The current password is incorrect",
      });
    }
    if (old === newPassword) {
      return res.status(400).render("users/change-password", {
        pageTitle,
        errorMessage: "The old password equals new password",
      });
    }
    if (newPassword !== newPasswordConfirmation) {
      return res.status(400).render("users/change-password", {
        pageTitle,
        errorMessage: "The password does not match the confirmation",
      });
    }
    const user = await User.findById(_id);
    user.password = newPassword;
    await user.save();
    req.session.destroy();
    req.flash("info", "Password updated");
    return res.redirect("/login");
  }
};

export const see = async (req, res) => {
  const {
    params: { id },
  } = req;
  const user = await User.findById(id).populate({
    path: "videos",
    populate: {
      path: "owner",
      model: "User",
    },
  });
  if (!user) {
    return res.status(404).render("404", { pageTitle: "User not found." });
  }
  return res.render("users/profile", {
    pageTitle: `${user.name}의 Profile`,
    user,
  });
};

export const startKakaoLogin = (req, res) => {
  const isCloudtype = process.env.NODE_ENV === "production";
  const redirect_uri = isCloudtype
    ? "https://port-0-wetube-reloaded-koh2xlilqzhxj.sel4.cloudtype.app"
    : "http://localhost:4000/users/kakao/finish";
  const baseUrl = "https://kauth.kakao.com/oauth/authorize";
  const config = {
    client_id: process.env.KAKAO_KEY,
    redirect_uri,
    response_type: "code",
    scope: "profile_nickname,profile_image,account_email",
  };
  const params = new URLSearchParams(config).toString();
  const finalUrl = `${baseUrl}?${params}`;
  return res.redirect(finalUrl);
};

export const finishKakaoLogin = async (req, res) => {
  const isCloudtype = process.env.NODE_ENV === "production";
  const redirect_uri = isCloudtype
    ? "https://port-0-wetube-reloaded-koh2xlilqzhxj.sel4.cloudtype.app"
    : "http://localhost:4000/users/kakao/finish";
  const baseUrl = "https://kauth.kakao.com/oauth/token";
  const config = {
    grant_type: "authorization_code",
    client_id: process.env.KAKAO_KEY,
    redirect_uri,
    code: req.query.code,
  };
  const params = new URLSearchParams(config).toString();
  const finalUrl = `${baseUrl}?${params}`;
  const tokenRequest = await (
    await fetch(finalUrl, {
      method: "POST",
    })
  ).json();
  if ("access_token" in tokenRequest) {
    const { access_token } = tokenRequest;
    const apiUrl = "https://kapi.kakao.com/v2/user/me";
    const userData = await (
      await fetch(apiUrl, {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
      })
    ).json();
    const kakaoAccount = userData.kakao_account;
    const kakaoProfile = kakaoAccount.profile;
    if (
      kakaoAccount.is_email_valid === false ||
      kakaoAccount.is_email_verified === false
    ) {
      return res.redirect("/login");
    }
    let user = await User.findOne({ email: kakaoAccount.email });
    if (!user) {
      user = await User.create({
        email: kakaoAccount.email,
        avatarUrl: kakaoProfile.profile_image_url,
        socialOnly: true,
        username: kakaoProfile.nickname,
        password: "",
        name: kakaoProfile.nickname,
      });
    }
    req.session.loggedIn = true;
    req.session.user = user;
    return res.redirect("/");
  } else {
    return res.redirect("/login");
  }
};
